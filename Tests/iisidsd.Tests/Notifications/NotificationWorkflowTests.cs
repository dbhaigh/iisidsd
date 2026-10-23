using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Notifications;
using iisidsd.Observability;
using iisidsd.Storage;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Notifications;

public sealed class NotificationWorkflowTests
{
    [Fact]
    public async Task Publish_DeduplicatesByClientAndSiteAndReopensAfterCooldown()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-10-22T12:00:00Z"));
        using var harness = await CreateHarness(clock);
        harness.EventStore.Publish(CreateEvent("first", "203.0.113.10", "shop.example"));
        var initial = Assert.Single(harness.Queue.List());
        Assert.Equal("pending", initial.Status);

        harness.Queue.RecordFailure(initial.Id, clock.GetUtcNow(), "IOException");
        clock.Advance(TimeSpan.FromMinutes(1));
        harness.EventStore.Publish(CreateEvent("repeat", "203.0.113.10", "shop.example"));
        var duringCooldown = Assert.Single(harness.Queue.List());
        Assert.Equal("retry", duringCooldown.Status);
        Assert.Equal(1, duringCooldown.AttemptCount);

        clock.Advance(TimeSpan.FromMinutes(14));
        harness.EventStore.Publish(CreateEvent("after-cooldown", "203.0.113.10", "shop.example"));
        var reopened = Assert.Single(harness.Queue.List());
        Assert.Equal(initial.Id, reopened.Id);
        Assert.Equal("pending", reopened.Status);
        Assert.Equal(0, reopened.AttemptCount);
        Assert.Equal(clock.GetUtcNow(), reopened.FirstSeenUtc);
    }

    [Fact]
    public async Task Delivery_RetriesRecoversAndAcknowledgesWithoutChangingDetection()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-10-22T13:00:00Z"));
        using var harness = await CreateHarness(clock, MakeOptions(maximumAttempts: 3));
        var securityEvent = CreateEvent("deliver", "203.0.113.11", "api.example");
        harness.EventStore.Publish(securityEvent);
        var queued = Assert.Single(harness.Queue.List());
        var provider = new FakeProvider { FailuresRemaining = 1 };
        var loggerProvider = new CapturingLoggerProvider();
        using var loggerFactory = LoggerFactory.Create(builder => builder.AddProvider(loggerProvider));
        var service = new NotificationDeliveryService(
            harness.Queue,
            provider,
            Options.Create(harness.Options),
            clock,
            loggerFactory.CreateLogger<NotificationDeliveryService>());

        Assert.Equal(0, await service.DispatchDueAsync(CancellationToken.None));
        var retry = Assert.Single(harness.Queue.List());
        Assert.Equal("retry", retry.Status);
        Assert.Equal(1, retry.AttemptCount);
        Assert.True(harness.EventStore.GetRecent(10).Single().IsSuspicious);
        Assert.DoesNotContain(loggerProvider.Messages, message => message.Contains("password=never-log", StringComparison.Ordinal));
        Assert.Contains(loggerProvider.Messages, message => message.Contains("InvalidOperationException", StringComparison.Ordinal));

        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(1, await service.DispatchDueAsync(CancellationToken.None));
        var delivered = Assert.Single(harness.Queue.List());
        Assert.Equal("delivered", delivered.Status);
        Assert.Equal(2, delivered.AttemptCount);
        Assert.Equal(2, provider.Messages.Count);

        var acknowledged = harness.Queue.Acknowledge(delivered.Id, clock.GetUtcNow(), "test-operator");
        Assert.Equal("acknowledged", acknowledged?.Status);
        Assert.Equal("test-operator", acknowledged?.AcknowledgedBy);
        Assert.Equal(1, harness.Queue.GetStatus().Acknowledged);
    }

    [Fact]
    public async Task Delivery_StopsAfterMaximumAttempts()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-10-22T13:30:00Z"));
        using var harness = await CreateHarness(clock, MakeOptions(maximumAttempts: 2));
        harness.EventStore.Publish(CreateEvent("exhausted", "203.0.113.12", "login.example"));
        var provider = new FakeProvider { FailuresRemaining = 5 };
        var service = new NotificationDeliveryService(
            harness.Queue,
            provider,
            Options.Create(harness.Options),
            clock,
            NullLogger<NotificationDeliveryService>.Instance);

        await service.DispatchDueAsync(CancellationToken.None);
        clock.Advance(TimeSpan.FromSeconds(1));
        await service.DispatchDueAsync(CancellationToken.None);
        clock.Advance(TimeSpan.FromDays(1));

        Assert.Equal("failed", Assert.Single(harness.Queue.List()).Status);
        Assert.Empty(harness.Queue.GetDue(clock.GetUtcNow()));
        Assert.Equal(2, provider.Messages.Count);
    }

    [Fact]
    public async Task QueueCapacity_DropsExcessAlertsWithoutDroppingDetectedEvents()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-10-22T14:00:00Z"));
        using var harness = await CreateHarness(clock, MakeOptions(queueCapacity: 2));
        var events = Enumerable.Range(0, 5)
            .Select(index => CreateEvent(
                $"flood-{index}",
                $"203.0.113.{index + 20}",
                $"site-{index}.example"))
            .ToArray();
        harness.EventStore.PublishBatch(events);

        Assert.Equal(5, harness.EventStore.GetRecent(10).Count);
        Assert.Equal(2, harness.Queue.GetStatus().Pending);
        Assert.Equal(3, harness.Queue.GetStatus().Dropped);
    }

    [Fact]
    public async Task StoredIncidentLimit_BoundsDeliveredAndPendingHistory()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-10-22T14:30:00Z"));
        var options = MakeOptions(queueCapacity: 1_000);
        options.StoredIncidentLimit = 100;
        using var harness = await CreateHarness(clock, options);
        var events = Enumerable.Range(0, 101)
            .Select(index => CreateEvent(
                $"stored-{index}",
                "203.0.113.100",
                $"stored-{index}.example"))
            .ToArray();

        harness.EventStore.PublishBatch(events);

        Assert.Equal(101, harness.EventStore.GetRecent(200).Count);
        Assert.Equal(100, harness.Queue.List(200).Count);
        Assert.Equal(1, harness.Queue.GetStatus().Dropped);
    }

    [Fact]
    public async Task PruneExpired_RemovesOnlyOldTerminalIncidents()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-10-22T14:45:00Z"));
        using var harness = await CreateHarness(clock);
        harness.EventStore.Publish(CreateEvent("terminal", "203.0.113.31", "done.example"));
        var delivered = Assert.Single(harness.Queue.List());
        harness.Queue.RecordDelivered(delivered.Id, clock.GetUtcNow());
        harness.EventStore.Publish(CreateEvent("active", "203.0.113.32", "pending.example"));
        clock.Advance(TimeSpan.FromDays(31));

        Assert.Equal(1, harness.Queue.PruneExpired(clock.GetUtcNow().AddDays(-30)));
        Assert.Equal("pending", Assert.Single(harness.Queue.List()).Status);
        Assert.Equal(1, harness.Queue.GetStatus().Pending);
    }

    [Fact]
    public async Task EnqueueFailure_DoesNotRollbackEventAndDoesNotLogExceptionText()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-10-22T15:00:00Z"));
        using var harness = await CreateHarness(clock, queue: new ThrowingQueue());
        var loggerProvider = new CapturingLoggerProvider();
        using var captureFactory = LoggerFactory.Create(builder => builder.AddProvider(loggerProvider));
        var store = CreateEventStore(harness, new ThrowingQueue(), captureFactory.CreateLogger<SqliteEventStore>());

        store.Publish(CreateEvent("queue-fails", "203.0.113.30", "secure.example"));

        Assert.Single(store.GetRecent(10));
        Assert.DoesNotContain(loggerProvider.Messages, message => message.Contains("password=never-log", StringComparison.Ordinal));
        Assert.Contains(loggerProvider.Messages, message => message.Contains("InvalidOperationException", StringComparison.Ordinal));
    }

    [Fact]
    public async Task MessageTemplate_RedactsSensitiveEvidenceAndIncludesIncidentContext()
    {
        var evidence = new DetectionEvidence(
            DetectionSignalCode.Custom,
            DetectionEvidenceFamily.PathContent,
            "credential-bearing marker",
            10,
            10,
            true,
            DetectorId: "test-detector",
            SignalKey: "test.secret",
            Explanation: "password=secret-value authorization: Bearer bearer-value \"api_key\":\"json-secret\"");
        var incident = new NotificationIncident(
            "00000000000000000000000000000002",
            "203.0.113.40",
            "portal.example",
            "Critical suspicious activity",
            12,
            "Critical",
            DateTimeOffset.Parse("2026-10-22T15:30:00Z"),
            DateTimeOffset.Parse("2026-10-22T15:25:00Z"),
            DateTimeOffset.Parse("2026-10-22T15:30:00Z"),
            [evidence],
            "pending",
            0,
            null,
            null,
            null,
            null,
            null);

        var formatted = NotificationMessageFormatter.Format(
            NotificationMessageFormatter.Create(incident, "http://127.0.0.1:5080/"));

        Assert.Contains("portal.example", formatted);
        Assert.Contains("First seen (UTC):", formatted);
        Assert.Contains("2026-10-22T15:25:00", formatted);
        Assert.Contains("http://127.0.0.1:5080/", formatted);
        Assert.Contains("password=[redacted]", formatted);
        Assert.Contains("authorization: [redacted]", formatted);
        Assert.DoesNotContain("secret-value", formatted);
        Assert.DoesNotContain("bearer-value", formatted);
        Assert.DoesNotContain("json-secret", formatted);

        var writer = new FakeWindowsEventLogWriter();
        var provider = new WindowsEventLogNotificationProvider(writer);
        await provider.DeliverAsync(
            NotificationMessageFormatter.Create(incident, "http://127.0.0.1:5080/"),
            CancellationToken.None);
        Assert.Equal(NotificationSeverity.Critical, writer.Severity);
        Assert.Contains("Target site: portal.example", writer.Message);
        Assert.DoesNotContain("secret-value", writer.Message);
    }

    [Fact]
    public void NotificationOptions_RequireExplicitProviderAndLoopbackDashboard()
    {
        var options = MakeOptions();
        Assert.True(options.IsValid());
        Assert.True(options.MeetsAlertThreshold(8, "High"));
        Assert.False(options.MeetsAlertThreshold(7, "Critical"));
        Assert.False(options.MeetsAlertThreshold(20, "Medium"));
        Assert.False(new NotificationOptions { Enabled = true }.IsValid());
        Assert.False(WithDashboard("https://example.invalid/").IsValid());
        Assert.False(WithDashboard("http://user:pass@127.0.0.1/").IsValid());

        static NotificationOptions WithDashboard(string value)
        {
            var options = MakeOptions();
            options.DashboardUrl = value;
            return options;
        }
    }

    private static async Task<TestHarness> CreateHarness(
        ManualTimeProvider clock,
        NotificationOptions? options = null,
        INotificationQueue? queue = null)
    {
        var root = Path.Combine(Path.GetTempPath(), "iisidsd-notification-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var environment = new TestHostEnvironment(root);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var notificationOptions = options ?? MakeOptions();
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(
            storageOptions,
            environment,
            findingStore,
            NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);
        var notificationQueue = queue ?? new SqliteNotificationQueue(
            storageOptions,
            Options.Create(notificationOptions),
            environment,
            clock);
        var observability = new IisObservability();
        var harness = new TestHarness(root, environment, storageOptions, findingStore, notificationQueue, notificationOptions, observability, clock);
        harness.EventStore = CreateEventStore(harness, notificationQueue);
        return harness;
    }

    private static SqliteEventStore CreateEventStore(
        TestHarness harness,
        INotificationQueue queue,
        ILogger<SqliteEventStore>? logger = null)
        => new(
            Options.Create(new IisEtwOptions { SubscriptionBufferSize = 8 }),
            harness.StorageOptions,
            harness.Environment,
            harness.FindingStore,
            harness.Observability,
            notificationQueue: queue,
            logger: logger);

    private static SecurityEvent CreateEvent(string id, string clientIp, string site)
        => new(
            DateTimeOffset.Parse("2026-10-22T15:00:00Z"),
            "server01",
            site,
            "GET",
            "/admin?token=must-not-be-delivered",
            clientIp,
            404,
            "test-agent",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            DetectionReason: "suspicious request",
            RiskScore: 10,
            RiskSeverity: "High",
            RiskIndicators: ["test-indicator"],
            DetectionEvidence:
            [
                new DetectionEvidence(
                    DetectionSignalCode.Custom,
                    DetectionEvidenceFamily.PathContent,
                    "test-indicator",
                    10,
                    10,
                    true,
                    DetectorId: "test-detector",
                    SignalKey: "test.signal",
                    Explanation: "Test evidence")
            ])
        {
            Id = id
        };

    private static NotificationOptions MakeOptions(
        int queueCapacity = 100,
        int maximumAttempts = 3,
        int cooldownMinutes = 15)
        => new()
        {
            Enabled = true,
            Provider = "WindowsEventLog",
            MinimumSeverity = "High",
            MinimumRiskScore = 8,
            QueueCapacity = queueCapacity,
            MaximumAttempts = maximumAttempts,
            CooldownMinutes = cooldownMinutes,
            RetryDelaySeconds = 1,
            MaximumRetryDelaySeconds = 4,
            DeliveryTimeoutSeconds = 5,
            RetentionDays = 30,
            DashboardUrl = "http://127.0.0.1:5080/"
        };

    private sealed class TestHarness(
        string root,
        TestHostEnvironment environment,
        IOptions<StorageOptions> storageOptions,
        IFindingStore findingStore,
        INotificationQueue queue,
        NotificationOptions options,
        IisObservability observability,
        ManualTimeProvider clock) : IDisposable
    {
        public TestHostEnvironment Environment { get; } = environment;
        public IOptions<StorageOptions> StorageOptions { get; } = storageOptions;
        public IFindingStore FindingStore { get; } = findingStore;
        public INotificationQueue Queue { get; } = queue;
        public NotificationOptions Options { get; } = options;
        public IisObservability Observability { get; } = observability;
        public ManualTimeProvider Clock { get; } = clock;
        public SqliteEventStore EventStore { get; set; } = null!;

        public void Dispose()
        {
            Observability.Dispose();
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private sealed class TestHostEnvironment(string contentRootPath) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Testing";
        public string ApplicationName { get; set; } = "iisidsd.Tests";
        public string ContentRootPath { get; set; } = contentRootPath;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan amount) => _now = _now.Add(amount);
    }

    private sealed class FakeProvider : INotificationProvider
    {
        public string Name => "WindowsEventLog";
        public int FailuresRemaining { get; set; }
        public List<NotificationMessage> Messages { get; } = [];

        public Task DeliverAsync(NotificationMessage message, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Messages.Add(message);
            if (FailuresRemaining-- > 0) throw new InvalidOperationException("password=never-log");
            return Task.CompletedTask;
        }
    }

    private sealed class FakeWindowsEventLogWriter : IWindowsEventLogWriter
    {
        public string Message { get; private set; } = string.Empty;
        public NotificationSeverity Severity { get; private set; }

        public void Write(string message, NotificationSeverity severity)
        {
            Message = message;
            Severity = severity;
        }
    }

    private sealed class ThrowingQueue : INotificationQueue
    {
        public NotificationEnqueueResult Enqueue(SecurityEvent webEvent, SqliteConnection connection, SqliteTransaction transaction)
            => throw new InvalidOperationException("password=never-log");

        public IReadOnlyList<NotificationIncident> List(int limit = 250) => [];
        public IReadOnlyList<NotificationIncident> GetDue(DateTimeOffset now, int limit = 25) => [];
        public NotificationQueueStatus GetStatus() => new(0, 0, 0, 0, 0, 0);
        public int PruneExpired(DateTimeOffset olderThanUtc) => 0;
        public void RecordDelivered(string id, DateTimeOffset attemptedAtUtc) { }
        public void RecordFailure(string id, DateTimeOffset attemptedAtUtc, string failureType) { }
        public NotificationIncident? Acknowledge(string id, DateTimeOffset acknowledgedAtUtc, string acknowledgedBy) => null;
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public List<string> Messages { get; } = [];
        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);
        public void Dispose() { }
    }

    private sealed class CapturingLogger(List<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => messages.Add(formatter(state, exception));
    }
}