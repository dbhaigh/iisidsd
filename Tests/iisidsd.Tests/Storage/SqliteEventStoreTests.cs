using iisidsd.Configuration;
using iisidsd.Detection;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Services;
using iisidsd.Storage;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Storage;

public sealed class SqliteEventStoreTests : IDisposable
{
    private readonly string _rootPath = Path.Combine(Path.GetTempPath(), "iisidsd-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Publish_StoresAndPrunesEventsByRetentionLimit()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions
        {
            DatabasePath = "data/test.sqlite3",
            EventRetentionLimit = 1
        });
        var etwOptions = Options.Create(new IisEtwOptions
        {
            SubscriptionBufferSize = 8
        });

        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);

        var store = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());
        store.Publish(new SecurityEvent(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            "server01",
            "example.test",
            "GET",
            "/first",
            "203.0.113.10",
            200,
            "agent-a",
            new Dictionary<string, string>())
        {
            Id = "first"
        });
        store.Publish(new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/second",
            "203.0.113.10",
            200,
            "agent-a",
            new Dictionary<string, string>(),
            RiskScore: 10,
            RiskSeverity: "Low",
            RiskIndicators: ["test-indicator"])
        {
            Id = "second"
        });

        var events = store.GetRecent(10);
        var webEvent = Assert.Single(events);
        Assert.Equal("second", webEvent.Id);
        Assert.Equal("/second", webEvent.Path);
        Assert.Contains("test-indicator", webEvent.RiskIndicators ?? []);

        var finding = Assert.IsType<IpFinding>(findingStore.Get("203.0.113.10"));
        Assert.Equal(2, finding.RequestCount);
        Assert.Equal(1, finding.SuspiciousRequestCount);
        Assert.Equal(10, finding.HighestRiskScore);
        Assert.Contains("example.test", finding.Domains);
        Assert.Contains("test-indicator", finding.RiskIndicators);

        new BanCountService(storageOptions, environment).IncrementBanCounts("203.0.113.10", ["example.test"]);
        Assert.Equal(1, findingStore.Get("203.0.113.10")?.BanCount);

        Assert.Equal(1, findingStore.Prune(DateTimeOffset.UtcNow.AddSeconds(1)));
        Assert.Null(findingStore.Get("203.0.113.10"));
    }

    [Fact]
    public async Task Publish_PrunesEventsOutsideConfiguredTimeRetention()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions
        {
            DatabasePath = "data/test.sqlite3",
            EventRetentionLimit = 100,
            EventRetentionDays = 1
        });
        var etwOptions = Options.Create(new IisEtwOptions { SubscriptionBufferSize = 8 });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);
        var store = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());
        var now = DateTimeOffset.UtcNow;

        store.Publish(new SecurityEvent(
            now.AddDays(-2),
            "server01",
            "example.test",
            "GET",
            "/expired",
            "203.0.113.11",
            200,
            "agent",
            new Dictionary<string, string>())
        {
            Id = "expired"
        });
        store.Publish(new SecurityEvent(
            now,
            "server01",
            "example.test",
            "GET",
            "/current",
            "203.0.113.11",
            200,
            "agent",
            new Dictionary<string, string>())
        {
            Id = "current"
        });

        Assert.Equal("current", Assert.Single(store.GetRecent(10)).Id);
    }

    [Fact]
    public async Task PruneExpiredEvents_RemovesOnlyEventsBeforeCutoff()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var etwOptions = Options.Create(new IisEtwOptions { SubscriptionBufferSize = 8 });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);
        var store = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());
        var cutoff = DateTimeOffset.UtcNow.AddDays(-1);

        store.Publish(CreateEvent("expired", cutoff.AddTicks(-1)));
        store.Publish(CreateEvent("boundary", cutoff));
        store.Publish(CreateEvent("recent", cutoff.AddTicks(1)));

        Assert.Equal(1, store.PruneExpiredEvents(cutoff));
        Assert.Equal(new[] { "recent", "boundary" }, store.GetRecent(10).Select(webEvent => webEvent.Id));
    }

    [Fact]
    public async Task Initializer_BackfillsFindingsFromExistingEventsOnlyOnce()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);

        var databasePath = Path.Combine(_rootPath, "data", "test.sqlite3");
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO events (
                    event_id, timestamp_utc, server, domain, method, path, client_ip, status_code,
                    user_agent, properties_json, is_suspicious, detection_reason, risk_score,
                    risk_severity, risk_indicators_json)
                VALUES (
                    'legacy-event', $timestamp, 'server01', 'legacy.test', 'GET', '/legacy',
                    '203.0.113.25', 404, 'legacy-agent', '{}', 1, 'legacy probing',
                    9, 'Critical', '["legacy-indicator"]');
                """;
            command.Parameters.AddWithValue("$timestamp", DateTimeOffset.UtcNow.AddDays(-1).UtcDateTime.ToString("O"));
            command.ExecuteNonQuery();
        }

        await initializer.StartAsync(CancellationToken.None);
        var finding = Assert.IsType<IpFinding>(findingStore.Get("203.0.113.25"));
        Assert.Equal(1, finding.RequestCount);
        Assert.Equal(1, finding.SuspiciousRequestCount);
        Assert.Equal("Critical", finding.HighestRiskSeverity);
        Assert.Contains("legacy.test", finding.Domains);
        Assert.Contains("legacy probing", finding.DetectionReasons);
        Assert.Contains("legacy-indicator", finding.RiskIndicators);

        await initializer.StartAsync(CancellationToken.None);
        Assert.Equal(1, findingStore.Get("203.0.113.25")?.RequestCount);
    }

    [Fact]
    public async Task Publish_RollsBackEventWhenFindingUpdateFails()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var etwOptions = Options.Create(new IisEtwOptions { SubscriptionBufferSize = 8 });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);

        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(_rootPath, "data", "test.sqlite3")
        }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TRIGGER fail_finding_insert
                BEFORE INSERT ON ip_findings
                BEGIN
                    SELECT RAISE(ABORT, 'test finding failure');
                END;
                """;
            command.ExecuteNonQuery();
        }

        var eventStore = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());
        var webEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/",
            "203.0.113.26",
            200,
            "agent",
            new Dictionary<string, string>());

        Assert.Throws<SqliteException>(() => eventStore.Publish(webEvent));
        Assert.Empty(eventStore.GetRecent(10));
    }

    [Fact]
    public async Task Prune_RemovesExpiredDomainFindingsForActiveIps()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);
        var eventStore = new SqliteEventStore(
            Options.Create(new IisEtwOptions { SubscriptionBufferSize = 8 }),
            storageOptions,
            environment,
            findingStore,
            new IisObservability());
        var recentTimestamp = DateTimeOffset.UtcNow;

        eventStore.Publish(new SecurityEvent(
            recentTimestamp.AddDays(-5),
            "server01",
            "old.example",
            "GET",
            "/old",
            "203.0.113.27",
            404,
            "agent",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            DetectionReason: "old signal",
            RiskScore: 4,
            RiskSeverity: "High",
            RiskIndicators: ["old-indicator"]));
        eventStore.Publish(new SecurityEvent(
            recentTimestamp,
            "server01",
            "new.example",
            "GET",
            "/new",
            "203.0.113.27",
            200,
            "agent",
            new Dictionary<string, string>()));

        findingStore.Prune(recentTimestamp.AddDays(-1));
        var activeFinding = Assert.IsType<IpFinding>(findingStore.Get("203.0.113.27"));
        Assert.DoesNotContain("old.example", activeFinding.Domains);
        Assert.Contains("new.example", activeFinding.Domains);
        Assert.Null(findingStore.Get("203.0.113.27", "old.example"));
        Assert.NotNull(findingStore.Get("203.0.113.27", "new.example"));

        findingStore.Prune(recentTimestamp.AddSeconds(1));
        Assert.Null(findingStore.Get("203.0.113.27"));
        Assert.Null(findingStore.Get("203.0.113.27", "old.example"));
    }

    [Fact]
    public async Task PublishAndSubscribe_ConcurrentWritersPersistAndNotifyEveryEvent()
    {
        const int writerCount = 8;
        const int eventsPerWriter = 40;
        const int totalEvents = writerCount * eventsPerWriter;
        const string clientIp = "203.0.113.28";
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions
        {
            DatabasePath = "data/test.sqlite3",
            EventRetentionLimit = totalEvents + 1
        });
        var etwOptions = Options.Create(new IisEtwOptions
        {
            SubscriptionBufferSize = totalEvents + 1
        });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);

        var store = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());
        using var subscriptionLifetime = new CancellationTokenSource();
        var reader = store.Subscribe(subscriptionLifetime.Token);
        var writers = Enumerable.Range(0, writerCount)
            .Select(writer => Task.Run(() =>
            {
                for (var index = 0; index < eventsPerWriter; index++)
                {
                    store.Publish(new SecurityEvent(
                        DateTimeOffset.UtcNow,
                        "server01",
                        "example.test",
                        "GET",
                        $"/writer-{writer}/event-{index}",
                        clientIp,
                        200,
                        "parallel-test",
                        new Dictionary<string, string>())
                    {
                        Id = $"{writer:D2}-{index:D3}"
                    });

                    if (index % 5 == 0)
                    {
                        using var transientLifetime = new CancellationTokenSource();
                        _ = store.Subscribe(transientLifetime.Token);
                        transientLifetime.Cancel();
                    }
                }
            }))
            .ToArray();

        await Task.WhenAll(writers);

        var delivered = new List<SecurityEvent>();
        while (reader.TryRead(out var webEvent))
        {
            delivered.Add(webEvent);
        }

        subscriptionLifetime.Cancel();
        var persisted = store.GetRecent(totalEvents + 1);
        var finding = Assert.IsType<IpFinding>(findingStore.Get(clientIp));
        Assert.Equal(totalEvents, persisted.Count);
        Assert.Equal(totalEvents, persisted.Select(static webEvent => webEvent.Id).Distinct().Count());
        Assert.Equal(totalEvents, delivered.Count);
        Assert.Equal(totalEvents, delivered.Select(static webEvent => webEvent.Id).Distinct().Count());
        Assert.Equal(totalEvents, finding.RequestCount);
    }

    [Fact]
    public async Task PublishAndFindingPrune_ConcurrentWritersDoNotDeadlock()
    {
        const int eventCount = 120;
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var etwOptions = Options.Create(new IisEtwOptions { SubscriptionBufferSize = 8 });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);
        var store = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());

        var publishTask = Task.Run(() => Parallel.For(0, eventCount, index =>
        {
            store.Publish(new SecurityEvent(
                DateTimeOffset.UtcNow,
                "server01",
                "example.test",
                "GET",
                $"/request-{index}",
                "203.0.113.90",
                200,
                "parallel-test",
                new Dictionary<string, string>()));
        }));
        var pruneTask = Task.Run(() => Parallel.For(0, eventCount, _ =>
            findingStore.Prune(DateTimeOffset.UtcNow.AddDays(-30))));

        await Task.WhenAll(publishTask, pruneTask).WaitAsync(TimeSpan.FromSeconds(15));

        Assert.Equal(eventCount, store.GetRecent(eventCount + 1).Count);
        Assert.Equal(eventCount, findingStore.Get("203.0.113.90")?.RequestCount);
    }

    [Fact]
    public async Task DetectorHistory_UsesSqliteEventsAlongsideIncrementalFindings()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var etwOptions = Options.Create(new IisEtwOptions { SubscriptionBufferSize = 8 });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);
        var eventStore = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());
        var timestamp = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);

        eventStore.Publish(new SecurityEvent(
            timestamp.AddSeconds(-3),
            "server01",
            "example.test",
            "GET",
            "/app.css",
            "203.0.113.99",
            200,
            "history-test",
            new Dictionary<string, string>()));
        eventStore.Publish(new SecurityEvent(
            timestamp.AddSeconds(-2),
            "server01",
            "example.test",
            "GET",
            "/missing-one",
            "203.0.113.98",
            404,
            "history-test",
            new Dictionary<string, string>()));
        eventStore.Publish(new SecurityEvent(
            timestamp.AddSeconds(-1),
            "server01",
            "example.test",
            "GET",
            "/missing-two",
            "203.0.113.98",
            404,
            "history-test",
            new Dictionary<string, string>()));

        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            NotFoundBurstThreshold = 3,
            RateThreshold = 1000,
            PathScanUniquePathThreshold = 1000
        }), eventStore);
        var analyzedEvent = detector.Analyze(new SecurityEvent(
            timestamp,
            "server01",
            "example.test",
            "GET",
            "/app.css",
            "203.0.113.98",
            404,
            "history-test",
            new Dictionary<string, string>()));

        Assert.NotNull(analyzedEvent);
        Assert.Contains("multiple 404 responses from the same client IP", analyzedEvent.RiskIndicators ?? []);
        Assert.DoesNotContain("request targets file type not seen in site history", analyzedEvent.RiskIndicators ?? []);
        eventStore.Publish(analyzedEvent);

        var finding = Assert.IsType<IpFinding>(findingStore.Get("203.0.113.98"));
        Assert.Equal(3, finding.RequestCount);
        Assert.Equal(1, finding.SuspiciousRequestCount);
        Assert.Contains("multiple 404 responses from the same client IP", finding.RiskIndicators);
    }

    public void Dispose()
    {
        if (!Directory.Exists(_rootPath))
        {
            return;
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();

        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Directory.Delete(_rootPath, recursive: true);
                return;
            }
            catch (IOException)
            {
                if (attempt == 4)
                {
                    return;
                }

                Thread.Sleep(100);
            }
            catch (UnauthorizedAccessException)
            {
                if (attempt == 4)
                {
                    return;
                }

                Thread.Sleep(100);
            }
        }
    }

    private static SecurityEvent CreateEvent(string id, DateTimeOffset timestamp)
        => new(
            timestamp,
            "server01",
            "example.test",
            "GET",
            "/test",
            "203.0.113.12",
            200,
            "agent",
            new Dictionary<string, string>())
        {
            Id = id
        };

    private sealed class TestHostEnvironment(string contentRootPath) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "iisidsd.Tests";
        public string ContentRootPath { get; set; } = contentRootPath;
        public IFileProvider ContentRootFileProvider { get; set; } = new PhysicalFileProvider(contentRootPath);
    }
}
