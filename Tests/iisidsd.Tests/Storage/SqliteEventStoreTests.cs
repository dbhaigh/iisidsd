using System.Diagnostics;
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

        Assert.Equal(1, store.PruneExpiredEvents(DateTimeOffset.UtcNow.AddDays(1)));
        var emptyReplay = store.GetPageAfter(1, 10);
        Assert.Empty(emptyReplay.Items);
        Assert.True(emptyReplay.GapDetected);
        Assert.Equal(2, emptyReplay.LatestCursor);
        Assert.Null(emptyReplay.OldestAvailableCursor);
        using var subscriptionLifetime = new CancellationTokenSource();
        Assert.Equal(2, store.SubscribeWithCursor(subscriptionLifetime.Token).InitialCursor);
    }

    [Fact]
    public async Task AnalystIncidentStore_SaveRetainsMostRecentlyUpdatedRecords()
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
            using var seedCommand = connection.CreateCommand();
            seedCommand.CommandText = """
                WITH RECURSIVE sources(index_value) AS (
                    SELECT 0
                    UNION ALL
                    SELECT index_value + 1 FROM sources WHERE index_value < 4999
                )
                INSERT INTO analyst_incidents (client_ip, status, note, updated_utc, updated_by)
                SELECT printf('source-%04d', index_value), 'open', '', '2000-01-01T00:00:00.0000000+00:00', 'seed'
                FROM sources;
                """;
            seedCommand.ExecuteNonQuery();
        }

        var store = new SqliteAnalystIncidentStore(storageOptions, environment);
        store.Save("source-new", "acknowledged", "recent", "administrator");

        using var verifyConnection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString());
        verifyConnection.Open();
        using var countCommand = verifyConnection.CreateCommand();
        countCommand.CommandText = "SELECT COUNT(*) FROM analyst_incidents;";
        Assert.Equal(5000L, (long)countCommand.ExecuteScalar()!);
        Assert.Null(store.Get("source-4999"));
        Assert.NotNull(store.Get("source-0000"));
        Assert.Equal("source-new", store.List().First().ClientIp);
    }

    [Fact]
    public async Task PublishBatch_IsIdempotentAndIngestionDiagnosticsSurviveStoreRestart()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions
        {
            DatabasePath = "data/test.sqlite3",
            EventRetentionLimit = 10
        });
        var etwOptions = Options.Create(new IisEtwOptions { SubscriptionBufferSize = 10 });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);

        var store = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());
        using var subscriptionLifetime = new CancellationTokenSource();
        var reader = store.Subscribe(subscriptionLifetime.Token);
        var eventToPublish = CreateEvent("idempotent-event", DateTimeOffset.UtcNow);
        var firstPublish = store.PublishBatch([eventToPublish, eventToPublish]);
        Assert.Single(firstPublish);
        Assert.Single(store.GetRecent(10));
        Assert.True(reader.TryRead(out _));
        Assert.False(reader.TryRead(out _));

        var expectedDiagnostics = new IngestionDiagnosticsSnapshot(20, 18, 1, 1, 17, 2, 3, 4);
        var sidecarPath = Path.Combine(_rootPath, "data", "test.sqlite3.etw-diagnostics.json");
        Directory.CreateDirectory(sidecarPath);
        store.SaveIngestionDiagnostics(expectedDiagnostics);
        Assert.Equal(expectedDiagnostics, store.GetIngestionDiagnostics());
        Directory.Delete(sidecarPath);
        store.SaveIngestionDiagnosticsSidecar(expectedDiagnostics);
        var restartedStore = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());

        Assert.Equal(expectedDiagnostics, restartedStore.GetIngestionDiagnostics());
        Assert.Empty(restartedStore.PublishBatch([eventToPublish]));
        Assert.Single(restartedStore.GetRecent(10));
        Assert.Equal(1, findingStore.Get("203.0.113.12")?.RequestCount);

        SqliteConnection.ClearAllPools();
        var databasePath = Path.Combine(_rootPath, "data", "test.sqlite3");
        File.Move(databasePath, databasePath + ".unavailable");
        var unavailableStore = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());
        Assert.Equal(expectedDiagnostics, unavailableStore.GetIngestionDiagnostics());
    }

    [Fact]
    public async Task GetRecent_AppliesParameterizedFiltersIndependently()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var etwOptions = Options.Create(new IisEtwOptions { SubscriptionBufferSize = 8 });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);
        var store = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());

        store.PublishBatch(
        [
            CreateEvent("other-domain", DateTimeOffset.UtcNow) with { ClientIp = "203.0.113.31", Domain = "other.example" },
            CreateEvent("same-domain", DateTimeOffset.UtcNow.AddTicks(1)) with { ClientIp = "203.0.113.32", Domain = "example.test" },
            CreateEvent("matching", DateTimeOffset.UtcNow.AddTicks(2)) with
            {
                ClientIp = "203.0.113.31",
                Domain = "example.test",
                IsSuspicious = true
            }
        ]);

        Assert.Equal("matching", Assert.Single(store.GetRecent(10, "203.0.113.31", "example.test", suspiciousOnly: true)).Id);
        Assert.Equal(new[] { "matching", "same-domain" }, store.GetRecent(10, domain: "example.test").Select(static item => item.Id));
        Assert.Equal("matching", Assert.Single(store.GetRecent(10, suspiciousOnly: true)).Id);
    }

    [Fact]
    public async Task PublishBatch_RollsUpFindingsOncePerIpAndDomain()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var etwOptions = Options.Create(new IisEtwOptions { SubscriptionBufferSize = 8 });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);
        var store = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());
        var timestamp = DateTimeOffset.UtcNow;

        store.PublishBatch(
        [
            CreateEvent("rollup-a1", timestamp) with { ClientIp = "203.0.113.41", Domain = "one.example" },
            CreateEvent("rollup-a2", timestamp.AddSeconds(1)) with
            {
                ClientIp = "203.0.113.41",
                Domain = "one.example",
                IsSuspicious = true,
                DetectionReason = "probe",
                RiskScore = 4,
                RiskSeverity = "Medium",
                RiskIndicators = ["path-scan"]
            },
            CreateEvent("rollup-b1", timestamp.AddSeconds(2)) with
            {
                ClientIp = "203.0.113.41",
                Domain = "two.example",
                IsSuspicious = true,
                DetectionReason = "scanner",
                RiskScore = 9,
                RiskSeverity = "Critical",
                RiskIndicators = ["scanner-agent"]
            }
        ]);

        var finding = Assert.IsType<IpFinding>(findingStore.Get("203.0.113.41"));
        Assert.Equal(3, finding.RequestCount);
        Assert.Equal(2, finding.SuspiciousRequestCount);
        Assert.Equal(9, finding.HighestRiskScore);
        Assert.Equal("Critical", finding.HighestRiskSeverity);
        Assert.Equal(new[] { "one.example", "two.example" }, finding.Domains);
        Assert.Equal(new[] { "probe", "scanner" }, finding.DetectionReasons.Order(StringComparer.Ordinal));
        Assert.Equal(new[] { "path-scan", "scanner-agent" }, finding.RiskIndicators);

        var domainFinding = Assert.IsType<IpFinding>(findingStore.Get("203.0.113.41", "one.example"));
        Assert.Equal(2, domainFinding.RequestCount);
        Assert.Equal(1, domainFinding.SuspiciousRequestCount);
        Assert.Equal(4, domainFinding.HighestRiskScore);
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
    public async Task Initializer_MigratesLegacySchemaAtomicallyAndUsesTimelineIndexes()
    {
        Directory.CreateDirectory(_rootPath);
        var databasePath = Path.Combine(_rootPath, "data", "test.sqlite3");
        Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
        using (var legacyConnection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString()))
        {
            legacyConnection.Open();
            using var legacyCommand = legacyConnection.CreateCommand();
            legacyCommand.CommandText = """
                CREATE TABLE ban_counts (
                    client_ip TEXT NOT NULL PRIMARY KEY,
                    ban_count INTEGER NOT NULL,
                    last_updated_utc TEXT NOT NULL);
                INSERT INTO ban_counts VALUES ('203.0.113.40', 7, '2026-10-01T00:00:00.0000000Z');
                """;
            legacyCommand.ExecuteNonQuery();
        }

        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);
        await initializer.StartAsync(CancellationToken.None);

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                (SELECT user_version FROM pragma_user_version),
                (SELECT journal_mode FROM pragma_journal_mode),
                (SELECT domain FROM ban_counts WHERE client_ip = '203.0.113.40'),
                (SELECT ban_count FROM ban_counts WHERE client_ip = '203.0.113.40'),
                (SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'analyst_incidents');
            """;
        using var reader = command.ExecuteReader();
        Assert.True(reader.Read());
        Assert.Equal(3, reader.GetInt32(0));
        Assert.Equal("wal", reader.GetString(1));
        Assert.Equal(string.Empty, reader.GetString(2));
        Assert.Equal(7, reader.GetInt32(3));
        Assert.Equal(1, reader.GetInt32(4));
        Assert.Contains("ix_events_domain_sequence", GetQueryPlan(connection,
            "SELECT event_id FROM events WHERE domain = 'example.test' ORDER BY sequence_id DESC LIMIT 100;"));
        var ipPlan = GetQueryPlan(connection,
            "SELECT event_id FROM events WHERE client_ip = '203.0.113.40' ORDER BY sequence_id DESC LIMIT 100;");
        Assert.Contains("ix_events_client_ip", ipPlan);
        Assert.DoesNotContain("USE TEMP B-TREE", ipPlan);
        var suspiciousPlan = GetQueryPlan(connection,
            "SELECT event_id FROM events WHERE is_suspicious = 1 ORDER BY sequence_id DESC LIMIT 100;");
        Assert.Contains("ix_events_suspicious_sequence", suspiciousPlan);
        Assert.DoesNotContain("USE TEMP B-TREE", suspiciousPlan);

        var findingsRiskPlan = GetQueryPlan(connection, """
            SELECT client_ip FROM ip_findings
            WHERE suspicious_count > 0 OR highest_risk_score > 0
            ORDER BY highest_risk_score DESC, suspicious_count DESC, last_seen DESC
            LIMIT 100;
            """);
        Assert.Contains("ix_ip_findings_risk", findingsRiskPlan);
        var findingsDomainPlan = GetQueryPlan(connection, """
            SELECT f.client_ip FROM ip_findings f
            INNER JOIN ip_finding_domains d ON d.client_ip = f.client_ip
            WHERE d.domain = 'example.test' AND (d.suspicious_count > 0 OR d.highest_risk_score > 0)
            ORDER BY d.highest_risk_score DESC, d.suspicious_count DESC, d.last_seen DESC
            LIMIT 100;
            """);
        Assert.Contains("ix_ip_finding_domains_domain", findingsDomainPlan);
        var expiredDomainPlan = GetQueryPlan(connection, """
            SELECT client_ip, domain FROM ip_finding_domains
            WHERE last_seen < '2026-10-01T00:00:00.0000000Z'
            ORDER BY last_seen LIMIT 1000;
            """);
        Assert.Contains("ix_ip_finding_domains_last_seen_client_ip", expiredDomainPlan);
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

        using var observability = new IisObservability();
        var eventStore = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, observability);
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
        Assert.Contains("sqlite_write_failures 1", observability.RenderPrometheus());
    }

    [Fact]
    public async Task Publish_ReportsBusyLockAfterConfiguredTimeout()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions
        {
            DatabasePath = "data/test.sqlite3",
            BusyTimeoutSeconds = 1
        });
        var etwOptions = Options.Create(new IisEtwOptions { SubscriptionBufferSize = 8 });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);

        using var blocker = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(_rootPath, "data", "test.sqlite3"),
            DefaultTimeout = 1
        }.ToString());
        blocker.Open();
        using var beginWrite = blocker.CreateCommand();
        beginWrite.CommandText = "BEGIN IMMEDIATE;";
        beginWrite.ExecuteNonQuery();

        using var observability = new IisObservability();
        var eventStore = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, observability);
        var elapsed = Stopwatch.StartNew();
        var exception = Assert.Throws<SqliteException>(() => eventStore.Publish(CreateEvent("busy-write", DateTimeOffset.UtcNow)));
        elapsed.Stop();

        Assert.Equal(5, exception.SqliteErrorCode);
        Assert.InRange(elapsed.Elapsed, TimeSpan.FromMilliseconds(800), TimeSpan.FromSeconds(5));
        Assert.Contains("sqlite_busy_failures 1", observability.RenderPrometheus());
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
        var exactCutoff = recentTimestamp.AddDays(-1);
        eventStore.Publish(new SecurityEvent(
            exactCutoff,
            "server01",
            "boundary.example",
            "GET",
            "/boundary",
            "203.0.113.27",
            200,
            "agent",
            new Dictionary<string, string>()));

        findingStore.Prune(exactCutoff);
        var activeFinding = Assert.IsType<IpFinding>(findingStore.Get("203.0.113.27"));
        Assert.DoesNotContain("old.example", activeFinding.Domains);
        Assert.Contains("new.example", activeFinding.Domains);
        Assert.Null(findingStore.Get("203.0.113.27", "old.example"));
        Assert.NotNull(findingStore.Get("203.0.113.27", "new.example"));
        Assert.NotNull(findingStore.Get("203.0.113.27", "boundary.example"));

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
    public async Task Subscribe_DisconnectsSlowConsumerAndAllowsCursorReplay()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var etwOptions = Options.Create(new IisEtwOptions { SubscriptionBufferSize = 2 });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);
        var store = new SqliteEventStore(etwOptions, storageOptions, environment, findingStore, new IisObservability());
        using var subscriptionLifetime = new CancellationTokenSource();
        var reader = store.Subscribe(subscriptionLifetime.Token);

        store.Publish(CreateEvent("first", DateTimeOffset.UtcNow));
        store.Publish(CreateEvent("second", DateTimeOffset.UtcNow.AddTicks(1)));
        store.Publish(CreateEvent("third", DateTimeOffset.UtcNow.AddTicks(2)));

        Assert.True(reader.TryRead(out var firstEvent));
        Assert.True(reader.TryRead(out var secondEvent));
        Assert.Equal("first", firstEvent.Id);
        Assert.Equal("second", secondEvent.Id);
        await Assert.ThrowsAsync<EventStreamSlowConsumerException>(() => reader.Completion);

        var replay = store.GetPageAfter(1, 10);
        Assert.Equal(["second", "third"], replay.Items.Select(static webEvent => webEvent.EventId));
        Assert.False(replay.GapDetected);
        subscriptionLifetime.Cancel();
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
    public async Task DetectorHistory_DoesNotRebuild404WindowsFromSqliteEvents()
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
        Assert.DoesNotContain("multiple 404 responses from the same client IP", analyzedEvent.RiskIndicators ?? []);
        Assert.DoesNotContain("request targets file type not seen in site history", analyzedEvent.RiskIndicators ?? []);
        eventStore.Publish(analyzedEvent);

        var finding = Assert.IsType<IpFinding>(findingStore.Get("203.0.113.98"));
        Assert.Equal(3, finding.RequestCount);
        Assert.Equal(1, finding.SuspiciousRequestCount);
        Assert.Contains("status code meets configured suspicious threshold", finding.RiskIndicators);
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

    private static string GetQueryPlan(SqliteConnection connection, string query)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "EXPLAIN QUERY PLAN " + query;
        using var reader = command.ExecuteReader();
        var details = new List<string>();
        while (reader.Read())
        {
            details.Add(reader.GetString(3));
        }

        return string.Join(Environment.NewLine, details);
    }

    private sealed class TestHostEnvironment(string contentRootPath) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "iisidsd.Tests";
        public string ContentRootPath { get; set; } = contentRootPath;
        public IFileProvider ContentRootFileProvider { get; set; } = new PhysicalFileProvider(contentRootPath);
    }
}
