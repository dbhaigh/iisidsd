using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Storage;
using Microsoft.Data.Sqlite;
using System.Text.Json;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Observability;

public sealed class IisObservabilityTests : IDisposable
{
    private readonly string _rootPath = Path.Combine(Path.GetTempPath(), "iisidsd-observability-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void RenderPrometheus_ExportsEventQueueAndSqliteMetrics()
    {
        using var observability = new IisObservability();
        var timestamp = DateTimeOffset.UtcNow;
        var securityEvent = new SecurityEvent(
            timestamp,
            "server01",
            "example.test",
            "GET",
            "/.env",
            "203.0.113.10",
            404,
            "test-agent",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            DetectionReason: "suspicious path",
            RiskScore: 8,
            RiskSeverity: "Critical");

        observability.RecordEtwEventReceived();
        observability.RecordEtwEventDropped();
        observability.RecordQueueItemEnqueued();
        observability.RecordQueueItemDequeued();
        observability.RecordEventProcessed(securityEvent);
        observability.RecordAutoDeny();
        observability.RecordSqliteWrite(TimeSpan.FromMilliseconds(12));

        var metrics = observability.RenderPrometheus();
        Assert.Contains("etw_events_received 1", metrics);
        Assert.Contains("etw_events_dropped 1", metrics);
        Assert.Contains("events_processed 1", metrics);
        Assert.Contains("suspicious_events 1", metrics);
        Assert.Contains("auto_denies 1", metrics);
        Assert.Contains("queue_depth 0", metrics);
        Assert.Contains("sqlite_write_duration_seconds_count 1", metrics);
        Assert.Equal(timestamp, observability.LastEventTimestamp);
    }

    [Fact]
    public void RecordEventProcessed_DoesNotMoveLastTimestampBackForLateEvents()
    {
        using var observability = new IisObservability();
        var latestTimestamp = DateTimeOffset.UtcNow;
        var laterEvent = new SecurityEvent(latestTimestamp, "server01", "example.test", "GET", "/", "203.0.113.10", 200,
            "test-agent", new Dictionary<string, string>());
        var delayedEvent = laterEvent with { Timestamp = latestTimestamp.AddMinutes(-1) };

        observability.RecordEventProcessed(laterEvent);
        observability.RecordEventProcessed(delayedEvent);

        Assert.Equal(latestTimestamp, observability.LastEventTimestamp);
    }

    [Fact]
    public void Diagnostics_ExposeAggregateMetricsWithoutRequestData()
    {
        using var observability = new IisObservability();
        var securityEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/private-path",
            "203.0.113.10",
            404,
            "private-agent",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            RiskScore: 8,
            RiskSeverity: "Critical",
            RiskIndicators: ["indicator-a", "indicator-b"]);

        observability.SetQueueCapacity(64);
        observability.SetEtwSubscriptionState(EtwSubscriptionState.Listening);
        observability.RecordDetectionAnalyzed(securityEvent);
        observability.RecordEventStreamStarted();
        observability.RecordEventStreamFailure();
        observability.RecordEventStreamEnded();
        observability.RecordEventRetentionRun(3);
        observability.RecordIisEnforcementOutcome("failed", simulation: false);
        observability.RecordExpiryCleanupCandidate();
        observability.RecordExpiryCleanupFailure();
        observability.RecordRecoveryAttempt("sqlite", "SqliteException");
        observability.RecordFatalError("runtime", "InvalidOperationException");

        var metrics = observability.RenderPrometheus();
        var snapshot = observability.GetOperationalDiagnosticsSnapshot("0.2.3", "abc123");
        var serializedSnapshot = JsonSerializer.Serialize(snapshot);

        Assert.Contains("queue_capacity 64", metrics);
        Assert.Contains("etw_subscription_state{state=\"listening\"} 1", metrics);
        Assert.Contains("detection_events_analyzed 1", metrics);
        Assert.Contains("detection_indicators 2", metrics);
        Assert.Contains("detection_events_by_severity{severity=\"critical\"} 1", metrics);
        Assert.Contains("detection_risk_score_bucket{le=\"8\"} 1", metrics);
        Assert.Contains("event_stream_connections 1", metrics);
        Assert.Contains("event_stream_failures 1", metrics);
        Assert.Contains("event_retention_events_pruned 3", metrics);
        Assert.Contains("iis_expiry_cleanup_failed 1", metrics);
        Assert.Contains("recovery_attempts 1", metrics);
        Assert.Contains("fatal_errors 1", metrics);
        Assert.Equal(0, snapshot.ActiveEventStreams);
        Assert.Equal(1, snapshot.IisAdministrationFailures);
        Assert.Equal(1, snapshot.DetectionEventsBySeverity["critical"]);
        Assert.Equal(5, snapshot.DetectionEventsBySeverity.Count);
        Assert.DoesNotContain("203.0.113.10", metrics);
        Assert.DoesNotContain("/private-path", metrics);
        Assert.DoesNotContain("private-agent", metrics);
        Assert.DoesNotContain("203.0.113.10", serializedSnapshot);
        Assert.DoesNotContain("/private-path", serializedSnapshot);
        Assert.DoesNotContain("private-agent", serializedSnapshot);
    }

    [Fact]
    public void SqliteHealthProbe_ReportsConnectionStatus()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var existingDatabaseOptions = Options.Create(new StorageOptions { DatabasePath = "data/health.sqlite3" });
        Directory.CreateDirectory(Path.Combine(_rootPath, "data"));
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(_rootPath, "data", "health.sqlite3")
        }.ToString()))
        {
            connection.Open();
        }

        var healthyProbe = new SqliteHealthProbe(
            existingDatabaseOptions,
            environment,
            NullLogger<SqliteHealthProbe>.Instance);
        var missingDatabaseProbe = new SqliteHealthProbe(
            Options.Create(new StorageOptions { DatabasePath = "data/missing.sqlite3" }),
            environment,
            NullLogger<SqliteHealthProbe>.Instance);

        Assert.True(healthyProbe.GetHealthSnapshot().Healthy);
        var missingSnapshot = missingDatabaseProbe.GetHealthSnapshot();
        Assert.False(missingSnapshot.Healthy);
        Assert.Equal(1, missingSnapshot.FailureCount);
        Assert.Equal("sqlite-error", missingSnapshot.LastFailureType);
        Assert.NotNull(missingSnapshot.LastCheckedAtUtc);
        Assert.DoesNotContain("missing.sqlite3", JsonSerializer.Serialize(missingSnapshot));
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_rootPath))
        {
            Directory.Delete(_rootPath, recursive: true);
        }
    }

    private sealed class TestHostEnvironment(string contentRootPath) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "iisidsd.Tests";
        public string ContentRootPath { get; set; } = contentRootPath;
        public IFileProvider ContentRootFileProvider { get; set; } = new PhysicalFileProvider(contentRootPath);
    }
}
