using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Storage;
using Microsoft.Data.Sqlite;
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

        Assert.True(healthyProbe.IsHealthy());
        Assert.False(missingDatabaseProbe.IsHealthy());
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
