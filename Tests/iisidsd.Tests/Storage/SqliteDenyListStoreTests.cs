using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Storage;

public sealed class SqliteDenyListStoreTests : IDisposable
{
    private readonly string _rootPath = Path.Combine(Path.GetTempPath(), "iisidsd-deny-store-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Store_PersistsAuditAndTemporaryBanExpiry()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);

        var store = new SqliteDenyListStore(storageOptions, environment);
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
        var auditId = store.BeginAudit(new DenyListAuditRecord(
            0,
            "DOMAIN\\admin",
            "add",
            "Example Site",
            "203.0.113.10",
            "Manual investigation",
            DateTimeOffset.UtcNow,
            DryRun: false,
            "pending",
            expiresAt));
        store.SetExpiry("Example Site", "203.0.113.10", expiresAt);
        store.SetExpiry("Another Site", "203.0.113.11", expiresAt);
        store.SetAuditExpiry(auditId, expiresAt.AddMinutes(1));
        store.CompleteAudit(auditId, "succeeded");

        var audit = Assert.Single(store.GetRecentAudit(10));
        Assert.Equal("DOMAIN\\admin", audit.Actor);
        Assert.Equal("Manual investigation", audit.Reason);
        Assert.Equal("succeeded", audit.Outcome);
        Assert.Equal(expiresAt.AddMinutes(1), audit.ExpiresAt);
        Assert.Equal(expiresAt, store.GetExpiry("Example Site", "203.0.113.10"));
        Assert.Empty(store.GetExpired(DateTimeOffset.UtcNow, 10));
        var expiredEntries = store.GetExpired(expiresAt.AddSeconds(1), 1);
        Assert.Equal("203.0.113.11", Assert.Single(expiredEntries).ClientIp);
        Assert.Equal(
            "203.0.113.10",
            Assert.Single(store.GetExpired(expiresAt.AddSeconds(1), 1, expiredEntries[0])).ClientIp);
    }

    [Fact]
    public async Task BeginAudit_DoesNotDeleteOlderAuditEntries()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
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
                WITH RECURSIVE sequence(value) AS (
                    SELECT 1
                    UNION ALL
                    SELECT value + 1 FROM sequence WHERE value < 10000
                )
                INSERT INTO iis_deny_list_audit (
                    actor, action, site_name, client_ip, reason, occurred_utc, dry_run, outcome)
                SELECT 'test', 'add', 'site', '203.0.113.1', 'seed', '2026-10-14T00:00:00.0000000Z', 0, 'succeeded'
                FROM sequence;
                """;
            command.ExecuteNonQuery();
        }

        var store = new SqliteDenyListStore(storageOptions, environment);
        store.BeginAudit(new DenyListAuditRecord(
            0,
            "test",
            "remove",
            "site",
            "203.0.113.1",
            "next record",
            DateTimeOffset.UtcNow,
            DryRun: false,
            "pending",
            null));

        using var verifyConnection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(_rootPath, "data", "test.sqlite3")
        }.ToString());
        verifyConnection.Open();
        using var verifyCommand = verifyConnection.CreateCommand();
        verifyCommand.CommandText = "SELECT COUNT(*) FROM iis_deny_list_audit;";
        Assert.Equal(10001L, (long)verifyCommand.ExecuteScalar()!);
    }

    [Fact]
    public async Task GetLastAutoDeny_ReturnsNewestAutomaticAddAcrossManualActions()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);

        var store = new SqliteDenyListStore(storageOptions, environment);
        var autoAuditId = store.BeginAudit(new DenyListAuditRecord(
            0,
            "system:auto-deny",
            "add",
            "Example Site",
            "203.0.113.20",
            "Automatic finding",
            DateTimeOffset.UtcNow,
            DryRun: true,
            "pending",
            null));
        store.CompleteAudit(autoAuditId, "dry-run");
        store.BeginAudit(new DenyListAuditRecord(
            0,
            "DOMAIN\\admin",
            "add",
            "Example Site",
            "203.0.113.21",
            "Manual action",
            DateTimeOffset.UtcNow,
            DryRun: false,
            "pending",
            null));

        var lastAutoDeny = Assert.IsType<DenyListAuditRecord>(store.GetLastAutoDeny());
        Assert.Equal("system:auto-deny", lastAutoDeny.Actor);
        Assert.Equal("203.0.113.20", lastAutoDeny.ClientIp);
        Assert.Equal("dry-run", lastAutoDeny.Outcome);
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
