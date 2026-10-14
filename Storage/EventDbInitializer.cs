using iisidsd.Configuration;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class EventDbInitializer(
    IOptions<StorageOptions> storageOptions,
    IHostEnvironment hostEnvironment,
    IFindingStore findingStore,
    ILogger<EventDbInitializer> logger) : IHostedService
{
    private readonly string _databasePath = GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath);
    private readonly IFindingStore _findingStore = findingStore;
    private readonly ILogger<EventDbInitializer> _logger = logger;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_databasePath)!);

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString());
        connection.Open();

        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                CREATE TABLE IF NOT EXISTS events (
                    sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    server TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    user_agent TEXT NOT NULL,
                    properties_json TEXT NOT NULL,
                    is_suspicious INTEGER NOT NULL,
                    detection_reason TEXT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_severity TEXT NOT NULL,
                    risk_indicators_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS ix_events_timestamp_utc ON events(timestamp_utc DESC);
                CREATE INDEX IF NOT EXISTS ix_events_client_ip ON events(client_ip);
                CREATE INDEX IF NOT EXISTS ix_events_is_suspicious ON events(is_suspicious, timestamp_utc DESC);

                CREATE TABLE IF NOT EXISTS ip_findings (
                    client_ip TEXT PRIMARY KEY COLLATE NOCASE,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    request_count INTEGER NOT NULL,
                    suspicious_count INTEGER NOT NULL,
                    highest_risk_score INTEGER NOT NULL,
                    highest_risk_severity TEXT NOT NULL,
                    domains_json TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    indicators_json TEXT NOT NULL,
                    ban_count INTEGER NOT NULL DEFAULT 0,
                    updated_utc TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS ix_ip_findings_risk
                    ON ip_findings(highest_risk_score DESC, suspicious_count DESC, last_seen DESC);
                CREATE INDEX IF NOT EXISTS ix_ip_findings_last_seen ON ip_findings(last_seen);

                CREATE TABLE IF NOT EXISTS ip_finding_domains (
                    client_ip TEXT NOT NULL COLLATE NOCASE,
                    domain TEXT NOT NULL COLLATE NOCASE,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    request_count INTEGER NOT NULL,
                    suspicious_count INTEGER NOT NULL,
                    highest_risk_score INTEGER NOT NULL,
                    highest_risk_severity TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    indicators_json TEXT NOT NULL,
                    PRIMARY KEY (client_ip, domain)
                );

                CREATE INDEX IF NOT EXISTS ix_ip_finding_domains_domain
                    ON ip_finding_domains(domain, highest_risk_score DESC, suspicious_count DESC, last_seen DESC);

                CREATE TABLE IF NOT EXISTS iis_deny_list_audit (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    site_name TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    occurred_utc TEXT NOT NULL,
                    dry_run INTEGER NOT NULL,
                    outcome TEXT NOT NULL,
                    expires_utc TEXT NULL
                );

                CREATE INDEX IF NOT EXISTS ix_iis_deny_list_audit_actor_action
                    ON iis_deny_list_audit(actor, action, audit_id DESC);

                CREATE INDEX IF NOT EXISTS ix_iis_deny_list_audit_occurred
                    ON iis_deny_list_audit(occurred_utc DESC);

                CREATE TABLE IF NOT EXISTS iis_temporary_denies (
                    site_name TEXT NOT NULL COLLATE NOCASE,
                    client_ip TEXT NOT NULL COLLATE NOCASE,
                    expires_utc TEXT NOT NULL,
                    PRIMARY KEY (site_name, client_ip)
                );

                CREATE INDEX IF NOT EXISTS ix_iis_temporary_denies_expiry
                    ON iis_temporary_denies(expires_utc);
                """;
            command.ExecuteNonQuery();
        }

        EnsureBanCountSchema(connection);

        var backfilledEvents = _findingStore.BackfillFromExistingEvents();
        if (backfilledEvents > 0)
        {
            _logger.LogInformation("Backfilled findings from {EventCount} retained events.", backfilledEvents);
        }

        _logger.LogInformation("Initialized event database at {DatabasePath}.", _databasePath);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static void EnsureBanCountSchema(SqliteConnection connection)
    {
        var hasBanCountsTable = false;
        using (var tableCheck = connection.CreateCommand())
        {
            tableCheck.CommandText = """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table' AND name = 'ban_counts'
                LIMIT 1;
                """;
            hasBanCountsTable = tableCheck.ExecuteScalar() is not null;
        }

        if (!hasBanCountsTable)
        {
            CreateBanCountsTable(connection);
            return;
        }

        var hasDomainColumn = false;
        using (var columnCheck = connection.CreateCommand())
        {
            columnCheck.CommandText = "PRAGMA table_info(ban_counts);";
            using var reader = columnCheck.ExecuteReader();
            while (reader.Read())
            {
                if (string.Equals(reader.GetString(1), "domain", StringComparison.OrdinalIgnoreCase))
                {
                    hasDomainColumn = true;
                    break;
                }
            }
        }

        if (!hasDomainColumn)
        {
            using var migrate = connection.CreateCommand();
            migrate.CommandText = """
                ALTER TABLE ban_counts RENAME TO ban_counts_legacy;

                CREATE TABLE ban_counts (
                    client_ip TEXT NOT NULL,
                    domain TEXT NOT NULL DEFAULT '',
                    ban_count INTEGER NOT NULL,
                    last_updated_utc TEXT NOT NULL,
                    PRIMARY KEY (client_ip, domain)
                );

                INSERT INTO ban_counts (client_ip, domain, ban_count, last_updated_utc)
                SELECT client_ip, '', ban_count, last_updated_utc
                FROM ban_counts_legacy;

                DROP TABLE ban_counts_legacy;
                """;
            migrate.ExecuteNonQuery();
        }

        CreateBanCountIndexes(connection);
    }

    private static void CreateBanCountsTable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE ban_counts (
                client_ip TEXT NOT NULL,
                domain TEXT NOT NULL DEFAULT '',
                ban_count INTEGER NOT NULL,
                last_updated_utc TEXT NOT NULL,
                PRIMARY KEY (client_ip, domain)
            );
            """;
        command.ExecuteNonQuery();
        CreateBanCountIndexes(connection);
    }

    private static void CreateBanCountIndexes(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_ban_counts_ban_count ON ban_counts(ban_count DESC, last_updated_utc DESC);
            CREATE INDEX IF NOT EXISTS ix_ban_counts_domain_client_ip ON ban_counts(domain, client_ip);
            """;
        command.ExecuteNonQuery();
    }

    private static string GetDatabasePath(string contentRootPath, string configuredPath)
        => Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(contentRootPath, configuredPath));
}
