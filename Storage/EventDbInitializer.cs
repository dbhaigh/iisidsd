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
    private const int CurrentSchemaVersion = 3;
    private readonly string _databasePath = GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath);
    private readonly IFindingStore _findingStore = findingStore;
    private readonly ILogger<EventDbInitializer> _logger = logger;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        using var connection = SqliteConnectionFactory.Open(_databasePath, storageOptions.Value);
        SqliteConnectionFactory.ConfigureJournalMode(connection, storageOptions.Value);
        var schemaVersion = GetSchemaVersion(connection);
        if (schemaVersion > CurrentSchemaVersion)
        {
            throw new InvalidOperationException(
                $"Database schema version {schemaVersion} is newer than the supported version {CurrentSchemaVersion}.");
        }

        using var transaction = connection.BeginTransaction();

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
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
                CREATE INDEX IF NOT EXISTS ix_events_domain_sequence ON events(domain, sequence_id DESC);
                CREATE INDEX IF NOT EXISTS ix_events_suspicious_sequence ON events(is_suspicious, sequence_id DESC);
                DROP INDEX IF EXISTS ix_events_is_suspicious;
                CREATE UNIQUE INDEX IF NOT EXISTS ux_events_event_id ON events(event_id);

                CREATE TABLE IF NOT EXISTS event_retention_state (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    retained_event_count INTEGER NOT NULL,
                    pruned_through_sequence INTEGER NOT NULL DEFAULT 0);

                INSERT OR IGNORE INTO event_retention_state (singleton_id, retained_event_count)
                SELECT 1, COUNT(*) FROM events;

                CREATE TRIGGER IF NOT EXISTS trg_events_retention_insert
                AFTER INSERT ON events
                BEGIN
                    UPDATE event_retention_state
                    SET retained_event_count = retained_event_count + 1
                    WHERE singleton_id = 1;
                END;

                CREATE TABLE IF NOT EXISTS etw_ingestion_diagnostics (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    events_received INTEGER NOT NULL DEFAULT 0,
                    events_accepted INTEGER NOT NULL DEFAULT 0,
                    events_dropped INTEGER NOT NULL DEFAULT 0,
                    events_malformed INTEGER NOT NULL DEFAULT 0,
                    events_processed INTEGER NOT NULL DEFAULT 0,
                    processing_failures INTEGER NOT NULL DEFAULT 0,
                    auto_deny_failures INTEGER NOT NULL DEFAULT 0,
                    processing_retries INTEGER NOT NULL DEFAULT 0,
                    updated_utc TEXT NOT NULL
                );

                INSERT OR IGNORE INTO etw_ingestion_diagnostics (singleton_id, updated_utc)
                VALUES (1, '1970-01-01T00:00:00.0000000Z');

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
                CREATE INDEX IF NOT EXISTS ix_ip_finding_domains_last_seen_client_ip
                    ON ip_finding_domains(last_seen, client_ip);

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

                CREATE TABLE IF NOT EXISTS iis_managed_denies (
                    site_name TEXT NOT NULL COLLATE NOCASE,
                    client_ip TEXT NOT NULL COLLATE NOCASE,
                    expires_utc TEXT NULL,
                    state TEXT NOT NULL,
                    audit_id INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (site_name, client_ip)
                );

                CREATE TABLE IF NOT EXISTS analyst_incidents (
                    client_ip TEXT PRIMARY KEY COLLATE NOCASE,
                    status TEXT NOT NULL CHECK (status IN ('open', 'acknowledged', 'suppressed', 'resolved')),
                    note TEXT NOT NULL DEFAULT '',
                    updated_utc TEXT NOT NULL,
                    updated_by TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS ix_analyst_incidents_updated
                    ON analyst_incidents(updated_utc DESC);

                CREATE INDEX IF NOT EXISTS ix_iis_managed_denies_state
                    ON iis_managed_denies(state, expires_utc);

                INSERT OR IGNORE INTO iis_managed_denies (
                    site_name, client_ip, expires_utc, state, audit_id)
                SELECT site_name, client_ip, expires_utc, 'active', 0
                FROM iis_temporary_denies;
                """;
            command.ExecuteNonQuery();
        }

        EnsureEventRetentionCursorSchema(connection, transaction);
        EnsureBanCountSchema(connection, transaction);
        using (var versionCommand = connection.CreateCommand())
        {
            versionCommand.Transaction = transaction;
            versionCommand.CommandText = $"PRAGMA user_version = {CurrentSchemaVersion};";
            versionCommand.ExecuteNonQuery();
        }

        transaction.Commit();

        var backfilledEvents = _findingStore.BackfillFromExistingEvents();
        if (backfilledEvents > 0)
        {
            _logger.LogInformation("Backfilled findings from {EventCount} retained events.", backfilledEvents);
        }

        _logger.LogInformation("Initialized event database at {DatabasePath}.", _databasePath);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static void EnsureEventRetentionCursorSchema(SqliteConnection connection, SqliteTransaction transaction)
    {
        var hasPrunedCursor = false;
        using (var columnCheck = connection.CreateCommand())
        {
            columnCheck.Transaction = transaction;
            columnCheck.CommandText = "PRAGMA table_info(event_retention_state);";
            using var reader = columnCheck.ExecuteReader();
            while (reader.Read())
            {
                if (string.Equals(reader.GetString(1), "pruned_through_sequence", StringComparison.OrdinalIgnoreCase))
                {
                    hasPrunedCursor = true;
                    break;
                }
            }
        }

        if (!hasPrunedCursor)
        {
            using var alterCommand = connection.CreateCommand();
            alterCommand.Transaction = transaction;
            alterCommand.CommandText = "ALTER TABLE event_retention_state ADD COLUMN pruned_through_sequence INTEGER NOT NULL DEFAULT 0;";
            alterCommand.ExecuteNonQuery();
        }

        using var triggerCommand = connection.CreateCommand();
        triggerCommand.Transaction = transaction;
        triggerCommand.CommandText = """
            DROP TRIGGER IF EXISTS trg_events_retention_delete;
            CREATE TRIGGER trg_events_retention_delete
            AFTER DELETE ON events
            BEGIN
                UPDATE event_retention_state
                SET retained_event_count = retained_event_count - 1,
                    pruned_through_sequence = MAX(pruned_through_sequence, OLD.sequence_id)
                WHERE singleton_id = 1;
            END;
            """;
        triggerCommand.ExecuteNonQuery();
    }

    private static int GetSchemaVersion(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        return Convert.ToInt32(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static void EnsureBanCountSchema(SqliteConnection connection, SqliteTransaction transaction)
    {
        var hasBanCountsTable = false;
        using (var tableCheck = connection.CreateCommand())
        {
            tableCheck.Transaction = transaction;
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
            CreateBanCountsTable(connection, transaction);
            return;
        }

        var hasDomainColumn = false;
        using (var columnCheck = connection.CreateCommand())
        {
            columnCheck.Transaction = transaction;
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
            migrate.Transaction = transaction;
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

        CreateBanCountIndexes(connection, transaction);
    }

    private static void CreateBanCountsTable(SqliteConnection connection, SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
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
        CreateBanCountIndexes(connection, transaction);
    }

    private static void CreateBanCountIndexes(SqliteConnection connection, SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
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
