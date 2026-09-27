using iisidsd.Configuration;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class EventDbInitializer(
    IOptions<StorageOptions> storageOptions,
    IHostEnvironment hostEnvironment,
    ILogger<EventDbInitializer> logger) : IHostedService
{
    private readonly string _databasePath = GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath);

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
                """;
            command.ExecuteNonQuery();
        }

        EnsureBanCountSchema(connection);

        logger.LogInformation("Initialized event database at {DatabasePath}.", _databasePath);
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
