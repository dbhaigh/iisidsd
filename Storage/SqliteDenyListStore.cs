using System.Globalization;
using iisidsd.Configuration;
using iisidsd.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class SqliteDenyListStore(
    IOptions<StorageOptions> storageOptions,
    IHostEnvironment hostEnvironment) : IDenyListStore
{
    private readonly string _databasePath = GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath);
    private readonly Lock _sync = new();
    private readonly Lock _writeSync = SqliteDatabaseLock.For(
        GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath));

    public long BeginAudit(DenyListAuditRecord record)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO iis_deny_list_audit (
                    actor, action, site_name, client_ip, reason, occurred_utc, dry_run, outcome, expires_utc)
                VALUES (
                    $actor, $action, $siteName, $clientIp, $reason, $occurredUtc, $dryRun, 'pending', $expiresUtc);
                SELECT last_insert_rowid();
                """;
            AddAuditParameters(command, record);
            var auditId = Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
            transaction.Commit();
            return auditId;
        }
    }

    public void CompleteAudit(long auditId, string outcome)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE iis_deny_list_audit SET outcome = $outcome WHERE audit_id = $auditId;";
            command.Parameters.AddWithValue("$outcome", outcome);
            command.Parameters.AddWithValue("$auditId", auditId);
            command.ExecuteNonQuery();
        }
    }

    public void SetAuditExpiry(long auditId, DateTimeOffset? expiresAt)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE iis_deny_list_audit SET expires_utc = $expiresUtc WHERE audit_id = $auditId;";
            command.Parameters.AddWithValue("$expiresUtc", expiresAt is { } value
                ? FormatTimestamp(value)
                : DBNull.Value);
            command.Parameters.AddWithValue("$auditId", auditId);
            command.ExecuteNonQuery();
        }
    }

    public IReadOnlyList<DenyListAuditRecord> GetRecentAudit(int limit)
    {
        var records = new List<DenyListAuditRecord>();
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT audit_id, actor, action, site_name, client_ip, reason, occurred_utc, dry_run, outcome, expires_utc
                FROM iis_deny_list_audit
                ORDER BY audit_id DESC
                LIMIT $limit;
                """;
            command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 500));
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                records.Add(ReadAuditRecord(reader));
            }
        }

        return records;
    }

    public DenyListAuditRecord? GetLastAutoDeny()
    {
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT audit_id, actor, action, site_name, client_ip, reason, occurred_utc, dry_run, outcome, expires_utc
                FROM iis_deny_list_audit
                WHERE actor = $actor AND action = $action
                ORDER BY audit_id DESC
                LIMIT 1;
                """;
            command.Parameters.AddWithValue("$actor", "system:auto-deny");
            command.Parameters.AddWithValue("$action", "add");
            using var reader = command.ExecuteReader();
            return reader.Read() ? ReadAuditRecord(reader) : null;
        }
    }

    public DateTimeOffset? GetExpiry(string siteName, string clientIp)
    {
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT expires_utc
                FROM iis_temporary_denies
                WHERE site_name = $siteName AND client_ip = $clientIp;
                """;
            command.Parameters.AddWithValue("$siteName", siteName);
            command.Parameters.AddWithValue("$clientIp", clientIp);
            var expiresUtc = command.ExecuteScalar() as string;
            return expiresUtc is null ? null : ParseTimestamp(expiresUtc);
        }
    }

    public void SetExpiry(string siteName, string clientIp, DateTimeOffset expiresAt)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO iis_temporary_denies (site_name, client_ip, expires_utc)
                VALUES ($siteName, $clientIp, $expiresUtc)
                ON CONFLICT(site_name, client_ip) DO UPDATE SET expires_utc = excluded.expires_utc;
                """;
            command.Parameters.AddWithValue("$siteName", siteName);
            command.Parameters.AddWithValue("$clientIp", clientIp);
            command.Parameters.AddWithValue("$expiresUtc", FormatTimestamp(expiresAt));
            command.ExecuteNonQuery();
        }
    }

    public void RemoveExpiry(string siteName, string clientIp)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM iis_temporary_denies WHERE site_name = $siteName AND client_ip = $clientIp;";
            command.Parameters.AddWithValue("$siteName", siteName);
            command.Parameters.AddWithValue("$clientIp", clientIp);
            command.ExecuteNonQuery();
        }
    }

    public IReadOnlyList<TemporaryDenyListEntry> GetExpired(
        DateTimeOffset now,
        int limit,
        TemporaryDenyListEntry? after = null)
    {
        var entries = new List<TemporaryDenyListEntry>();
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT site_name, client_ip, expires_utc
                FROM iis_temporary_denies
                WHERE expires_utc <= $now
                  AND (
                    $afterExpiresUtc IS NULL
                    OR expires_utc > $afterExpiresUtc
                    OR (expires_utc = $afterExpiresUtc AND site_name COLLATE NOCASE > $afterSiteName COLLATE NOCASE)
                    OR (expires_utc = $afterExpiresUtc
                        AND site_name = $afterSiteName COLLATE NOCASE
                        AND client_ip COLLATE NOCASE > $afterClientIp COLLATE NOCASE))
                ORDER BY expires_utc, site_name COLLATE NOCASE, client_ip COLLATE NOCASE
                LIMIT $limit;
                """;
            command.Parameters.AddWithValue("$now", FormatTimestamp(now));
            command.Parameters.AddWithValue("$afterExpiresUtc", after is null ? DBNull.Value : FormatTimestamp(after.ExpiresAt));
            command.Parameters.AddWithValue("$afterSiteName", (object?)after?.SiteName ?? DBNull.Value);
            command.Parameters.AddWithValue("$afterClientIp", (object?)after?.ClientIp ?? DBNull.Value);
            command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                entries.Add(new TemporaryDenyListEntry(
                    reader.GetString(0),
                    reader.GetString(1),
                    ParseTimestamp(reader.GetString(2))));
            }
        }

        return entries;
    }

    private SqliteConnection OpenConnection()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_databasePath)!);
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString());
        connection.Open();
        return connection;
    }

    private static void AddAuditParameters(SqliteCommand command, DenyListAuditRecord record)
    {
        command.Parameters.AddWithValue("$actor", record.Actor);
        command.Parameters.AddWithValue("$action", record.Action);
        command.Parameters.AddWithValue("$siteName", record.SiteName);
        command.Parameters.AddWithValue("$clientIp", record.ClientIp);
        command.Parameters.AddWithValue("$reason", record.Reason);
        command.Parameters.AddWithValue("$occurredUtc", FormatTimestamp(record.OccurredAt));
        command.Parameters.AddWithValue("$dryRun", record.DryRun ? 1 : 0);
        command.Parameters.AddWithValue("$expiresUtc", record.ExpiresAt is { } expiresAt
            ? FormatTimestamp(expiresAt)
            : DBNull.Value);
    }

    private static DateTimeOffset ParseTimestamp(string value)
        => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static string FormatTimestamp(DateTimeOffset value)
        => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static string GetDatabasePath(string contentRootPath, string configuredPath)
        => Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(contentRootPath, configuredPath));

    private static DenyListAuditRecord ReadAuditRecord(SqliteDataReader reader)
        => new(
            reader.GetInt64(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetString(5),
            ParseTimestamp(reader.GetString(6)),
            reader.GetInt32(7) != 0,
            reader.GetString(8),
            reader.IsDBNull(9) ? null : ParseTimestamp(reader.GetString(9)));
}
