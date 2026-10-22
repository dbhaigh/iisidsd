using System.Globalization;
using System.Security.Cryptography;
using System.Text;
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
    private readonly string _mutationMutexName = CreateMutationMutexName(
        GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath));
    private readonly Lock _sync = new();
    private readonly Lock _writeSync = SqliteDatabaseLock.For(
        GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath));

    public IDisposable AcquireMutationLock()
    {
        var mutex = new Mutex(false, _mutationMutexName);
        try
        {
            try
            {
                mutex.WaitOne();
            }
            catch (AbandonedMutexException)
            {
            }

            return new MutationMutexLease(mutex);
        }
        catch
        {
            mutex.Dispose();
            throw;
        }
    }

    public long BeginAudit(DenyListAuditRecord record)
        => InsertAudit(record, "pending");

    public long RecordAudit(DenyListAuditRecord record)
        => InsertAudit(record, record.Outcome);

    private long InsertAudit(DenyListAuditRecord record, string outcome)
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
                    $actor, $action, $siteName, $clientIp, $reason, $occurredUtc, $dryRun, $outcome, $expiresUtc);
                SELECT last_insert_rowid();
                """;
            AddAuditParameters(command, record);
            command.Parameters.AddWithValue("$outcome", outcome);
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

    public ManagedDenyListEntry? GetManagedDeny(string siteName, string clientIp)
    {
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT site_name, client_ip, expires_utc, state, audit_id
                FROM iis_managed_denies
                WHERE site_name = $siteName AND client_ip = $clientIp;
                """;
            command.Parameters.AddWithValue("$siteName", siteName);
            command.Parameters.AddWithValue("$clientIp", clientIp);
            using var reader = command.ExecuteReader();
            return reader.Read() ? ReadManagedDeny(reader) : null;
        }
    }

    public IReadOnlyList<ManagedDenyListEntry> GetPendingManagedDenies(int limit)
    {
        var entries = new List<ManagedDenyListEntry>();
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT site_name, client_ip, expires_utc, state, audit_id
                FROM iis_managed_denies
                WHERE state <> 'active'
                ORDER BY site_name COLLATE NOCASE, client_ip COLLATE NOCASE
                LIMIT $limit;
                """;
            command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                entries.Add(ReadManagedDeny(reader));
            }
        }

        return entries;
    }

    public bool TryPrepareManagedDeny(ManagedDenyListEntry entry)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT OR IGNORE INTO iis_managed_denies (
                    site_name, client_ip, expires_utc, state, audit_id)
                VALUES ($siteName, $clientIp, $expiresUtc, $state, $auditId);
                """;
            command.Parameters.AddWithValue("$siteName", entry.SiteName);
            command.Parameters.AddWithValue("$clientIp", entry.ClientIp);
            command.Parameters.AddWithValue("$expiresUtc", entry.ExpiresAt is { } expiresAt
                ? FormatTimestamp(expiresAt)
                : DBNull.Value);
            command.Parameters.AddWithValue("$state", entry.State);
            command.Parameters.AddWithValue("$auditId", entry.AuditId);
            return command.ExecuteNonQuery() == 1;
        }
    }

    public bool CompleteManagedDeny(string siteName, string clientIp, DateTimeOffset? expiresAt, long auditId)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            using (var update = connection.CreateCommand())
            {
                update.Transaction = transaction;
                update.CommandText = """
                    UPDATE iis_managed_denies
                    SET expires_utc = $expiresUtc, state = 'active', audit_id = $auditId
                                        WHERE site_name = $siteName AND client_ip = $clientIp
                                            AND state IN ('pending-add', 'pending-remove', 'recovery-required')
                                            AND audit_id = $auditId;
                    """;
                update.Parameters.AddWithValue("$expiresUtc", expiresAt is { } value
                    ? FormatTimestamp(value)
                    : DBNull.Value);
                update.Parameters.AddWithValue("$auditId", auditId);
                update.Parameters.AddWithValue("$siteName", siteName);
                update.Parameters.AddWithValue("$clientIp", clientIp);
                if (update.ExecuteNonQuery() != 1)
                {
                    return false;
                }
            }

            using (var expiry = connection.CreateCommand())
            {
                expiry.Transaction = transaction;
                expiry.CommandText = expiresAt is null
                    ? "DELETE FROM iis_temporary_denies WHERE site_name = $siteName AND client_ip = $clientIp;"
                    : """
                        INSERT INTO iis_temporary_denies (site_name, client_ip, expires_utc)
                        VALUES ($siteName, $clientIp, $expiresUtc)
                        ON CONFLICT(site_name, client_ip) DO UPDATE SET expires_utc = excluded.expires_utc;
                        """;
                expiry.Parameters.AddWithValue("$siteName", siteName);
                expiry.Parameters.AddWithValue("$clientIp", clientIp);
                if (expiresAt is { } expiryValue)
                {
                    expiry.Parameters.AddWithValue("$expiresUtc", FormatTimestamp(expiryValue));
                }

                expiry.ExecuteNonQuery();
            }

            transaction.Commit();
            return true;
        }
    }

    public bool TryTransitionManagedDeny(
        string siteName,
        string clientIp,
        string expectedState,
        long expectedAuditId,
        string state,
        long auditId)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                UPDATE iis_managed_denies
                SET state = $state, audit_id = $auditId
                WHERE site_name = $siteName AND client_ip = $clientIp
                  AND state = $expectedState AND audit_id = $expectedAuditId;
                """;
            command.Parameters.AddWithValue("$state", state);
            command.Parameters.AddWithValue("$auditId", auditId);
            command.Parameters.AddWithValue("$siteName", siteName);
            command.Parameters.AddWithValue("$clientIp", clientIp);
            command.Parameters.AddWithValue("$expectedState", expectedState);
            command.Parameters.AddWithValue("$expectedAuditId", expectedAuditId);
            return command.ExecuteNonQuery() == 1;
        }
    }

    public bool TryRemoveManagedDeny(string siteName, string clientIp, string expectedState, long expectedAuditId)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            using (var managed = connection.CreateCommand())
            {
                managed.Transaction = transaction;
                managed.CommandText = """
                    DELETE FROM iis_managed_denies
                    WHERE site_name = $siteName AND client_ip = $clientIp
                      AND state = $expectedState AND audit_id = $expectedAuditId;
                    """;
                managed.Parameters.AddWithValue("$siteName", siteName);
                managed.Parameters.AddWithValue("$clientIp", clientIp);
                managed.Parameters.AddWithValue("$expectedState", expectedState);
                managed.Parameters.AddWithValue("$expectedAuditId", expectedAuditId);
                if (managed.ExecuteNonQuery() != 1)
                {
                    return false;
                }
            }

            using (var expiry = connection.CreateCommand())
            {
                expiry.Transaction = transaction;
                expiry.CommandText = "DELETE FROM iis_temporary_denies WHERE site_name = $siteName AND client_ip = $clientIp;";
                expiry.Parameters.AddWithValue("$siteName", siteName);
                expiry.Parameters.AddWithValue("$clientIp", clientIp);
                expiry.ExecuteNonQuery();
            }

            transaction.Commit();
            return true;
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
        => SqliteConnectionFactory.Open(_databasePath, storageOptions.Value);

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

    private static string CreateMutationMutexName(string databasePath)
    {
        var normalizedPath = Path.GetFullPath(databasePath).ToUpperInvariant();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalizedPath)));
        return $"Global\\iisidsd-denylist-{hash}";
    }

    private sealed class MutationMutexLease(Mutex mutex) : IDisposable
    {
        private Mutex? _mutex = mutex;

        public void Dispose()
        {
            var ownedMutex = Interlocked.Exchange(ref _mutex, null);
            if (ownedMutex is null)
            {
                return;
            }

            try
            {
                ownedMutex.ReleaseMutex();
            }
            finally
            {
                ownedMutex.Dispose();
            }
        }
    }

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

    private static ManagedDenyListEntry ReadManagedDeny(SqliteDataReader reader)
        => new(
            reader.GetString(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : ParseTimestamp(reader.GetString(2)),
            reader.GetString(3),
            reader.GetInt64(4));
}
