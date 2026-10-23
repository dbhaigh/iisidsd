using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using iisidsd.Configuration;
using iisidsd.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class SqliteNotificationQueue(
    IOptions<StorageOptions> storageOptions,
    IOptions<NotificationOptions> notificationOptions,
    IHostEnvironment hostEnvironment,
    TimeProvider? timeProvider = null) : INotificationQueue
{
    private const int MaximumListLimit = 500;
    private const int MaximumEvidenceItems = 16;
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly StorageOptions _storageOptions = storageOptions.Value;
    private readonly NotificationOptions _notificationOptions = notificationOptions.Value;
    private readonly string _databasePath = GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath);
    private readonly Lock _writeSync = SqliteDatabaseLock.For(GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public NotificationEnqueueResult Enqueue(SecurityEvent webEvent, SqliteConnection connection, SqliteTransaction transaction)
    {
        if (!webEvent.IsSuspicious || !_notificationOptions.MeetsAlertThreshold(webEvent.RiskScore, webEvent.RiskSeverity))
        {
            return NotificationEnqueueResult.NotEligible;
        }

        var now = _timeProvider.GetUtcNow();
        var nowText = FormatTimestamp(now);
        using (var pruneCommand = connection.CreateCommand())
        {
            pruneCommand.Transaction = transaction;
            pruneCommand.CommandText = "DELETE FROM notification_incidents WHERE status IN ('delivered', 'failed', 'acknowledged') AND last_seen_utc < $cutoff;";
            pruneCommand.Parameters.AddWithValue("$cutoff", FormatTimestamp(now.AddDays(-_notificationOptions.RetentionDays)));
            pruneCommand.ExecuteNonQuery();
        }

        var deduplicationKey = CreateDeduplicationKey(webEvent.ClientIp, webEvent.Domain);
        var exists = false;
        using (var existsCommand = connection.CreateCommand())
        {
            existsCommand.Transaction = transaction;
            existsCommand.CommandText = "SELECT 1 FROM notification_incidents WHERE deduplication_key = $key LIMIT 1;";
            existsCommand.Parameters.AddWithValue("$key", deduplicationKey);
            exists = existsCommand.ExecuteScalar() is not null;
        }

        if (!exists)
        {
            using var capacityCommand = connection.CreateCommand();
            capacityCommand.Transaction = transaction;
            capacityCommand.CommandText = "SELECT COUNT(*) FROM notification_incidents WHERE status IN ('pending', 'retry');";
            if (Convert.ToInt32(capacityCommand.ExecuteScalar(), CultureInfo.InvariantCulture) >= _notificationOptions.QueueCapacity)
            {
                IncrementDroppedCount(connection, transaction);
                return NotificationEnqueueResult.CapacityExceeded;
            }

            using var storageCapacityCommand = connection.CreateCommand();
            storageCapacityCommand.Transaction = transaction;
            storageCapacityCommand.CommandText = "SELECT COUNT(*) FROM notification_incidents;";
            if (Convert.ToInt32(storageCapacityCommand.ExecuteScalar(), CultureInfo.InvariantCulture) >= _notificationOptions.StoredIncidentLimit)
            {
                IncrementDroppedCount(connection, transaction);
                return NotificationEnqueueResult.CapacityExceeded;
            }
        }

        var evidence = (webEvent.DetectionEvidence ?? [])
            .Where(static item => item.Contributed)
            .Take(MaximumEvidenceItems)
            .ToArray();
        var id = Guid.NewGuid().ToString("N");
        var cooldownUntil = FormatTimestamp(now.AddMinutes(_notificationOptions.CooldownMinutes));
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO notification_incidents (
                notification_id, deduplication_key, client_ip, target_site, summary, risk_score,
                risk_severity, event_timestamp_utc, first_seen_utc, last_seen_utc, evidence_json,
                status, attempt_count, next_attempt_utc, cooldown_until_utc, created_utc)
            VALUES (
                $id, $key, $clientIp, $targetSite, $summary, $riskScore,
                $riskSeverity, $eventTimestamp, $now, $now, $evidence,
                'pending', 0, $now, $cooldownUntil, $now)
            ON CONFLICT(deduplication_key) DO UPDATE SET
                status = CASE WHEN $now >= notification_incidents.cooldown_until_utc THEN 'pending' ELSE notification_incidents.status END,
                attempt_count = CASE WHEN $now >= notification_incidents.cooldown_until_utc THEN 0 ELSE notification_incidents.attempt_count END,
                next_attempt_utc = CASE WHEN $now >= notification_incidents.cooldown_until_utc THEN $now ELSE notification_incidents.next_attempt_utc END,
                delivered_utc = CASE WHEN $now >= notification_incidents.cooldown_until_utc THEN NULL ELSE notification_incidents.delivered_utc END,
                acknowledged_utc = CASE WHEN $now >= notification_incidents.cooldown_until_utc THEN NULL ELSE notification_incidents.acknowledged_utc END,
                acknowledged_by = CASE WHEN $now >= notification_incidents.cooldown_until_utc THEN NULL ELSE notification_incidents.acknowledged_by END,
                last_failure_type = CASE WHEN $now >= notification_incidents.cooldown_until_utc THEN NULL ELSE notification_incidents.last_failure_type END,
                first_seen_utc = CASE WHEN $now >= notification_incidents.cooldown_until_utc THEN $now ELSE notification_incidents.first_seen_utc END,
                cooldown_until_utc = CASE WHEN $now >= notification_incidents.cooldown_until_utc THEN $cooldownUntil ELSE notification_incidents.cooldown_until_utc END,
                target_site = excluded.target_site,
                summary = excluded.summary,
                risk_score = excluded.risk_score,
                risk_severity = excluded.risk_severity,
                event_timestamp_utc = excluded.event_timestamp_utc,
                last_seen_utc = excluded.last_seen_utc,
                evidence_json = excluded.evidence_json;
            """;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$key", deduplicationKey);
        command.Parameters.AddWithValue("$clientIp", webEvent.ClientIp);
        command.Parameters.AddWithValue("$targetSite", webEvent.Domain);
        command.Parameters.AddWithValue("$summary", CreateSummary(webEvent));
        command.Parameters.AddWithValue("$riskScore", webEvent.RiskScore);
        command.Parameters.AddWithValue("$riskSeverity", webEvent.RiskSeverity);
        command.Parameters.AddWithValue("$eventTimestamp", FormatTimestamp(webEvent.Timestamp));
        command.Parameters.AddWithValue("$now", nowText);
        command.Parameters.AddWithValue("$evidence", JsonSerializer.Serialize(evidence, SerializerOptions));
        command.Parameters.AddWithValue("$cooldownUntil", cooldownUntil);
        command.ExecuteNonQuery();
        return exists ? NotificationEnqueueResult.Deduplicated : NotificationEnqueueResult.Enqueued;
    }

    public IReadOnlyList<NotificationIncident> List(int limit = 250)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT notification_id, client_ip, target_site, summary, risk_score, risk_severity,
                   event_timestamp_utc, first_seen_utc, last_seen_utc, evidence_json, status,
                   attempt_count, next_attempt_utc, delivered_utc, acknowledged_utc, last_failure_type, acknowledged_by
            FROM notification_incidents
            ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'retry' THEN 1 WHEN 'failed' THEN 2 ELSE 3 END,
                     last_seen_utc DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, MaximumListLimit));
        return ReadIncidents(command);
    }

    public IReadOnlyList<NotificationIncident> GetDue(DateTimeOffset now, int limit = 25)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT notification_id, client_ip, target_site, summary, risk_score, risk_severity,
                   event_timestamp_utc, first_seen_utc, last_seen_utc, evidence_json, status,
                   attempt_count, next_attempt_utc, delivered_utc, acknowledged_utc, last_failure_type, acknowledged_by
            FROM notification_incidents
            WHERE status IN ('pending', 'retry') AND next_attempt_utc <= $now
            ORDER BY next_attempt_utc, first_seen_utc
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$now", FormatTimestamp(now));
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 100));
        return ReadIncidents(command);
    }

    public NotificationQueueStatus GetStatus()
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                COALESCE(SUM(status = 'pending'), 0),
                COALESCE(SUM(status = 'retry'), 0),
                COALESCE(SUM(status = 'delivered'), 0),
                COALESCE(SUM(status = 'failed'), 0),
                COALESCE(SUM(status = 'acknowledged'), 0),
                (SELECT dropped_count FROM notification_queue_state WHERE singleton_id = 1)
            FROM notification_incidents;
            """;
        using var reader = command.ExecuteReader();
        reader.Read();
        return new NotificationQueueStatus(
            reader.GetInt32(0), reader.GetInt32(1), reader.GetInt32(2),
            reader.GetInt32(3), reader.GetInt32(4), reader.GetInt32(5));
    }

    public int PruneExpired(DateTimeOffset olderThanUtc)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM notification_incidents WHERE status IN ('delivered', 'failed', 'acknowledged') AND last_seen_utc < $cutoff;";
            command.Parameters.AddWithValue("$cutoff", FormatTimestamp(olderThanUtc));
            return command.ExecuteNonQuery();
        }
    }

    public void RecordDelivered(string id, DateTimeOffset attemptedAtUtc)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                UPDATE notification_incidents
                SET status = 'delivered', attempt_count = attempt_count + 1,
                    next_attempt_utc = NULL, delivered_utc = $now,
                    last_attempt_utc = $now, last_failure_type = NULL
                WHERE notification_id = $id AND status IN ('pending', 'retry');
                """;
            command.Parameters.AddWithValue("$id", id);
            command.Parameters.AddWithValue("$now", FormatTimestamp(attemptedAtUtc));
            command.ExecuteNonQuery();
        }
    }

    public void RecordFailure(string id, DateTimeOffset attemptedAtUtc, string failureType)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            var attemptCount = 0;
            using (var readCommand = connection.CreateCommand())
            {
                readCommand.Transaction = transaction;
                readCommand.CommandText = "SELECT attempt_count FROM notification_incidents WHERE notification_id = $id AND status IN ('pending', 'retry');";
                readCommand.Parameters.AddWithValue("$id", id);
                if (readCommand.ExecuteScalar() is not long currentAttempts)
                {
                    transaction.Rollback();
                    return;
                }

                attemptCount = checked((int)currentAttempts + 1);
            }

            var isFailed = attemptCount >= _notificationOptions.MaximumAttempts;
            var delaySeconds = Math.Min(
                _notificationOptions.MaximumRetryDelaySeconds,
                _notificationOptions.RetryDelaySeconds * Math.Pow(2, Math.Min(attemptCount - 1, 20)));
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                UPDATE notification_incidents
                SET status = $status, attempt_count = $attemptCount,
                    next_attempt_utc = $nextAttempt, last_attempt_utc = $now,
                    last_failure_type = $failureType
                WHERE notification_id = $id AND status IN ('pending', 'retry');
                """;
            command.Parameters.AddWithValue("$id", id);
            command.Parameters.AddWithValue("$status", isFailed ? "failed" : "retry");
            command.Parameters.AddWithValue("$attemptCount", attemptCount);
            command.Parameters.AddWithValue("$nextAttempt", isFailed
                ? DBNull.Value
                : FormatTimestamp(attemptedAtUtc.AddSeconds(delaySeconds)));
            command.Parameters.AddWithValue("$now", FormatTimestamp(attemptedAtUtc));
            command.Parameters.AddWithValue("$failureType", BoundFailureType(failureType));
            command.ExecuteNonQuery();
            transaction.Commit();
        }
    }

    public NotificationIncident? Acknowledge(string id, DateTimeOffset acknowledgedAtUtc, string acknowledgedBy)
    {
        lock (_writeSync)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                UPDATE notification_incidents
                SET status = 'acknowledged', acknowledged_utc = $now, acknowledged_by = $actor, next_attempt_utc = NULL
                WHERE notification_id = $id AND status <> 'acknowledged';
                """;
            command.Parameters.AddWithValue("$id", id);
            command.Parameters.AddWithValue("$now", FormatTimestamp(acknowledgedAtUtc));
            command.Parameters.AddWithValue("$actor", string.IsNullOrWhiteSpace(acknowledgedBy) ? "unknown" : acknowledgedBy);
            var changed = command.ExecuteNonQuery();
            transaction.Commit();
            return changed == 0 ? null : GetById(id);
        }
    }

    private NotificationIncident? GetById(string id)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT notification_id, client_ip, target_site, summary, risk_score, risk_severity,
                   event_timestamp_utc, first_seen_utc, last_seen_utc, evidence_json, status,
                   attempt_count, next_attempt_utc, delivered_utc, acknowledged_utc, last_failure_type, acknowledged_by
            FROM notification_incidents WHERE notification_id = $id;
            """;
        command.Parameters.AddWithValue("$id", id);
        return ReadIncidents(command).FirstOrDefault();
    }

    private static IReadOnlyList<NotificationIncident> ReadIncidents(SqliteCommand command)
    {
        using var reader = command.ExecuteReader();
        var incidents = new List<NotificationIncident>();
        while (reader.Read())
        {
            incidents.Add(new NotificationIncident(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetInt32(4),
                reader.GetString(5),
                ParseTimestamp(reader.GetString(6)),
                ParseTimestamp(reader.GetString(7)),
                ParseTimestamp(reader.GetString(8)),
                JsonSerializer.Deserialize<List<DetectionEvidence>>(reader.GetString(9), SerializerOptions) ?? [],
                reader.GetString(10),
                reader.GetInt32(11),
                reader.IsDBNull(12) ? null : ParseTimestamp(reader.GetString(12)),
                reader.IsDBNull(13) ? null : ParseTimestamp(reader.GetString(13)),
                reader.IsDBNull(14) ? null : ParseTimestamp(reader.GetString(14)),
                reader.IsDBNull(15) ? null : reader.GetString(15),
                reader.IsDBNull(16) ? null : reader.GetString(16)));
        }

        return incidents;
    }

    private SqliteConnection OpenConnection() => SqliteConnectionFactory.Open(_databasePath, _storageOptions);

    private static void IncrementDroppedCount(SqliteConnection connection, SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "UPDATE notification_queue_state SET dropped_count = dropped_count + 1 WHERE singleton_id = 1;";
        command.ExecuteNonQuery();
    }

    private static string CreateDeduplicationKey(string clientIp, string targetSite)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{clientIp.ToLowerInvariant()}\n{targetSite.ToLowerInvariant()}"));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string CreateSummary(SecurityEvent webEvent)
        => $"{webEvent.RiskSeverity} suspicious IIS activity from {webEvent.ClientIp} at {webEvent.Domain} (risk score {webEvent.RiskScore}).";

    private static string BoundFailureType(string? failureType)
        => string.IsNullOrEmpty(failureType) ? "Unknown" : new string(failureType.Where(char.IsAsciiLetterOrDigit).Take(64).ToArray());

    private static string FormatTimestamp(DateTimeOffset value)
        => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTimestamp(string value)
        => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static string GetDatabasePath(string contentRootPath, string configuredPath)
        => Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(contentRootPath, configuredPath));
}