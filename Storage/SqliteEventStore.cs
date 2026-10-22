using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Threading.Channels;
using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Observability;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class SqliteEventStore(
    IOptions<IisEtwOptions> etwOptions,
    IOptions<StorageOptions> storageOptions,
    IHostEnvironment hostEnvironment,
    IFindingStore findingStore,
    IisObservability observability,
    IOptions<DashboardOptions>? dashboardOptions = null) : IEventStore, IEventRetentionStore, IReplayableEventStore
{
    private const int RetentionDeleteBatchSize = 1_000;
    private const int MaximumQueryLimit = 10_000;
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly int _subscriptionBufferSize = Math.Clamp(etwOptions.Value.SubscriptionBufferSize, 1, 4_096);
    private readonly int _maximumStreamSubscribers = Math.Clamp(dashboardOptions?.Value.MaximumEventStreamSubscribers ?? 64, 1, 256);
    private readonly int _eventRetentionLimit = Math.Max(1, storageOptions.Value.EventRetentionLimit);
    private readonly int _eventRetentionDays = storageOptions.Value.EventRetentionDays;
    private readonly string _databasePath = GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath);
    private readonly Lock _writeSync = SqliteDatabaseLock.For(
        GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath));
    private readonly ConcurrentDictionary<Guid, Channel<SecurityEvent>> _subscribers = [];
    private readonly object _subscriberSync = new();

    public IReadOnlyList<SecurityEvent> GetRecent(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
    {
        var events = new List<SecurityEvent>();
        limit = Math.Clamp(limit, 1, Math.Min(_eventRetentionLimit, MaximumQueryLimit));
        var predicates = new List<string>(3);
        if (clientIp is not null)
        {
            predicates.Add("client_ip = $clientIp");
        }

        if (domain is not null)
        {
            predicates.Add("domain = $domain");
        }

        if (suspiciousOnly)
        {
            predicates.Add("is_suspicious = 1");
        }

        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
                SELECT
                    event_id,
                    timestamp_utc,
                    server,
                    domain,
                    method,
                    path,
                    client_ip,
                    status_code,
                    user_agent,
                    properties_json,
                    is_suspicious,
                    detection_reason,
                    risk_score,
                    risk_severity,
                    risk_indicators_json
                FROM events
                {(predicates.Count == 0 ? "" : "WHERE " + string.Join(" AND ", predicates))}
                ORDER BY sequence_id DESC
                LIMIT $limit;
            """;
        if (clientIp is not null)
        {
            command.Parameters.AddWithValue("$clientIp", clientIp);
        }

        if (domain is not null)
        {
            command.Parameters.AddWithValue("$domain", domain);
        }

        command.Parameters.AddWithValue("$limit", limit);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            events.Add(ReadEvent(reader));
        }

        return events;
    }

    public EventPage<StoredSecurityEvent> GetLatestPage(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
    {
        limit = Math.Clamp(limit, 1, MaximumQueryLimit);
        var (oldestCursor, latestCursor, prunedThroughCursor) = GetCursorBounds();
        var predicates = BuildEventPredicates(clientIp, domain, suspiciousOnly);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        AddEventFilterParameters(command, clientIp, domain, suspiciousOnly);
        command.Parameters.AddWithValue("$limit", limit + 1);
        command.CommandText = $"""
            SELECT sequence_id, event_id, timestamp_utc, server, domain, method, path, client_ip, status_code,
                   user_agent, properties_json, is_suspicious, detection_reason, risk_score, risk_severity, risk_indicators_json
            FROM events
            {(predicates.Count == 0 ? "" : "WHERE " + string.Join(" AND ", predicates))}
            ORDER BY sequence_id DESC
            LIMIT $limit;
            """;
        var records = ReadStoredEvents(command);
        var hasMore = records.Count > limit;
        if (hasMore) records.RemoveAt(records.Count - 1);
        records.Reverse();
        return new EventPage<StoredSecurityEvent>(
            records,
            records.Count == 0 ? null : records[0].SequenceId,
            records.Count == 0 ? null : records[^1].SequenceId,
            latestCursor,
            hasMore,
            false,
            oldestCursor,
            prunedThroughCursor);
    }

    public EventPage<StoredSecurityEvent> GetPageAfter(
        long afterSequence,
        int limit,
        string? clientIp = null,
        string? domain = null,
        bool suspiciousOnly = false)
    {
        limit = Math.Clamp(limit, 1, MaximumQueryLimit);
        var (oldestCursor, latestCursor, prunedThroughCursor) = GetCursorBounds();
        var predicates = BuildEventPredicates(clientIp, domain, suspiciousOnly);
        predicates.Insert(0, "sequence_id > $afterSequence");
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.Parameters.AddWithValue("$afterSequence", afterSequence);
        AddEventFilterParameters(command, clientIp, domain, suspiciousOnly);
        command.Parameters.AddWithValue("$limit", limit + 1);
        command.CommandText = $"""
            SELECT sequence_id, event_id, timestamp_utc, server, domain, method, path, client_ip, status_code,
                   user_agent, properties_json, is_suspicious, detection_reason, risk_score, risk_severity, risk_indicators_json
            FROM events
            WHERE {string.Join(" AND ", predicates)}
            ORDER BY sequence_id ASC
            LIMIT $limit;
            """;
        var records = ReadStoredEvents(command);
        var hasMore = records.Count > limit;
        if (hasMore) records.RemoveAt(records.Count - 1);
        return new EventPage<StoredSecurityEvent>(
            records,
            records.Count == 0 ? null : records[0].SequenceId,
            records.Count == 0 ? null : records[^1].SequenceId,
            latestCursor,
            hasMore,
            afterSequence < prunedThroughCursor,
            oldestCursor,
            prunedThroughCursor);
    }

    public EventPage<StoredSecurityEvent> GetPageBefore(
        long beforeSequence,
        int limit,
        string? clientIp = null,
        string? domain = null,
        bool suspiciousOnly = false)
    {
        limit = Math.Clamp(limit, 1, MaximumQueryLimit);
        var (oldestCursor, latestCursor, prunedThroughCursor) = GetCursorBounds();
        var predicates = BuildEventPredicates(clientIp, domain, suspiciousOnly);
        predicates.Insert(0, "sequence_id < $beforeSequence");
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.Parameters.AddWithValue("$beforeSequence", beforeSequence);
        AddEventFilterParameters(command, clientIp, domain, suspiciousOnly);
        command.Parameters.AddWithValue("$limit", limit + 1);
        command.CommandText = $"""
            SELECT sequence_id, event_id, timestamp_utc, server, domain, method, path, client_ip, status_code,
                   user_agent, properties_json, is_suspicious, detection_reason, risk_score, risk_severity, risk_indicators_json
            FROM events
            WHERE {string.Join(" AND ", predicates)}
            ORDER BY sequence_id DESC
            LIMIT $limit;
            """;
        var records = ReadStoredEvents(command);
        var hasMore = records.Count > limit;
        if (hasMore) records.RemoveAt(records.Count - 1);
        records.Reverse();
        return new EventPage<StoredSecurityEvent>(
            records,
            records.Count == 0 ? null : records[0].SequenceId,
            records.Count == 0 ? null : records[^1].SequenceId,
            latestCursor,
            hasMore,
            false,
            oldestCursor,
            prunedThroughCursor);
    }

    public void Publish(SecurityEvent webEvent)
        => PublishBatch([webEvent]);

    public IReadOnlyList<SecurityEvent> PublishBatch(IReadOnlyList<SecurityEvent> webEvents)
    {
        ArgumentNullException.ThrowIfNull(webEvents);
        if (webEvents.Count == 0)
        {
            return [];
        }

        var newlyPersistedEvents = new List<SecurityEvent>(webEvents.Count);
        var started = Stopwatch.GetTimestamp();
        try
        {
            lock (_writeSync)
            {
                using var connection = OpenConnection();
                using var transaction = connection.BeginTransaction();
                using var insertCommand = connection.CreateCommand();
                insertCommand.Transaction = transaction;
                insertCommand.CommandText = """
                        INSERT OR IGNORE INTO events (
                            event_id,
                            timestamp_utc,
                            server,
                            domain,
                            method,
                            path,
                            client_ip,
                            status_code,
                            user_agent,
                            properties_json,
                            is_suspicious,
                            detection_reason,
                            risk_score,
                            risk_severity,
                            risk_indicators_json)
                        VALUES (
                            $eventId,
                            $timestamp,
                            $server,
                            $domain,
                            $method,
                            $path,
                            $clientIp,
                            $statusCode,
                            $userAgent,
                            $properties,
                            $isSuspicious,
                            $detectionReason,
                            $riskScore,
                            $riskSeverity,
                            $riskIndicators)
                        RETURNING sequence_id;
                    """;
                foreach (var webEvent in webEvents)
                {
                    SetEventParameters(insertCommand, webEvent);
                    if (insertCommand.ExecuteScalar() is not long sequenceId)
                    {
                        continue;
                    }

                    newlyPersistedEvents.Add(webEvent with { SequenceId = sequenceId });
                }

                findingStore.UpsertBatch(newlyPersistedEvents, connection, transaction);

                if (newlyPersistedEvents.Count > 0)
                {
                        var cutoff = DateTimeOffset.UtcNow.AddDays(-_eventRetentionDays).UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
                        using (var agePruneCommand = connection.CreateCommand())
                        {
                            agePruneCommand.Transaction = transaction;
                            agePruneCommand.CommandText = """
                                DELETE FROM events
                                WHERE sequence_id IN (
                                    SELECT sequence_id
                                    FROM events
                                    WHERE timestamp_utc < $cutoff
                                    ORDER BY timestamp_utc
                                    LIMIT $limit);
                                """;
                            agePruneCommand.Parameters.AddWithValue("$cutoff", cutoff);
                            agePruneCommand.Parameters.AddWithValue("$limit", RetentionDeleteBatchSize);
                            agePruneCommand.ExecuteNonQuery();
                        }

                        using var rowCountCommand = connection.CreateCommand();
                        rowCountCommand.Transaction = transaction;
                        rowCountCommand.CommandText = "SELECT retained_event_count FROM event_retention_state WHERE singleton_id = 1;";
                        var retainedEventCount = Convert.ToInt64(rowCountCommand.ExecuteScalar(), CultureInfo.InvariantCulture);
                        if (retainedEventCount > _eventRetentionLimit)
                        {
                            using var countPruneCommand = connection.CreateCommand();
                            countPruneCommand.Transaction = transaction;
                            countPruneCommand.CommandText = """
                                DELETE FROM events
                                WHERE sequence_id IN (
                                    SELECT sequence_id
                                    FROM events
                                    ORDER BY sequence_id
                                    LIMIT $excess);
                                """;
                            countPruneCommand.Parameters.AddWithValue("$excess", retainedEventCount - _eventRetentionLimit);
                            countPruneCommand.ExecuteNonQuery();
                        }
                }

                transaction.Commit();

                foreach (var webEvent in newlyPersistedEvents)
                {
                    foreach (var subscriber in _subscribers)
                    {
                        if (!subscriber.Value.Writer.TryWrite(webEvent))
                        {
                            RemoveSubscriber(subscriber.Key, new EventStreamSlowConsumerException());
                        }
                    }
                }
            }
        }
        catch (SqliteException exception)
        {
            observability.RecordSqliteFailure(exception.SqliteErrorCode);
            throw;
        }
        finally
        {
            observability.RecordSqliteWrite(Stopwatch.GetElapsedTime(started));
        }

        return newlyPersistedEvents;
    }

    public IngestionDiagnosticsSnapshot GetIngestionDiagnostics()
    {
        var sidecarSnapshot = ReadSidecarDiagnostics();
        try
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT events_received, events_accepted, events_dropped, events_malformed,
                       events_processed, processing_failures, auto_deny_failures, processing_retries
                FROM etw_ingestion_diagnostics
                WHERE singleton_id = 1;
                """;
            using var reader = command.ExecuteReader();
            if (reader.Read())
            {
                var databaseSnapshot = new IngestionDiagnosticsSnapshot(
                    reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3),
                    reader.GetInt64(4), reader.GetInt64(5), reader.GetInt64(6), reader.GetInt64(7));
                return Max(databaseSnapshot, sidecarSnapshot);
            }
        }
        catch (SqliteException)
        {
        }

        return sidecarSnapshot;
    }

    public void SaveIngestionDiagnostics(IngestionDiagnosticsSnapshot snapshot)
    {
        SaveIngestionDiagnosticsSidecar(snapshot);
        try
        {
            lock (_writeSync)
            {
                using var connection = OpenConnection();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    INSERT INTO etw_ingestion_diagnostics (
                        singleton_id, events_received, events_accepted, events_dropped, events_malformed,
                        events_processed, processing_failures, auto_deny_failures, processing_retries, updated_utc)
                    VALUES (1, $received, $accepted, $dropped, $malformed, $processed, $failures, $autoDenyFailures, $retries, $updatedUtc)
                    ON CONFLICT(singleton_id) DO UPDATE SET
                        events_received = MAX(events_received, excluded.events_received),
                        events_accepted = MAX(events_accepted, excluded.events_accepted),
                        events_dropped = MAX(events_dropped, excluded.events_dropped),
                        events_malformed = MAX(events_malformed, excluded.events_malformed),
                        events_processed = MAX(events_processed, excluded.events_processed),
                        processing_failures = MAX(processing_failures, excluded.processing_failures),
                        auto_deny_failures = MAX(auto_deny_failures, excluded.auto_deny_failures),
                        processing_retries = MAX(processing_retries, excluded.processing_retries),
                        updated_utc = excluded.updated_utc;
                    """;
                command.Parameters.AddWithValue("$received", snapshot.EventsReceived);
                command.Parameters.AddWithValue("$accepted", snapshot.EventsAccepted);
                command.Parameters.AddWithValue("$dropped", snapshot.EventsDropped);
                command.Parameters.AddWithValue("$malformed", snapshot.EventsMalformed);
                command.Parameters.AddWithValue("$processed", snapshot.EventsProcessed);
                command.Parameters.AddWithValue("$failures", snapshot.ProcessingFailures);
                command.Parameters.AddWithValue("$autoDenyFailures", snapshot.AutoDenyFailures);
                command.Parameters.AddWithValue("$retries", snapshot.ProcessingRetries);
                command.Parameters.AddWithValue("$updatedUtc", DateTimeOffset.UtcNow.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
                command.ExecuteNonQuery();
            }
        }
        catch (SqliteException exception)
        {
            observability.RecordSqliteFailure(exception.SqliteErrorCode);
            throw;
        }
    }

    public void SaveIngestionDiagnosticsSidecar(IngestionDiagnosticsSnapshot snapshot)
    {
        try
        {
            WriteSidecarDiagnostics(snapshot);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private IngestionDiagnosticsSnapshot ReadSidecarDiagnostics()
    {
        var path = _databasePath + ".etw-diagnostics.json";
        try
        {
            using var stream = File.OpenRead(path);
            return JsonSerializer.Deserialize<IngestionDiagnosticsSnapshot>(stream, SerializerOptions)
                ?? new IngestionDiagnosticsSnapshot(0, 0, 0, 0, 0, 0, 0, 0);
        }
        catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
        {
            return new IngestionDiagnosticsSnapshot(0, 0, 0, 0, 0, 0, 0, 0);
        }
    }

    private void WriteSidecarDiagnostics(IngestionDiagnosticsSnapshot snapshot)
    {
        var path = _databasePath + ".etw-diagnostics.json";
        var tempPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(stream, snapshot, SerializerOptions);
                stream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    private static IngestionDiagnosticsSnapshot Max(
        IngestionDiagnosticsSnapshot left,
        IngestionDiagnosticsSnapshot right)
        => new(
            Math.Max(left.EventsReceived, right.EventsReceived),
            Math.Max(left.EventsAccepted, right.EventsAccepted),
            Math.Max(left.EventsDropped, right.EventsDropped),
            Math.Max(left.EventsMalformed, right.EventsMalformed),
            Math.Max(left.EventsProcessed, right.EventsProcessed),
            Math.Max(left.ProcessingFailures, right.ProcessingFailures),
            Math.Max(left.AutoDenyFailures, right.AutoDenyFailures),
            Math.Max(left.ProcessingRetries, right.ProcessingRetries));

    private static void SetEventParameters(SqliteCommand command, SecurityEvent webEvent)
    {
        command.Parameters.Clear();
        command.Parameters.AddWithValue("$eventId", webEvent.Id);
        command.Parameters.AddWithValue("$timestamp", webEvent.Timestamp.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$server", webEvent.Server);
        command.Parameters.AddWithValue("$domain", webEvent.Domain);
        command.Parameters.AddWithValue("$method", webEvent.Method);
        command.Parameters.AddWithValue("$path", webEvent.Path);
        command.Parameters.AddWithValue("$clientIp", webEvent.ClientIp);
        command.Parameters.AddWithValue("$statusCode", webEvent.StatusCode);
        command.Parameters.AddWithValue("$userAgent", webEvent.UserAgent);
        command.Parameters.AddWithValue("$properties", JsonSerializer.Serialize(webEvent.Properties, SerializerOptions));
        command.Parameters.AddWithValue("$isSuspicious", webEvent.IsSuspicious ? 1 : 0);
        command.Parameters.AddWithValue("$detectionReason", (object?)webEvent.DetectionReason ?? DBNull.Value);
        command.Parameters.AddWithValue("$riskScore", webEvent.RiskScore);
        command.Parameters.AddWithValue("$riskSeverity", webEvent.RiskSeverity);
        command.Parameters.AddWithValue("$riskIndicators", JsonSerializer.Serialize(webEvent.RiskIndicators ?? [], SerializerOptions));
    }

    public int PruneExpiredEvents(DateTimeOffset olderThan)
    {
        var cutoff = olderThan.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        var started = Stopwatch.GetTimestamp();
        var totalPruned = 0;
        try
        {
            while (true)
            {
                int pruned;
                lock (_writeSync)
                {
                        using var connection = OpenConnection();
                        using var transaction = connection.BeginTransaction();
                        using var command = connection.CreateCommand();
                        command.Transaction = transaction;
                        command.CommandText = """
                            DELETE FROM events
                            WHERE sequence_id IN (
                                SELECT sequence_id
                                FROM events
                                WHERE timestamp_utc < $cutoff
                                ORDER BY timestamp_utc
                                LIMIT $limit);
                            """;
                        command.Parameters.AddWithValue("$cutoff", cutoff);
                        command.Parameters.AddWithValue("$limit", RetentionDeleteBatchSize);
                        pruned = command.ExecuteNonQuery();
                        transaction.Commit();
                }

                totalPruned += pruned;
                if (pruned < RetentionDeleteBatchSize)
                {
                    return totalPruned;
                }
            }
        }
        catch (SqliteException exception)
        {
            observability.RecordSqliteFailure(exception.SqliteErrorCode);
            throw;
        }
        finally
        {
            observability.RecordSqliteWrite(Stopwatch.GetElapsedTime(started));
        }
    }

    public ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken)
        => SubscribeWithCursor(cancellationToken).Reader;

    public EventStreamSubscription SubscribeWithCursor(CancellationToken cancellationToken)
    {
        lock (_writeSync)
        {
            var reader = SubscribeCore(cancellationToken);
            var (_, latestCursor, _) = GetCursorBounds();
            return new EventStreamSubscription(reader, latestCursor);
        }
    }

    private ChannelReader<SecurityEvent> SubscribeCore(CancellationToken cancellationToken)
    {
        var channel = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(_subscriptionBufferSize)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
        var id = Guid.NewGuid();
        lock (_subscriberSync)
        {
            if (_subscribers.Count >= _maximumStreamSubscribers)
            {
                throw new EventStreamSubscriberLimitException();
            }

            _subscribers[id] = channel;
        }

        cancellationToken.Register(() => RemoveSubscriber(id));
        return channel.Reader;
    }

    private void RemoveSubscriber(Guid id, Exception? completionError = null)
    {
        lock (_subscriberSync)
        {
            if (_subscribers.TryRemove(id, out var channel))
            {
                channel.Writer.TryComplete(completionError);
            }
        }
    }

    private (long? Oldest, long Latest, long PrunedThrough) GetCursorBounds()
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT MIN(sequence_id) FROM events),
                   MAX(COALESCE((SELECT MAX(sequence_id) FROM events), 0),
                       COALESCE((SELECT pruned_through_sequence FROM event_retention_state WHERE singleton_id = 1), 0)),
                   (SELECT pruned_through_sequence FROM event_retention_state WHERE singleton_id = 1);
            """;
        using var reader = command.ExecuteReader();
        reader.Read();
        long? oldest = reader.IsDBNull(0) ? null : reader.GetInt64(0);
        var latest = reader.IsDBNull(1) ? 0 : reader.GetInt64(1);
        var prunedThrough = reader.IsDBNull(2) ? 0 : reader.GetInt64(2);
        return (oldest, latest, prunedThrough);
    }

    private static List<string> BuildEventPredicates(string? clientIp, string? domain, bool suspiciousOnly)
    {
        var predicates = new List<string>(3);
        if (clientIp is not null) predicates.Add("client_ip = $clientIp");
        if (domain is not null) predicates.Add("domain = $domain");
        if (suspiciousOnly) predicates.Add("is_suspicious = 1");
        return predicates;
    }

    private static void AddEventFilterParameters(SqliteCommand command, string? clientIp, string? domain, bool suspiciousOnly)
    {
        if (clientIp is not null) command.Parameters.AddWithValue("$clientIp", clientIp);
        if (domain is not null) command.Parameters.AddWithValue("$domain", domain);
        if (suspiciousOnly) command.Parameters.AddWithValue("$suspiciousOnly", 1);
    }

    private static List<StoredSecurityEvent> ReadStoredEvents(SqliteCommand command)
    {
        using var reader = command.ExecuteReader();
        var events = new List<StoredSecurityEvent>();
        while (reader.Read())
        {
            var webEvent = ReadEvent(reader, sequenceIdColumnOffset: 1);
            var sequenceId = reader.GetInt64(0);
            events.Add(new StoredSecurityEvent(
                sequenceId,
                webEvent.Id,
                webEvent.Timestamp,
                webEvent.Server,
                webEvent.Domain,
                webEvent.Method,
                webEvent.Path,
                webEvent.ClientIp,
                webEvent.StatusCode,
                webEvent.UserAgent,
                webEvent.Properties,
                webEvent.IsSuspicious,
                webEvent.DetectionReason,
                webEvent.RiskScore,
                webEvent.RiskSeverity,
                webEvent.RiskIndicators ?? []));
        }

        return events;
    }

    private SqliteConnection OpenConnection()
        => SqliteConnectionFactory.Open(_databasePath, storageOptions.Value);

    internal static SecurityEvent ReadEvent(SqliteDataReader reader, int sequenceIdColumnOffset = 0)
    {
        var properties = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(9 + sequenceIdColumnOffset), SerializerOptions) ?? [];
        var riskIndicators = JsonSerializer.Deserialize<List<string>>(reader.GetString(14 + sequenceIdColumnOffset), SerializerOptions) ?? [];
        return new SecurityEvent(
            DateTimeOffset.Parse(reader.GetString(1 + sequenceIdColumnOffset), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            reader.GetString(2 + sequenceIdColumnOffset),
            reader.GetString(3 + sequenceIdColumnOffset),
            reader.GetString(4 + sequenceIdColumnOffset),
            reader.GetString(5 + sequenceIdColumnOffset),
            reader.GetString(6 + sequenceIdColumnOffset),
            reader.GetInt32(7 + sequenceIdColumnOffset),
            reader.GetString(8 + sequenceIdColumnOffset),
            properties,
            reader.GetInt32(10 + sequenceIdColumnOffset) != 0,
            reader.IsDBNull(11 + sequenceIdColumnOffset) ? null : reader.GetString(11 + sequenceIdColumnOffset),
            reader.GetInt32(12 + sequenceIdColumnOffset),
            reader.GetString(13 + sequenceIdColumnOffset),
            riskIndicators)
        {
            Id = reader.GetString(sequenceIdColumnOffset)
        };
    }

    private static string GetDatabasePath(string contentRootPath, string configuredPath)
        => Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(contentRootPath, configuredPath));
}
