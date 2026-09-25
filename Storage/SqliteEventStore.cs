using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Threading.Channels;
using iisidsd.Configuration;
using iisidsd.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class SqliteEventStore(
    IOptions<IisEtwOptions> etwOptions,
    IOptions<StorageOptions> storageOptions,
    IHostEnvironment hostEnvironment) : IEventStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly int _subscriptionBufferSize = etwOptions.Value.SubscriptionBufferSize;
    private readonly int _eventRetentionLimit = Math.Max(1, storageOptions.Value.EventRetentionLimit);
    private readonly string _databasePath = GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath);
    private readonly Lock _sync = new();
    private readonly ConcurrentDictionary<Guid, Channel<SecurityEvent>> _subscribers = [];

    public IReadOnlyList<SecurityEvent> GetRecent(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
    {
        var events = new List<SecurityEvent>();
        limit = Math.Clamp(limit, 1, _eventRetentionLimit);

        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
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
                WHERE ($clientIp IS NULL OR client_ip = $clientIp)
                  AND ($domain IS NULL OR domain = $domain)
                  AND ($suspiciousOnly = 0 OR is_suspicious = 1)
                ORDER BY sequence_id DESC
                LIMIT $limit;
                """;
            command.Parameters.AddWithValue("$clientIp", (object?)clientIp ?? DBNull.Value);
            command.Parameters.AddWithValue("$domain", (object?)domain ?? DBNull.Value);
            command.Parameters.AddWithValue("$suspiciousOnly", suspiciousOnly ? 1 : 0);
            command.Parameters.AddWithValue("$limit", limit);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                events.Add(ReadEvent(reader));
            }
        }

        return events;
    }

    public void Publish(SecurityEvent webEvent)
    {
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            using var insertCommand = connection.CreateCommand();
            insertCommand.Transaction = transaction;
            insertCommand.CommandText = """
                INSERT INTO events (
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
                    $riskIndicators);
                """;
            insertCommand.Parameters.AddWithValue("$eventId", webEvent.Id);
            insertCommand.Parameters.AddWithValue("$timestamp", webEvent.Timestamp.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            insertCommand.Parameters.AddWithValue("$server", webEvent.Server);
            insertCommand.Parameters.AddWithValue("$domain", webEvent.Domain);
            insertCommand.Parameters.AddWithValue("$method", webEvent.Method);
            insertCommand.Parameters.AddWithValue("$path", webEvent.Path);
            insertCommand.Parameters.AddWithValue("$clientIp", webEvent.ClientIp);
            insertCommand.Parameters.AddWithValue("$statusCode", webEvent.StatusCode);
            insertCommand.Parameters.AddWithValue("$userAgent", webEvent.UserAgent);
            insertCommand.Parameters.AddWithValue("$properties", JsonSerializer.Serialize(webEvent.Properties, SerializerOptions));
            insertCommand.Parameters.AddWithValue("$isSuspicious", webEvent.IsSuspicious ? 1 : 0);
            insertCommand.Parameters.AddWithValue("$detectionReason", (object?)webEvent.DetectionReason ?? DBNull.Value);
            insertCommand.Parameters.AddWithValue("$riskScore", webEvent.RiskScore);
            insertCommand.Parameters.AddWithValue("$riskSeverity", webEvent.RiskSeverity);
            insertCommand.Parameters.AddWithValue("$riskIndicators", JsonSerializer.Serialize(webEvent.RiskIndicators ?? [], SerializerOptions));
            insertCommand.ExecuteNonQuery();

            using var pruneCommand = connection.CreateCommand();
            pruneCommand.Transaction = transaction;
            pruneCommand.CommandText = """
                DELETE FROM events
                WHERE sequence_id <= COALESCE(
                    (
                        SELECT sequence_id
                        FROM events
                        ORDER BY sequence_id DESC
                        LIMIT 1 OFFSET $retentionLimit
                    ),
                    -1);
                """;
            pruneCommand.Parameters.AddWithValue("$retentionLimit", _eventRetentionLimit);
            pruneCommand.ExecuteNonQuery();
            transaction.Commit();
        }

        foreach (var subscriber in _subscribers.Values)
        {
            subscriber.Writer.TryWrite(webEvent);
        }
    }

    public ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken)
    {
        var channel = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(_subscriptionBufferSize)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false
        });
        var id = Guid.NewGuid();
        _subscribers[id] = channel;
        cancellationToken.Register(() =>
        {
            if (_subscribers.TryRemove(id, out var removed))
            {
                removed.Writer.TryComplete();
            }
        });
        return channel.Reader;
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

    private static SecurityEvent ReadEvent(SqliteDataReader reader)
    {
        var properties = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(9), SerializerOptions) ?? [];
        var riskIndicators = JsonSerializer.Deserialize<List<string>>(reader.GetString(14), SerializerOptions) ?? [];
        return new SecurityEvent(
            DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetString(5),
            reader.GetString(6),
            reader.GetInt32(7),
            reader.GetString(8),
            properties,
            reader.GetInt32(10) != 0,
            reader.IsDBNull(11) ? null : reader.GetString(11),
            reader.GetInt32(12),
            reader.GetString(13),
            riskIndicators)
        {
            Id = reader.GetString(0)
        };
    }

    private static string GetDatabasePath(string contentRootPath, string configuredPath)
        => Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(contentRootPath, configuredPath));
}
