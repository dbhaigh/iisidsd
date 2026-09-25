using System.Globalization;
using iisidsd.Configuration;
using iisidsd.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace iisidsd.Services;

public sealed class BanCountService(
    IOptions<StorageOptions> storageOptions,
    IHostEnvironment hostEnvironment) : IBanCountService
{
    private readonly string _databasePath = GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath);
    private readonly Lock _sync = new();

    public IReadOnlyList<BanCountRecord> GetBanCounts(int limit)
    {
        limit = Math.Max(1, limit);
        var results = new List<BanCountRecord>();

        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT client_ip, ban_count, last_updated_utc
                FROM ban_counts
                ORDER BY ban_count DESC, last_updated_utc DESC
                LIMIT $limit;
                """;
            command.Parameters.AddWithValue("$limit", limit);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                results.Add(ReadRecord(reader));
            }
        }

        return results;
    }

    public IReadOnlyDictionary<string, BanCountRecord> GetBanCounts(IEnumerable<string> clientIps)
    {
        var ips = clientIps
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (ips.Length == 0)
        {
            return new Dictionary<string, BanCountRecord>(StringComparer.OrdinalIgnoreCase);
        }

        var results = new Dictionary<string, BanCountRecord>(StringComparer.OrdinalIgnoreCase);
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            var parameterNames = new List<string>(ips.Length);
            for (var index = 0; index < ips.Length; index++)
            {
                var parameterName = $"$ip{index}";
                parameterNames.Add(parameterName);
                command.Parameters.AddWithValue(parameterName, ips[index]);
            }

            command.CommandText = $"""
                SELECT client_ip, ban_count, last_updated_utc
                FROM ban_counts
                WHERE client_ip IN ({string.Join(", ", parameterNames)});
                """;

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var record = ReadRecord(reader);
                results[record.ClientIp] = record;
            }
        }

        return results;
    }

    public BanCountRecord GetBanCount(string clientIp)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
        {
            throw new ArgumentException("Client IP is required.", nameof(clientIp));
        }

        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT client_ip, ban_count, last_updated_utc
                FROM ban_counts
                WHERE client_ip = $clientIp;
                """;
            command.Parameters.AddWithValue("$clientIp", clientIp);

            using var reader = command.ExecuteReader();
            return reader.Read()
                ? ReadRecord(reader)
                : new BanCountRecord(clientIp, 0, DateTimeOffset.UtcNow);
        }
    }

    public BanCountRecord SetBanCount(string clientIp, int banCount)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
        {
            throw new ArgumentException("Client IP is required.", nameof(clientIp));
        }

        if (banCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(banCount), banCount, "Ban count must be non-negative.");
        }

        var updated = new BanCountRecord(clientIp, banCount, DateTimeOffset.UtcNow);
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO ban_counts (client_ip, ban_count, last_updated_utc)
                VALUES ($clientIp, $banCount, $lastUpdatedUtc)
                ON CONFLICT(client_ip) DO UPDATE SET
                    ban_count = excluded.ban_count,
                    last_updated_utc = excluded.last_updated_utc;
                """;
            command.Parameters.AddWithValue("$clientIp", updated.ClientIp);
            command.Parameters.AddWithValue("$banCount", updated.BanCount);
            command.Parameters.AddWithValue("$lastUpdatedUtc", updated.LastUpdated.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            command.ExecuteNonQuery();
        }

        return updated;
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

    private static BanCountRecord ReadRecord(SqliteDataReader reader)
        => new(
            reader.GetString(0),
            reader.GetInt32(1),
            DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind));

    private static string GetDatabasePath(string contentRootPath, string configuredPath)
        => Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(contentRootPath, configuredPath));
}
