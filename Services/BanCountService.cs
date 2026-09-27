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

    public IReadOnlyList<BanCountRecord> GetBanCounts(int limit, string? domain = null)
    {
        limit = Math.Max(1, limit);
        var normalizedDomain = NormalizeDomainKey(domain);
        var results = new List<BanCountRecord>();

        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = string.IsNullOrEmpty(normalizedDomain)
                ? """
                    SELECT client_ip, SUM(ban_count) AS ban_count, MAX(last_updated_utc) AS last_updated_utc
                    FROM ban_counts
                    GROUP BY client_ip
                    ORDER BY ban_count DESC, last_updated_utc DESC
                    LIMIT $limit;
                    """
                : """
                    SELECT client_ip, SUM(ban_count) AS ban_count, MAX(last_updated_utc) AS last_updated_utc
                    FROM ban_counts
                    WHERE domain = $domain
                    GROUP BY client_ip
                    ORDER BY ban_count DESC, last_updated_utc DESC
                    LIMIT $limit;
                    """;
            command.Parameters.AddWithValue("$limit", limit);
            if (!string.IsNullOrEmpty(normalizedDomain))
            {
                command.Parameters.AddWithValue("$domain", normalizedDomain);
            }

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                results.Add(ReadRecord(reader));
            }
        }

        return results;
    }

    public IReadOnlyDictionary<string, BanCountRecord> GetBanCounts(IEnumerable<string> clientIps, string? domain = null)
    {
        var ips = clientIps
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (ips.Length == 0)
        {
            return new Dictionary<string, BanCountRecord>(StringComparer.OrdinalIgnoreCase);
        }

        var normalizedDomain = NormalizeDomainKey(domain);
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

            command.CommandText = string.IsNullOrEmpty(normalizedDomain)
                ? $"""
                    SELECT client_ip, SUM(ban_count) AS ban_count, MAX(last_updated_utc) AS last_updated_utc
                    FROM ban_counts
                    WHERE client_ip IN ({string.Join(", ", parameterNames)})
                    GROUP BY client_ip;
                    """
                : $"""
                    SELECT client_ip, SUM(ban_count) AS ban_count, MAX(last_updated_utc) AS last_updated_utc
                    FROM ban_counts
                    WHERE client_ip IN ({string.Join(", ", parameterNames)}) AND domain = $domain
                    GROUP BY client_ip;
                    """;
            if (!string.IsNullOrEmpty(normalizedDomain))
            {
                command.Parameters.AddWithValue("$domain", normalizedDomain);
            }

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var record = ReadRecord(reader);
                results[record.ClientIp] = record;
            }
        }

        return results;
    }

    public BanCountRecord GetBanCount(string clientIp, string? domain = null)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
        {
            throw new ArgumentException("Client IP is required.", nameof(clientIp));
        }

        var normalizedDomain = NormalizeDomainKey(domain);
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = string.IsNullOrEmpty(normalizedDomain)
                ? """
                    SELECT client_ip, SUM(ban_count) AS ban_count, MAX(last_updated_utc) AS last_updated_utc
                    FROM ban_counts
                    WHERE client_ip = $clientIp
                    GROUP BY client_ip;
                    """
                : """
                    SELECT client_ip, SUM(ban_count) AS ban_count, MAX(last_updated_utc) AS last_updated_utc
                    FROM ban_counts
                    WHERE client_ip = $clientIp AND domain = $domain
                    GROUP BY client_ip;
                    """;
            command.Parameters.AddWithValue("$clientIp", clientIp);
            if (!string.IsNullOrEmpty(normalizedDomain))
            {
                command.Parameters.AddWithValue("$domain", normalizedDomain);
            }

            using var reader = command.ExecuteReader();
            return reader.Read()
                ? ReadRecord(reader)
                : new BanCountRecord(clientIp, 0, DateTimeOffset.UtcNow);
        }
    }

    public BanCountRecord SetBanCount(string clientIp, int banCount, string? domain = null)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
        {
            throw new ArgumentException("Client IP is required.", nameof(clientIp));
        }

        if (banCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(banCount), banCount, "Ban count must be non-negative.");
        }

        var normalizedDomain = NormalizeDomainKey(domain);
        var updated = new BanCountRecord(clientIp, banCount, DateTimeOffset.UtcNow);
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO ban_counts (client_ip, domain, ban_count, last_updated_utc)
                VALUES ($clientIp, $domain, $banCount, $lastUpdatedUtc)
                ON CONFLICT(client_ip, domain) DO UPDATE SET
                    ban_count = excluded.ban_count,
                    last_updated_utc = excluded.last_updated_utc;
                """;
            command.Parameters.AddWithValue("$clientIp", updated.ClientIp);
            command.Parameters.AddWithValue("$domain", normalizedDomain);
            command.Parameters.AddWithValue("$banCount", updated.BanCount);
            command.Parameters.AddWithValue("$lastUpdatedUtc", updated.LastUpdated.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            command.ExecuteNonQuery();
        }

        return updated;
    }

    public void IncrementBanCounts(string clientIp, IEnumerable<string> domains)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
        {
            throw new ArgumentException("Client IP is required.", nameof(clientIp));
        }

        var normalizedDomains = (domains ?? [])
            .Select(NormalizeDomainKey)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (normalizedDomains.Length == 0)
        {
            return;
        }

        var lastUpdatedUtc = DateTimeOffset.UtcNow.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        lock (_sync)
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            foreach (var domain in normalizedDomains)
            {
                using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = """
                    INSERT INTO ban_counts (client_ip, domain, ban_count, last_updated_utc)
                    VALUES ($clientIp, $domain, 1, $lastUpdatedUtc)
                    ON CONFLICT(client_ip, domain) DO UPDATE SET
                        ban_count = ban_count + 1,
                        last_updated_utc = excluded.last_updated_utc;
                    """;
                command.Parameters.AddWithValue("$clientIp", clientIp);
                command.Parameters.AddWithValue("$domain", domain);
                command.Parameters.AddWithValue("$lastUpdatedUtc", lastUpdatedUtc);
                command.ExecuteNonQuery();
            }

            transaction.Commit();
        }
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

    private static string NormalizeDomainKey(string? domain)
        => string.IsNullOrWhiteSpace(domain)
            ? string.Empty
            : domain.Trim().TrimEnd('.').ToLowerInvariant();

    private static string GetDatabasePath(string contentRootPath, string configuredPath)
        => Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(contentRootPath, configuredPath));
}
