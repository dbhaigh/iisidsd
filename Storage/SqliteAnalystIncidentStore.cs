using System.Globalization;
using iisidsd.Configuration;
using iisidsd.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class SqliteAnalystIncidentStore(
    IOptions<StorageOptions> storageOptions,
    IHostEnvironment hostEnvironment) : IAnalystIncidentStore
{
    private const int MaximumListLimit = 500;
    private const int MaximumStoredIncidents = 5000;
    private readonly string _databasePath = GetDatabasePath(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath);

    public IReadOnlyList<AnalystIncidentRecord> List(int limit = MaximumListLimit)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT client_ip, status, note, updated_utc, updated_by
            FROM analyst_incidents
            ORDER BY updated_utc DESC, client_ip COLLATE NOCASE
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, MaximumListLimit));
        using var reader = command.ExecuteReader();
        var records = new List<AnalystIncidentRecord>();
        while (reader.Read())
        {
            records.Add(ReadRecord(reader));
        }

        return records;
    }

    public AnalystIncidentRecord? Get(string clientIp)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT client_ip, status, note, updated_utc, updated_by
            FROM analyst_incidents
            WHERE client_ip = $clientIp;
            """;
        command.Parameters.AddWithValue("$clientIp", clientIp);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadRecord(reader) : null;
    }

    public AnalystIncidentRecord Save(string clientIp, string status, string note, string updatedBy)
    {
        var updatedAt = DateTimeOffset.UtcNow;
        using var connection = OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO analyst_incidents (client_ip, status, note, updated_utc, updated_by)
            VALUES ($clientIp, $status, $note, $updatedUtc, $updatedBy)
            ON CONFLICT(client_ip) DO UPDATE SET
                status = excluded.status,
                note = excluded.note,
                updated_utc = excluded.updated_utc,
                updated_by = excluded.updated_by;
            """;
        command.Parameters.AddWithValue("$clientIp", clientIp);
        command.Parameters.AddWithValue("$status", status);
        command.Parameters.AddWithValue("$note", note);
        command.Parameters.AddWithValue("$updatedUtc", updatedAt.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$updatedBy", updatedBy);
        command.ExecuteNonQuery();

        using var pruneCommand = connection.CreateCommand();
        pruneCommand.Transaction = transaction;
        pruneCommand.CommandText = """
            DELETE FROM analyst_incidents
            WHERE client_ip IN (
                SELECT client_ip
                FROM analyst_incidents
                ORDER BY updated_utc DESC, client_ip COLLATE NOCASE ASC
                LIMIT -1 OFFSET $retentionLimit
            );
            """;
        pruneCommand.Parameters.AddWithValue("$retentionLimit", MaximumStoredIncidents);
        pruneCommand.ExecuteNonQuery();
        transaction.Commit();
        return new AnalystIncidentRecord(clientIp, status, note, updatedAt, updatedBy);
    }

    private SqliteConnection OpenConnection() => SqliteConnectionFactory.Open(_databasePath, storageOptions.Value);

    private static AnalystIncidentRecord ReadRecord(SqliteDataReader reader)
        => new(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            DateTimeOffset.Parse(reader.GetString(3), CultureInfo.InvariantCulture),
            reader.GetString(4));

    private static string GetDatabasePath(string contentRootPath, string configuredPath)
        => Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(contentRootPath, configuredPath));
}