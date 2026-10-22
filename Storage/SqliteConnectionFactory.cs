using iisidsd.Configuration;
using Microsoft.Data.Sqlite;

namespace iisidsd.Storage;

internal static class SqliteConnectionFactory
{
    public static SqliteConnection Open(
        string databasePath,
        StorageOptions options,
        SqliteOpenMode mode = SqliteOpenMode.ReadWriteCreate)
    {
        var busyTimeoutSeconds = GetBusyTimeoutSeconds(options);
        var synchronousMode = GetSynchronousMode(options);
        if (mode == SqliteOpenMode.ReadWriteCreate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
        }

        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = mode,
            DefaultTimeout = busyTimeoutSeconds
        }.ToString());

        try
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = $"""
                PRAGMA busy_timeout = {busyTimeoutSeconds * 1000};
                PRAGMA foreign_keys = ON;
                PRAGMA synchronous = {synchronousMode};
                """;
            command.ExecuteNonQuery();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    public static void ConfigureJournalMode(SqliteConnection connection, StorageOptions options)
    {
        var journalMode = GetJournalMode(options);
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA journal_mode = {journalMode};";
        var actualMode = Convert.ToString(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
        if (!string.Equals(actualMode, journalMode, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"SQLite journal mode '{journalMode}' was requested but '{actualMode}' is active.");
        }
    }

    private static string GetJournalMode(StorageOptions options)
        => options.JournalMode.ToUpperInvariant() switch
        {
            "WAL" => "WAL",
            "DELETE" => "DELETE",
            _ => throw new InvalidOperationException("SQLite journal mode must be WAL or DELETE.")
        };

    private static string GetSynchronousMode(StorageOptions options)
        => options.SynchronousMode.ToUpperInvariant() switch
        {
            "FULL" => "FULL",
            "EXTRA" => "EXTRA",
            "NORMAL" => "NORMAL",
            _ => throw new InvalidOperationException("SQLite synchronous mode must be FULL, EXTRA, or NORMAL.")
        };

    private static int GetBusyTimeoutSeconds(StorageOptions options)
        => options.BusyTimeoutSeconds is >= 1 and <= 120
            ? options.BusyTimeoutSeconds
            : throw new InvalidOperationException("SQLite busy timeout must be between 1 and 120 seconds.");
}