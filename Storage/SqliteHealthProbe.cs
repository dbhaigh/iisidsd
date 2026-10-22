using System.Diagnostics;
using System.Globalization;
using iisidsd.Configuration;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class SqliteHealthProbe(
    IOptions<StorageOptions> storageOptions,
    IHostEnvironment hostEnvironment,
    ILogger<SqliteHealthProbe> logger)
{
    private static readonly TimeSpan IntegrityCheckInterval = TimeSpan.FromHours(1);
    private readonly string _databasePath = Path.IsPathRooted(storageOptions.Value.DatabasePath)
        ? storageOptions.Value.DatabasePath
        : Path.GetFullPath(Path.Combine(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath));
    private readonly Lock _integritySync = new();
    private long _lastIntegrityCheckTimestamp;
    private bool _lastIntegrityCheckHealthy = true;

    public bool IsHealthy()
    {
        try
        {
            using var connection = SqliteConnectionFactory.Open(
                _databasePath,
                storageOptions.Value,
                SqliteOpenMode.ReadWrite);

            using var command = connection.CreateCommand();
            command.CommandText = "SELECT 1;";
            if (Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) != 1)
            {
                return false;
            }

            return CheckIntegrityIfDue(connection);
        }
        catch (SqliteException exception)
        {
            logger.LogError(exception, "SQLite health probe failed for database {DatabasePath}.", _databasePath);
            return false;
        }
    }

    private bool CheckIntegrityIfDue(SqliteConnection connection)
    {
        var now = Stopwatch.GetTimestamp();
        var lastCheck = Interlocked.Read(ref _lastIntegrityCheckTimestamp);
        if (lastCheck != 0 && Stopwatch.GetElapsedTime(lastCheck, now) < IntegrityCheckInterval)
        {
            return _lastIntegrityCheckHealthy;
        }

        lock (_integritySync)
        {
            lastCheck = Interlocked.Read(ref _lastIntegrityCheckTimestamp);
            if (lastCheck != 0 && Stopwatch.GetElapsedTime(lastCheck, now) < IntegrityCheckInterval)
            {
                return _lastIntegrityCheckHealthy;
            }

            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA quick_check(1);";
            var result = command.ExecuteScalar() as string;
            _lastIntegrityCheckHealthy = string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase);
            Interlocked.Exchange(ref _lastIntegrityCheckTimestamp, Stopwatch.GetTimestamp());
            if (!_lastIntegrityCheckHealthy)
            {
                logger.LogError("SQLite integrity check failed for database {DatabasePath}. Result={IntegrityResult}", _databasePath, result);
            }

            return _lastIntegrityCheckHealthy;
        }
    }
}
