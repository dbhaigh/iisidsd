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
    private readonly string _databasePath = Path.IsPathRooted(storageOptions.Value.DatabasePath)
        ? storageOptions.Value.DatabasePath
        : Path.GetFullPath(Path.Combine(hostEnvironment.ContentRootPath, storageOptions.Value.DatabasePath));

    public bool IsHealthy()
    {
        try
        {
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = _databasePath,
                Mode = SqliteOpenMode.ReadWrite
            }.ToString());
            connection.Open();

            using var command = connection.CreateCommand();
            command.CommandText = "SELECT 1;";
            return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) == 1;
        }
        catch (SqliteException exception)
        {
            logger.LogError(exception, "SQLite health probe failed for database {DatabasePath}.", _databasePath);
            return false;
        }
    }
}
