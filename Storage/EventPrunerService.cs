using Microsoft.Data.Sqlite;
using iisidsd.Configuration;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class EventPrunerService(
    IEventRetentionStore eventStore,
    IOptions<StorageOptions> storageOptions,
    ILogger<EventPrunerService> logger) : BackgroundService
{
    private readonly int _retentionDays = storageOptions.Value.EventRetentionDays;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(24));
        do
        {
            var prunedCount = await PruneWithRetryAsync(stoppingToken);
            if (prunedCount is > 0)
            {
                logger.LogInformation("Pruned {EventCount} events older than {RetentionDays} days.", prunedCount, _retentionDays);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task<int?> PruneWithRetryAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                return eventStore.PruneExpiredEvents(DateTimeOffset.UtcNow.AddDays(-_retentionDays));
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode is 5 or 6)
            {
                if (attempt == 3)
                {
                    logger.LogError(exception, "Unable to prune expired events after {Attempts} attempts.", attempt);
                    return null;
                }

                logger.LogWarning(exception, "SQLite was temporarily busy while pruning events; retrying attempt {Attempt}.", attempt + 1);
                await Task.Delay(TimeSpan.FromMilliseconds(200 * attempt), cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogError(exception, "Unable to prune expired events.");
                return null;
            }
        }

        return null;
    }
}
