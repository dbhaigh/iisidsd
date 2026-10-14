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
            var prunedCount = eventStore.PruneExpiredEvents(DateTimeOffset.UtcNow.AddDays(-_retentionDays));
            if (prunedCount > 0)
            {
                logger.LogInformation("Pruned {EventCount} events older than {RetentionDays} days.", prunedCount, _retentionDays);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
