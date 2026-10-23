using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Storage;
using Microsoft.Extensions.Options;

namespace iisidsd.Iis;

public sealed class TemporaryDenyListCleaner(
    IDenyListStore denyListStore,
    IIisDenyListService denyListService,
    IOptions<IisAdminOptions> adminOptions,
    ILogger<TemporaryDenyListCleaner> logger,
    IisObservability observability) : BackgroundService
{
    private readonly HashSet<TemporaryDenyListEntry> _dryRunActionsLogged = [];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        do
        {
            var policy = adminOptions.Value.GetEnforcementPolicy();
            if (policy.CanMutate || policy.IsSimulation)
            {
                if (policy.CanMutate)
                {
                    denyListService.ReconcilePendingManagedDenies();
                }

                TemporaryDenyListEntry? after = null;
                while (!stoppingToken.IsCancellationRequested)
                {
                    var expiredEntries = denyListStore.GetExpired(DateTimeOffset.UtcNow, limit: 250, after);
                    if (expiredEntries.Count == 0)
                    {
                        break;
                    }

                    foreach (var entry in expiredEntries)
                    {
                        observability.RecordExpiryCleanupCandidate();
                        if (policy.IsSimulation)
                        {
                            if (_dryRunActionsLogged.Add(entry))
                            {
                                denyListService.RemoveExpiredDeniedIp(entry);
                                if (_dryRunActionsLogged.Count > 10000)
                                {
                                    _dryRunActionsLogged.Clear();
                                }
                            }
                        }
                        else if (!denyListService.RemoveExpiredDeniedIp(entry))
                        {
                            logger.LogWarning("Expired deny-list cleanup did not complete.");
                        }

                        after = entry;
                    }
                }
            }

            if (!await timer.WaitForNextTickAsync(stoppingToken))
            {
                break;
            }
        }
        while (!stoppingToken.IsCancellationRequested);
    }
}
