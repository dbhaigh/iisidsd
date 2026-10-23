using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.Extensions.Options;

namespace iisidsd.Notifications;

public sealed class NotificationDeliveryService(
    INotificationQueue queue,
    INotificationProvider provider,
    IOptions<NotificationOptions> options,
    TimeProvider timeProvider,
    ILogger<NotificationDeliveryService> logger) : BackgroundService
{
    private const int DeliveryBatchSize = 25;
    private readonly NotificationOptions _options = options.Value;
    private DateTimeOffset _nextPruneAtUtc;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            int dispatched;
            try
            {
                dispatched = await DispatchDueAsync(stoppingToken);
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(
                    "Notification worker iteration failed. FailureType={FailureType}",
                    exception.GetType().Name);
                await Task.Delay(TimeSpan.FromSeconds(5), timeProvider, stoppingToken);
                continue;
            }

            if (dispatched == 0)
            {
                await Task.Delay(TimeSpan.FromSeconds(1), timeProvider, stoppingToken);
            }
        }
    }

    public async Task<int> DispatchDueAsync(CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        if (now >= _nextPruneAtUtc)
        {
            queue.PruneExpired(now.AddDays(-_options.RetentionDays));
            _nextPruneAtUtc = now.AddHours(1);
        }

        if (!_options.Enabled || !string.Equals(_options.Provider, provider.Name, StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        var due = queue.GetDue(now, DeliveryBatchSize);
        var dispatched = 0;
        foreach (var incident in due)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(_options.DeliveryTimeoutSeconds));
            try
            {
                var message = NotificationMessageFormatter.Create(incident, _options.DashboardUrl);
                await provider.DeliverAsync(message, timeout.Token).WaitAsync(timeout.Token);
                queue.RecordDelivered(incident.Id, timeProvider.GetUtcNow());
                dispatched++;
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    queue.RecordFailure(incident.Id, timeProvider.GetUtcNow(), exception.GetType().Name);
                }
                catch (Exception stateException)
                {
                    logger.LogError(
                        "Unable to record notification delivery outcome. NotificationId={NotificationId} FailureType={FailureType}",
                        incident.Id,
                        stateException.GetType().Name);
                }

                logger.LogWarning(
                    "Notification delivery failed. NotificationId={NotificationId} FailureType={FailureType}",
                    incident.Id,
                    exception.GetType().Name);
            }
        }

        return dispatched;
    }
}