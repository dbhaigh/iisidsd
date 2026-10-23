using System.Diagnostics;
using System.Runtime.ExceptionServices;
using iisidsd.Configuration;
using iisidsd.Detection;
using iisidsd.Iis;
using iisidsd.Observability;
using iisidsd.Storage;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Options;

namespace iisidsd.Etw;

public sealed class IisEtwListener(
    IEventStore eventStore,
    ISuspiciousActivityDetector detector,
    IIisAutoDenyService autoDenyService,
    IisObservability observability,
    IOptions<IisEtwOptions> options,
    ILogger<IisEtwListener> logger) : BackgroundService
{
    private readonly IisEtwOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            observability.SetEtwSubscriptionState(EtwSubscriptionState.Disabled);
            logger.LogInformation("IIS ETW ingestion is disabled.");
            await Task.Delay(Timeout.Infinite, stoppingToken);
            return;
        }

        if (!OperatingSystem.IsWindows())
        {
            observability.SetEtwSubscriptionState(EtwSubscriptionState.Unsupported);
            logger.LogError("IIS ETW ingestion requires Windows.");
            await Task.Delay(Timeout.Infinite, stoppingToken);
            return;
        }

        var retryDelay = TimeSpan.FromSeconds(5);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunSessionAsync(stoppingToken);
                if (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                throw new InvalidOperationException("IIS ETW event processing stopped unexpectedly.");
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                observability.SetEtwSubscriptionState(EtwSubscriptionState.Recovering);
                observability.RecordFatalError("etw", exception.GetType().Name);
                logger.LogError(
                    exception,
                    "IIS ETW ingestion stopped. Retrying in {RetryDelay}.",
                    retryDelay);
                try
                {
                    await Task.Delay(retryDelay, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                retryDelay = TimeSpan.FromSeconds(Math.Min(retryDelay.TotalSeconds * 2, 60));
            }
        }

        observability.SetEtwSubscriptionState(EtwSubscriptionState.Stopped);
    }

    private async Task RunSessionAsync(CancellationToken stoppingToken)
    {
        observability.SetEtwSubscriptionState(EtwSubscriptionState.Starting);
        var pipeline = new EtwIngestionPipeline(
            eventStore,
            detector,
            autoDenyService,
            observability,
            options,
            logger);
        using var session = new TraceEventSession(_options.SessionName);
        using var source = new ETWTraceEventSource(session.SessionName, TraceEventSourceType.Session);
        using var registration = stoppingToken.Register(() => source.StopProcessing());

        source.Dynamic.All += traceEvent => OnEvent(traceEvent, pipeline);
        session.EnableProvider(_options.ProviderId, TraceEventLevel.Informational);
        observability.SetEtwSubscriptionState(EtwSubscriptionState.Listening);
        logger.LogInformation("Listening for IIS ETW events from {Provider} ({ProviderId}).", _options.ProviderName, _options.ProviderId);
        var processingTask = pipeline.ProcessAsync();
        Exception? processingFailure = null;

        try
        {
            await Task.Run(source.Process, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            processingFailure = exception;
        }
        finally
        {
            pipeline.Complete();
        }

        logger.LogInformation("ETW reception stopped; draining accepted events.");
        await processingTask;
        logger.LogInformation(
            "ETW ingestion drain completed. AcceptedCount={AcceptedCount} ProcessedCount={ProcessedCount} DroppedCount={DroppedCount} FailureCount={FailureCount}",
            observability.EtwEventsAccepted,
            observability.EventsProcessed,
            observability.EtwEventsDropped,
            observability.EventProcessingFailures);
        if (processingFailure is not null)
        {
            ExceptionDispatchInfo.Capture(processingFailure).Throw();
        }
    }

    private void OnEvent(TraceEvent traceEvent, EtwIngestionPipeline pipeline)
    {
        var receivedTimestamp = Stopwatch.GetTimestamp();
        try
        {
            var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var totalCharacters = 0;
            foreach (var name in traceEvent.PayloadNames)
            {
                if (properties.Count == 256 || string.IsNullOrWhiteSpace(name) || name.Length > 128)
                {
                    pipeline.RecordMalformed("too-many-payload-properties");
                    return;
                }

                var value = Convert.ToString(traceEvent.PayloadByName(name), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
                totalCharacters += name.Length + value.Length;
                if (value.Length > 16_384 || totalCharacters > 65_536)
                {
                    pipeline.RecordMalformed("payload-too-large");
                    return;
                }

                properties.Add(name, value);
            }

            var payload = new EtwEventPayload(
                traceEvent.TimeStamp.ToUniversalTime(),
                Guid.NewGuid().ToString("N"),
                receivedTimestamp,
                properties);
            pipeline.TryEnqueue(payload);
        }
        catch (Exception)
        {
            pipeline.RecordMalformed("payload-snapshot-failed");
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(CancellationToken.None);
    }
}
