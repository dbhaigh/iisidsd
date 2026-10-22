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
    private readonly EtwIngestionPipeline _pipeline = new(
        eventStore,
        detector,
        autoDenyService,
        observability,
        options,
        logger);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            logger.LogInformation("IIS ETW ingestion is disabled.");
            await Task.Delay(Timeout.Infinite, stoppingToken);
            return;
        }

        if (!OperatingSystem.IsWindows())
        {
            logger.LogError("IIS ETW ingestion requires Windows.");
            await Task.Delay(Timeout.Infinite, stoppingToken);
            return;
        }

        using var session = new TraceEventSession(_options.SessionName);
        using var source = new ETWTraceEventSource(session.SessionName, TraceEventSourceType.Session);
        using var registration = stoppingToken.Register(() => source.StopProcessing());

        source.Dynamic.All += OnEvent;
        session.EnableProvider(_options.ProviderId, TraceEventLevel.Informational);
        logger.LogInformation("Listening for IIS ETW events from {Provider} ({ProviderId}).", _options.ProviderName, _options.ProviderId);
        var processingTask = _pipeline.ProcessAsync();
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
            _pipeline.Complete();
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

    private void OnEvent(TraceEvent traceEvent)
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
                    _pipeline.RecordMalformed("too-many-payload-properties");
                    return;
                }

                var value = Convert.ToString(traceEvent.PayloadByName(name), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
                totalCharacters += name.Length + value.Length;
                if (value.Length > 16_384 || totalCharacters > 65_536)
                {
                    _pipeline.RecordMalformed("payload-too-large");
                    return;
                }

                properties.Add(name, value);
            }

            var payload = new EtwEventPayload(
                traceEvent.TimeStamp.ToUniversalTime(),
                Guid.NewGuid().ToString("N"),
                receivedTimestamp,
                properties);
            _pipeline.TryEnqueue(payload);
        }
        catch (Exception)
        {
            _pipeline.RecordMalformed("payload-snapshot-failed");
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(CancellationToken.None);
    }
}
