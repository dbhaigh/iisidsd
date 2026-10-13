using System.Globalization;
using System.Threading.Channels;
using iisidsd.Configuration;
using iisidsd.Detection;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Options;

namespace iisidsd.Etw;

public sealed class IisEtwListener(
    IEventStore eventStore,
    ISuspiciousActivityDetector detector,
    IIisAutoDenyService autoDenyService,
    IOptions<IisEtwOptions> options,
    ILogger<IisEtwListener> logger) : BackgroundService
{
    private static readonly string[] ServerNamePropertyNames = ["scomputername", "ServerName", "ComputerName", "MachineName"];
    private static readonly string[] DomainPropertyNames = ["cshost", "ssitename", "SiteName", "ServerName", "Host", "HostName"];
    private static readonly string[] MethodPropertyNames = ["csmethod", "Method", "HttpMethod", "Verb"];
    private static readonly string[] PathPropertyNames = ["csuristem", "UriStem", "Path", "RequestPath", "Url"];
    private static readonly string[] ClientIpPropertyNames = ["cip", "ClientIP", "ClientIp", "RemoteAddress", "RemoteIp"];
    private static readonly string[] StatusCodePropertyNames = ["scstatus", "HttpStatus", "StatusCode", "Status"];
    private static readonly string[] UserAgentPropertyNames = ["csUserAgent", "UserAgent", "User-Agent"];

    private readonly IisEtwOptions _options = options.Value;
    private readonly Channel<SecurityEvent> _ingestionQueue = Channel.CreateBounded<SecurityEvent>(
        new BoundedChannelOptions(Math.Max(1, options.Value.IngestionBufferSize))
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
    private long _droppedEventCount;

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
        var processingTask = ProcessEventsAsync();

        try
        {
            await Task.Run(source.Process, stoppingToken);
        }
        catch
        {
            _ingestionQueue.Writer.TryComplete();
            await processingTask;
            throw;
        }

        _ingestionQueue.Writer.TryComplete();
        await processingTask;
    }

    private void OnEvent(TraceEvent traceEvent)
    {
        var properties = traceEvent.PayloadNames
            .ToDictionary(name => name, name => Convert.ToString(traceEvent.PayloadByName(name), CultureInfo.InvariantCulture) ?? string.Empty, StringComparer.OrdinalIgnoreCase);

        var webEvent = new SecurityEvent(
            traceEvent.TimeStamp.ToUniversalTime(),
            Get(properties, ServerNamePropertyNames) ?? Environment.MachineName,
            Get(properties, DomainPropertyNames) ?? "unknown",
            Get(properties, MethodPropertyNames) ?? "",
            Get(properties, PathPropertyNames) ?? "",
            Get(properties, ClientIpPropertyNames) ?? "",
            GetInt(properties, StatusCodePropertyNames) ?? 0,
            Get(properties, UserAgentPropertyNames) ?? "",
            properties);

        if (!_ingestionQueue.Writer.TryWrite(webEvent))
        {
            var droppedCount = Interlocked.Increment(ref _droppedEventCount);
            if (droppedCount == 1 || droppedCount % 100 == 0)
            {
                logger.LogWarning("ETW ingestion queue is full; {DroppedEventCount} event(s) have been dropped.", droppedCount);
            }
        }
    }

    private async Task ProcessEventsAsync()
    {
        await foreach (var webEvent in _ingestionQueue.Reader.ReadAllAsync())
        {
            try
            {
                var suspiciousEvent = detector.Analyze(webEvent);
                var storedEvent = suspiciousEvent ?? webEvent;
                eventStore.Publish(storedEvent);
                if (suspiciousEvent is not null)
                {
                    logger.LogWarning("Suspicious IIS activity detected for {Domain}: {Reason}", suspiciousEvent.Domain, suspiciousEvent.DetectionReason);
                    autoDenyService.Apply(suspiciousEvent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Unable to process IIS ETW event {EventId} from {ClientIp}.", webEvent.Id, webEvent.ClientIp);
            }
        }
    }

    private static string? Get(IReadOnlyDictionary<string, string> properties, string[] names)
    {
        foreach (var name in names)
        {
            if (properties.TryGetValue(name, out var value))
            {
                return value;
            }
        }

        return null;
    }

    private static int? GetInt(IReadOnlyDictionary<string, string> properties, string[] names)
        => int.TryParse(Get(properties, names), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : null;
}
