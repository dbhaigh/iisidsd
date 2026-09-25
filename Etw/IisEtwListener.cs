using System.Globalization;
using iisidsd.Configuration;
using iisidsd.Detection;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Options;

namespace iisidsd.Etw;

public sealed class IisEtwListener(
    IEventStore eventStore,
    ISuspiciousActivityDetector detector,
    IOptions<IisEtwOptions> options,
    ILogger<IisEtwListener> logger) : BackgroundService
{
    private readonly IisEtwOptions _options = options.Value;

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
        session.EnableProvider(_options.ProviderName, TraceEventLevel.Informational);
        logger.LogInformation("Listening for IIS ETW events from {Provider}.", _options.ProviderName);

        await Task.Run(source.Process, stoppingToken);
    }

    private void OnEvent(TraceEvent traceEvent)
    {
        var properties = traceEvent.PayloadNames
            .ToDictionary(name => name, name => Convert.ToString(traceEvent.PayloadByName(name), CultureInfo.InvariantCulture) ?? string.Empty, StringComparer.OrdinalIgnoreCase);

        var webEvent = new SecurityEvent(
            traceEvent.TimeStamp.ToUniversalTime(),
            Get(properties, "scomputername", "ServerName", "ComputerName", "MachineName") ?? Environment.MachineName,
            Get(properties, "cshost", "ssitename", "SiteName", "ServerName", "Host", "HostName") ?? "unknown",
            Get(properties, "csmethod", "Method", "HttpMethod", "Verb") ?? "",
            Get(properties, "csuristem", "UriStem", "Path", "RequestPath", "Url") ?? "",
            Get(properties, "cip", "ClientIP", "ClientIp", "RemoteAddress", "RemoteIp") ?? "",
            GetInt(properties, "scstatus", "HttpStatus", "StatusCode", "Status") ?? 0,
            Get(properties, "csUserAgent", "UserAgent", "User-Agent") ?? "",
            properties);

        var suspiciousEvent = detector.Analyze(webEvent);
        eventStore.Publish(suspiciousEvent ?? webEvent);
        if (suspiciousEvent is not null)
        {
            logger.LogWarning("Suspicious IIS activity detected for {Domain}: {Reason}", suspiciousEvent.Domain, suspiciousEvent.DetectionReason);
        }
    }

    private static string? Get(IReadOnlyDictionary<string, string> properties, params string[] names)
        => names.FirstOrDefault(properties.ContainsKey) is { } name ? properties[name] : null;

    private static int? GetInt(IReadOnlyDictionary<string, string> properties, params string[] names)
        => int.TryParse(Get(properties, names), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : null;
}
