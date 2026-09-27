using System.Collections.Concurrent;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.Extensions.Options;

namespace iisidsd.Detection;

public sealed class SuspiciousActivityDetector : ISuspiciousActivityDetector
{
    private const int ExtensionHistoryLimit = 5000;
    private readonly DetectionOptions _options;
    private readonly IEventStore? _eventStore;
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _knownExtensionsByDomain = new(StringComparer.OrdinalIgnoreCase);

    public SuspiciousActivityDetector(IOptions<DetectionOptions> options)
        : this(options, eventStore: null)
    {
    }

    public SuspiciousActivityDetector(IOptions<DetectionOptions> options, IEventStore? eventStore)
    {
        _options = options.Value;
        _eventStore = eventStore;
    }

    private static readonly HashSet<int> SuspiciousStatusCodes = [401, 403, 404];
    private static readonly HashSet<string> UnusualMethods = ["trace", "connect", "debug"];
    private static readonly string[] SuspiciousUriFragments = ["../", "%2e", "wp-admin", "phpmyadmin", "/.env"];
    private static readonly string[] ScannerUserAgents = ["sqlmap", "nikto", "nmap", "masscan", "burp"];

    public SecurityEvent? Analyze(SecurityEvent webEvent)
    {
        var score = 0;
        var reason = "IIS ETW request";
        var indicators = new List<string>();

        var method = (webEvent.Method ?? string.Empty).ToLowerInvariant();
        var uri = (webEvent.Path ?? string.Empty).ToLowerInvariant();
        var agent = (webEvent.UserAgent ?? string.Empty).ToLowerInvariant();

        if (SuspiciousStatusCodes.Contains(webEvent.StatusCode))
        {
            score += 1;
            reason = "probing/error response";
            indicators.Add("suspicious status code (401/403/404)");
        }

        if (UnusualMethods.Contains(method))
        {
            score += 3;
            reason = "unusual HTTP method";
            indicators.Add("unusual HTTP method");
        }

        if (SuspiciousUriFragments.Any(uri.Contains))
        {
            score += 5;
            reason = "suspicious request URI";
            indicators.Add("suspicious request URI pattern");
        }

        if (IsUnrecognizedFileTypeRequest(webEvent))
        {
            score += 4;
            if (reason is "IIS ETW request" or "probing/error response")
            {
                reason = "unrecognized file type request";
            }
            indicators.Add("request targets file type not seen in site history");
        }

        if (ScannerUserAgents.Any(agent.Contains))
        {
            score += 6;
            reason = "known security scanner user-agent";
            indicators.Add("known scanner user-agent");
        }

        if (score == 0)
        {
            return null;
        }

        return webEvent with
        {
            IsSuspicious = true,
            DetectionReason = reason,
            RiskScore = score,
            RiskSeverity = GetSeverity(score),
            RiskIndicators = indicators
        };
    }

    private bool IsUnrecognizedFileTypeRequest(SecurityEvent webEvent)
    {
        var extension = ExtractFileExtension(webEvent.Path);
        if (extension is null)
        {
            return false;
        }

        var domain = string.IsNullOrWhiteSpace(webEvent.Domain) ? "*" : webEvent.Domain;
        var knownExtensions = _knownExtensionsByDomain.GetOrAdd(domain, LoadKnownExtensions);

        if (webEvent.StatusCode is >= 200 and < 400)
        {
            knownExtensions.TryAdd(extension, 0);
            return false;
        }

        return !knownExtensions.ContainsKey(extension);
    }

    private ConcurrentDictionary<string, byte> LoadKnownExtensions(string domain)
    {
        if (_eventStore is null)
        {
            return new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        }

        var domainFilter = string.Equals(domain, "*", StringComparison.Ordinal) ? null : domain;
        var usedExtensions = _eventStore.GetRecent(ExtensionHistoryLimit, domain: domainFilter)
            .Where(static webEvent => webEvent.StatusCode is >= 200 and < 400)
            .Select(static webEvent => ExtractFileExtension(webEvent.Path))
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static extension => extension, static _ => (byte)0, StringComparer.OrdinalIgnoreCase);

        return new ConcurrentDictionary<string, byte>(usedExtensions, StringComparer.OrdinalIgnoreCase);
    }

    private static string? ExtractFileExtension(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var cleanPath = path.Split(['?', '#'], 2)[0].Trim();
        if (cleanPath.Length == 0 || cleanPath.EndsWith("/", StringComparison.Ordinal))
        {
            return null;
        }

        var extension = Path.GetExtension(cleanPath);
        return extension.Length <= 1 ? null : extension.ToLowerInvariant();
    }

    private static string GetSeverity(int score) => score switch
    {
        >= 8 => "Critical",
        >= 4 => "High",
        >= 1 => "Medium",
        _ => "Low"
    };
}
