using System.Collections.Concurrent;
using System.Threading;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.Extensions.Options;

namespace iisidsd.Detection;

public sealed class SuspiciousActivityDetector : ISuspiciousActivityDetector
{
    private const int ExtensionHistoryLimit = 5000;
    private readonly DetectionOptions _options;
    private readonly IEventStore? _eventStore;
    private readonly string[] _suspiciousUriFragments;
    private readonly string[] _scannerUserAgents;
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _knownExtensionsByDomain = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, RequestHistory> _requestHistoryByIp = new(StringComparer.OrdinalIgnoreCase);
    private int _historyCleanupCounter;

    public SuspiciousActivityDetector(IOptions<DetectionOptions> options)
        : this(options, eventStore: null)
    {
    }

    public SuspiciousActivityDetector(IOptions<DetectionOptions> options, IEventStore? eventStore)
    {
        _options = options.Value;
        _eventStore = eventStore;
        _suspiciousUriFragments = _options.SuspiciousPathFragments
            .Where(static fragment => !string.IsNullOrWhiteSpace(fragment))
            .Select(static fragment => fragment.ToLowerInvariant())
            .ToArray();
        _scannerUserAgents = _options.ScannerUserAgents
            .Where(static userAgent => !string.IsNullOrWhiteSpace(userAgent))
            .Select(static userAgent => userAgent.ToLowerInvariant())
            .ToArray();
    }

    private static readonly HashSet<string> UnusualMethods = ["trace", "connect", "debug"];

    public SecurityEvent? Analyze(SecurityEvent webEvent)
    {
        long score = 0;
        var reason = "IIS ETW request";
        var indicators = new List<string>();

        var method = (webEvent.Method ?? string.Empty).ToLowerInvariant();
        var uri = (webEvent.Path ?? string.Empty).ToLowerInvariant();
        var agent = (webEvent.UserAgent ?? string.Empty).ToLowerInvariant();

        var requestWindow = RecordRequest(webEvent);

        if (webEvent.StatusCode >= Math.Max(100, _options.MinimumSuspiciousStatusCode))
        {
            score += Math.Max(0, _options.StatusScoreWeight);
            reason = "probing/error response";
            indicators.Add("status code meets configured suspicious threshold");
        }

        if (!string.IsNullOrEmpty(webEvent.Path) &&
            webEvent.Path.Length >= Math.Max(1, _options.RequestPathLengthThreshold))
        {
            score += Math.Max(0, _options.LongPathScoreWeight);
            if (reason == "IIS ETW request")
            {
                reason = "unusually long request path";
            }
            indicators.Add("request path exceeds configured length threshold");
        }

        if (IsRepeatedNotFoundScan(webEvent))
        {
            score += Math.Max(0, _options.RepeatedNotFoundScoreWeight);
            reason = "repeated not found probing";
            indicators.Add("multiple 404 responses from the same client IP");
        }

        if (UnusualMethods.Contains(method))
        {
            score += Math.Max(0, _options.UnusualMethodScoreWeight);
            reason = "unusual HTTP method";
            indicators.Add("unusual HTTP method");
        }

        if (_suspiciousUriFragments.Any(uri.Contains))
        {
            score += Math.Max(0, _options.PathFragmentScoreWeight);
            reason = "suspicious request URI";
            indicators.Add("suspicious request URI pattern");
        }

        if (IsUnrecognizedFileTypeRequest(webEvent))
        {
            score += Math.Max(0, _options.UnknownExtensionScoreWeight);
            if (reason is "IIS ETW request" or "probing/error response")
            {
                reason = "unrecognized file type request";
            }
            indicators.Add("request targets file type not seen in site history");
        }

        if (requestWindow.RequestCount > Math.Max(0, _options.RateThreshold))
        {
            score += Math.Max(0, _options.RequestRateScoreWeight);
            reason = "high request rate";
            indicators.Add("request rate exceeded the configured threshold");
        }

        if (requestWindow.UniquePathCount >= Math.Max(1, _options.PathScanUniquePathThreshold))
        {
            score += Math.Max(0, _options.PathScanScoreWeight);
            reason = "path scanning activity";
            indicators.Add("many unique request paths from the same client IP");
        }

        if (_scannerUserAgents.Any(agent.Contains))
        {
            score += Math.Max(0, _options.ScannerUserAgentScoreWeight);
            reason = "known security scanner user-agent";
            indicators.Add("known scanner user-agent");
        }

        if (score == 0)
        {
            return null;
        }

        var riskScore = (int)Math.Min(score, int.MaxValue);
        return webEvent with
        {
            IsSuspicious = true,
            DetectionReason = reason,
            RiskScore = riskScore,
            RiskSeverity = GetSeverity(riskScore),
            RiskIndicators = indicators
        };
    }

    private RequestWindowSignals RecordRequest(SecurityEvent webEvent)
    {
        if (string.IsNullOrWhiteSpace(webEvent.ClientIp))
        {
            return default;
        }

        var ip = webEvent.ClientIp;
        var currentBucket = webEvent.Timestamp.ToUnixTimeSeconds();
        var rateWindowSeconds = Math.Max(1, _options.RateWindowSeconds);
        var pathWindowSeconds = Math.Max(1, _options.PathScanWindowSeconds);
        var maximumWindowSeconds = Math.Max(rateWindowSeconds, pathWindowSeconds);
        var oldestBucket = currentBucket - maximumWindowSeconds + 1;
        var normalizedPath = NormalizePath(webEvent.Path);
        var history = _requestHistoryByIp.GetOrAdd(ip, static _ => new RequestHistory());
        long requestCount;
        int uniquePathCount;

        while (true)
        {
            lock (history.Sync)
            {
                if (!_requestHistoryByIp.TryGetValue(ip, out var activeHistory) ||
                    !ReferenceEquals(history, activeHistory))
                {
                    history = _requestHistoryByIp.GetOrAdd(ip, static _ => new RequestHistory());
                    continue;
                }

                foreach (var staleBucket in history.Buckets.Keys.Where(bucket => bucket < oldestBucket).ToArray())
                {
                    history.Buckets.Remove(staleBucket);
                }

                if (!history.Buckets.TryGetValue(currentBucket, out var bucket))
                {
                    bucket = new RequestBucket();
                    history.Buckets.Add(currentBucket, bucket);
                }

                bucket.RequestCount++;
                if (normalizedPath.Length > 0)
                {
                    bucket.Paths.Add(normalizedPath);
                }

                var oldestRateBucket = currentBucket - rateWindowSeconds + 1;
                requestCount = history.Buckets
                    .Where(entry => entry.Key >= oldestRateBucket && entry.Key <= currentBucket)
                    .Sum(static entry => entry.Value.RequestCount);
                var oldestPathBucket = currentBucket - pathWindowSeconds + 1;
                uniquePathCount = history.Buckets
                    .Where(entry => entry.Key >= oldestPathBucket && entry.Key <= currentBucket)
                    .SelectMany(static entry => entry.Value.Paths)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count();
                history.LastActivityBucket = Math.Max(history.LastActivityBucket, currentBucket);
            }

            break;
        }

        if ((Interlocked.Increment(ref _historyCleanupCounter) & 0xff) == 0)
        {
            PruneInactiveHistories(currentBucket - maximumWindowSeconds + 1);
        }

        return new RequestWindowSignals(requestCount, uniquePathCount);
    }

    private void PruneInactiveHistories(long oldestActiveBucket)
    {
        foreach (var entry in _requestHistoryByIp)
        {
            lock (entry.Value.Sync)
            {
                if (entry.Value.LastActivityBucket < oldestActiveBucket)
                {
                    ((ICollection<KeyValuePair<string, RequestHistory>>)_requestHistoryByIp).Remove(entry);
                }
            }
        }
    }

    private static string NormalizePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        return path.Split(['?', '#'], 2)[0].Trim().ToLowerInvariant();
    }

    private readonly record struct RequestWindowSignals(long RequestCount, int UniquePathCount);

    private sealed class RequestHistory
    {
        public object Sync { get; } = new();
        public Dictionary<long, RequestBucket> Buckets { get; } = [];
        public long LastActivityBucket { get; set; } = long.MinValue;
    }

    private sealed class RequestBucket
    {
        public long RequestCount { get; set; }
        public HashSet<string> Paths { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private bool IsRepeatedNotFoundScan(SecurityEvent webEvent)
    {
        if (webEvent.StatusCode != 404 || _eventStore is null || string.IsNullOrWhiteSpace(webEvent.ClientIp))
        {
            return false;
        }

        var threshold = Math.Max(2, _options.NotFoundBurstThreshold);
        var lookbackLimit = Math.Max(threshold, _options.NotFoundBurstLookbackLimit);
        var priorNotFoundResponses = _eventStore.GetRecent(lookbackLimit, clientIp: webEvent.ClientIp)
            .Count(static previousEvent => previousEvent.StatusCode == 404);

        return priorNotFoundResponses + 1 >= threshold;
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
