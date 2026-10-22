using System.Security.Cryptography;
using System.Text;
using System.Threading;
using iisidsd.Models;
using iisidsd.Networking;
using iisidsd.Observability;
using iisidsd.Storage;
using Microsoft.Extensions.Options;

namespace iisidsd.Detection;

public sealed class SuspiciousActivityDetector : ISuspiciousActivityDetector
{
    private const int ExtensionHistoryLimit = 5000;
    private readonly DetectionOptions _options;
    private readonly IEventStore? _eventStore;
    private readonly IisObservability? _observability;
    private readonly TimeProvider _timeProvider;
    private readonly string[] _suspiciousUriFragments;
    private readonly string[] _scannerUserAgents;
    private readonly Dictionary<SiteIdentityKey, ExtensionHistory> _knownExtensionsBySite = [];
    private readonly Dictionary<RequestHistoryKey, RequestHistory> _requestHistoryByClientAndSite = [];
    private readonly object _extensionHistorySync = new();
    private readonly object _requestHistorySync = new();
    private readonly object _clockSync = new();
    private DateTimeOffset? _lastWallClockSample;
    private long _lastMonotonicSample;
    private int _historyCleanupCounter;
    private int _trackedPathTokenCount;
    private int _trackedHistoryBucketCount;

    public SuspiciousActivityDetector(IOptions<DetectionOptions> options)
        : this(options, eventStore: null, observability: null, TimeProvider.System)
    {
    }

    public SuspiciousActivityDetector(IOptions<DetectionOptions> options, IEventStore? eventStore)
        : this(options, eventStore, observability: null, TimeProvider.System)
    {
    }

    public SuspiciousActivityDetector(IOptions<DetectionOptions> options, IEventStore? eventStore, IisObservability? observability)
        : this(options, eventStore, observability, TimeProvider.System)
    {
    }

    public SuspiciousActivityDetector(IOptions<DetectionOptions> options, IEventStore? eventStore, IisObservability? observability, TimeProvider timeProvider)
    {
        _options = options.Value;
        _eventStore = eventStore;
        _observability = observability;
        _timeProvider = timeProvider;
        _suspiciousUriFragments = _options.SuspiciousPathFragments
            .Where(static fragment => !string.IsNullOrWhiteSpace(fragment))
            .Select(static fragment => fragment.ToLowerInvariant())
            .ToArray();
        _scannerUserAgents = _options.ScannerUserAgents
            .Where(static userAgent => !string.IsNullOrWhiteSpace(userAgent))
            .Select(static userAgent => userAgent.ToLowerInvariant())
            .ToArray();
    }

    private static readonly HashSet<string> UnusualMethods = new(StringComparer.OrdinalIgnoreCase) { "trace", "connect", "debug" };

    public SecurityEvent? Analyze(SecurityEvent webEvent) => AnalyzeDetailed(webEvent).Event;

    public DetectionAssessment AnalyzeDetailed(SecurityEvent webEvent)
    {
        ArgumentNullException.ThrowIfNull(webEvent);
        const string DefaultReason = "IIS ETW request";
        var method = webEvent.Method ?? string.Empty;
        var uri = webEvent.Path ?? string.Empty;
        var agent = webEvent.UserAgent ?? string.Empty;
        ObserveSystemClock();
        var requestWindow = RecordRequest(webEvent);
        var matchedSignals = new List<SignalMatch>(9);
        var order = 0;

        void Match(
            bool matched,
            int configuredWeight,
            int familyPriority,
            DetectionSignalCode code,
            DetectionEvidenceFamily family,
            string indicator,
            string reason,
            bool reasonOnlyWhenGeneric = false,
            bool repeatedBehavior = false)
        {
            if (matched && configuredWeight > 0)
            {
                matchedSignals.Add(new SignalMatch(
                    code,
                    family,
                    indicator,
                    Math.Max(0, configuredWeight),
                    familyPriority,
                    order,
                    reason,
                    reasonOnlyWhenGeneric,
                    repeatedBehavior));
            }

            order++;
        }

        Match(
            webEvent.StatusCode >= Math.Max(100, _options.MinimumSuspiciousStatusCode),
            _options.StatusScoreWeight,
            0,
            DetectionSignalCode.SuspiciousStatus,
            DetectionEvidenceFamily.ResponseOutcome,
            "status code meets configured suspicious threshold",
            "probing/error response");
        Match(
            !string.IsNullOrEmpty(webEvent.Path) && webEvent.Path.Length >= Math.Max(1, _options.RequestPathLengthThreshold),
            _options.LongPathScoreWeight,
            0,
            DetectionSignalCode.LongPath,
            DetectionEvidenceFamily.PathShape,
            "request path exceeds configured length threshold",
            "unusually long request path",
            reasonOnlyWhenGeneric: true);
        Match(
            _options.RepeatedNotFoundScoreWeight > 0 && requestWindow.NotFoundCount >= Math.Max(2, _options.NotFoundBurstThreshold),
            _options.RepeatedNotFoundScoreWeight,
            2,
            DetectionSignalCode.RepeatedNotFound,
            DetectionEvidenceFamily.ResponseOutcome,
            "multiple 404 responses from the same client IP",
            "repeated not found probing",
            repeatedBehavior: true);
        Match(
            _options.AuthenticationFailureScoreWeight > 0 &&
                webEvent.StatusCode is 401 or 403 &&
                requestWindow.AuthenticationFailureCount >= Math.Max(2, _options.AuthenticationFailureThreshold),
            _options.AuthenticationFailureScoreWeight,
            2,
            DetectionSignalCode.RepeatedAuthenticationFailure,
            DetectionEvidenceFamily.ResponseOutcome,
            "repeated authentication failures from the same client IP",
            "repeated authentication failures",
            repeatedBehavior: true);
        Match(
            UnusualMethods.Contains(method),
            _options.UnusualMethodScoreWeight,
            0,
            DetectionSignalCode.UnusualMethod,
            DetectionEvidenceFamily.RequestMethod,
            "unusual HTTP method",
            "unusual HTTP method");
        Match(
            _suspiciousUriFragments.Any(fragment => uri.Contains(fragment, StringComparison.OrdinalIgnoreCase)),
            _options.PathFragmentScoreWeight,
            0,
            DetectionSignalCode.SuspiciousPathFragment,
            DetectionEvidenceFamily.PathContent,
            "suspicious request URI pattern",
            "suspicious request URI");
        Match(
            _options.UnknownExtensionScoreWeight > 0 && IsUnrecognizedFileTypeRequest(webEvent),
            _options.UnknownExtensionScoreWeight,
            1,
            DetectionSignalCode.UnknownExtension,
            DetectionEvidenceFamily.ResponseOutcome,
            "request targets file type not seen in site history",
            "unrecognized file type request",
            reasonOnlyWhenGeneric: true);
        Match(
            requestWindow.RequestCount > Math.Max(0, _options.RateThreshold),
            _options.RequestRateScoreWeight,
            0,
            DetectionSignalCode.HighRequestRate,
            DetectionEvidenceFamily.TrafficPattern,
            "request rate exceeded the configured threshold",
            "high request rate",
            repeatedBehavior: true);
        Match(
            requestWindow.UniquePathCount >= Math.Max(1, _options.PathScanUniquePathThreshold),
            _options.PathScanScoreWeight,
            1,
            DetectionSignalCode.PathEnumeration,
            DetectionEvidenceFamily.TrafficPattern,
            "many unique request paths from the same client IP",
            "path scanning activity",
            repeatedBehavior: true);
        Match(
            _scannerUserAgents.Any(userAgent => agent.Contains(userAgent, StringComparison.OrdinalIgnoreCase)),
            _options.ScannerUserAgentScoreWeight,
            0,
            DetectionSignalCode.ScannerUserAgent,
            DetectionEvidenceFamily.UserAgent,
            "known scanner user-agent",
            "known security scanner user-agent");

        var selectedSignals = matchedSignals
            .GroupBy(static signal => signal.Family)
            .Select(static family => family
                .OrderByDescending(static signal => signal.Weight)
                .ThenByDescending(static signal => signal.FamilyPriority)
                .ThenBy(static signal => signal.Order)
                .First())
            .ToArray();
        var selectedOrders = selectedSignals.Select(static signal => signal.Order).ToHashSet();
        var evidence = matchedSignals
            .Select(signal =>
            {
                var contributes = selectedOrders.Contains(signal.Order) && signal.Weight > 0;
                return new DetectionEvidence(signal.Code, signal.Family, signal.Indicator, signal.Weight,
                    contributes ? signal.Weight : 0, contributes);
            })
            .ToArray();
        long score = 0;
        foreach (var signal in selectedSignals.Where(static signal => signal.Weight > 0))
        {
            score = Math.Min(int.MaxValue, score + signal.Weight);
        }

        if (score == 0)
        {
            return new DetectionAssessment(null, DetectionEvidenceScope.None, DetectionEvidenceStrength.None, 0, evidence);
        }

        var contributingSignals = selectedSignals.Where(static signal => signal.Weight > 0).ToArray();
        var evidenceFamilyCount = contributingSignals.Select(static signal => signal.Family).Distinct().Count();
        var hasRepeatedBehavior = contributingSignals.Any(static signal => signal.RepeatedBehavior);
        var hasSingleRequestEvidence = contributingSignals.Any(static signal => !signal.RepeatedBehavior);
        var scope = hasRepeatedBehavior
            ? hasSingleRequestEvidence ? DetectionEvidenceScope.CorrelatedAttackSequence : DetectionEvidenceScope.RepeatedBehavior
            : DetectionEvidenceScope.SingleRequest;
        var strength = evidenceFamilyCount switch
        {
            <= 1 => DetectionEvidenceStrength.Limited,
            2 => DetectionEvidenceStrength.Supported,
            _ => DetectionEvidenceStrength.Corroborated
        };
        var reason = DefaultReason;
        foreach (var signal in contributingSignals.OrderBy(static signal => signal.Order))
        {
            if (!signal.ReasonOnlyWhenGeneric || reason is DefaultReason or "probing/error response")
            {
                reason = signal.Reason;
            }
        }

        var riskScore = (int)score;
        var detectedEvent = webEvent with
        {
            IsSuspicious = true,
            DetectionReason = reason,
            RiskScore = riskScore,
            RiskSeverity = GetSeverity(riskScore),
            RiskIndicators = contributingSignals.OrderBy(static signal => signal.Order).Select(static signal => signal.Indicator).ToArray()
        };

        return new DetectionAssessment(detectedEvent, scope, strength, evidenceFamilyCount, evidence);
    }

    private void ObserveSystemClock()
    {
        var wallClockSample = _timeProvider.GetUtcNow();
        var monotonicSample = _timeProvider.GetTimestamp();
        lock (_clockSync)
        {
            if (_lastWallClockSample is { } previousWallClockSample)
            {
                var elapsed = _timeProvider.GetElapsedTime(_lastMonotonicSample, monotonicSample);
                var expectedWallClock = previousWallClockSample + elapsed;
                var rollbackTolerance = TimeSpan.FromSeconds(Math.Max(5, Math.Clamp(_options.MaximumEventLatenessSeconds, 0, 30)));
                if (wallClockSample < expectedWallClock - rollbackTolerance)
                {
                    lock (_requestHistorySync)
                    {
                        _requestHistoryByClientAndSite.Clear();
                        _trackedPathTokenCount = 0;
                        _trackedHistoryBucketCount = 0;
                        _historyCleanupCounter = 0;
                        _observability?.SetDetectionRequestHistorySnapshot(0, 0, 0);
                    }

                    _observability?.RecordDetectionClockReset();
                }
            }

            _lastWallClockSample = wallClockSample;
            _lastMonotonicSample = monotonicSample;
        }
    }

    private RequestWindowSignals RecordRequest(SecurityEvent webEvent)
    {
        if (!IpAddressNormalizer.TryNormalize(webEvent.ClientIp, out var normalizedIp) ||
            !SiteIdentityNormalizer.TryCreate(webEvent, out var siteIdentity) ||
            webEvent.Timestamp == default)
        {
            return default;
        }

        var historyKey = new RequestHistoryKey(normalizedIp, siteIdentity);
        var currentBucket = webEvent.Timestamp.ToUnixTimeSeconds();
        var rateWindowSeconds = Math.Clamp(_options.RateWindowSeconds, 1, 300);
        var pathWindowSeconds = Math.Clamp(_options.PathScanWindowSeconds, 1, 300);
        var authenticationFailureWindowSeconds = Math.Clamp(_options.AuthenticationFailureWindowSeconds, 1, 300);
        var notFoundWindowSeconds = Math.Clamp(_options.NotFoundBurstWindowSeconds, 1, 300);
        var maximumWindowSeconds = Math.Max(Math.Max(rateWindowSeconds, pathWindowSeconds), authenticationFailureWindowSeconds);
        maximumWindowSeconds = Math.Max(maximumWindowSeconds, notFoundWindowSeconds);
        var maximumLateness = Math.Clamp(_options.MaximumEventLatenessSeconds, 0, 30);
        if (webEvent.Timestamp > _timeProvider.GetUtcNow().AddSeconds(maximumLateness))
        {
            _observability?.RecordOutOfOrderDetectionEvent();
            return default;
        }

        var oldestBucket = currentBucket - maximumWindowSeconds - maximumLateness + 1;
        var pathToken = _options.PathScanScoreWeight > 0
            ? GetPathToken(webEvent.Path, _options.MaximumTrackedPathLengthCharacters)
            : null;

        lock (_requestHistorySync)
        {
            var maximumHistoryBuckets = Math.Clamp(_options.MaximumTrackedHistoryBuckets, 1, 262144);
            if (_trackedHistoryBucketCount >= maximumHistoryBuckets)
            {
                PruneExpiredHistoryBuckets(oldestBucket);
                PruneInactiveHistories(oldestBucket);
            }

            var history = GetOrCreateHistory(historyKey, currentBucket, maximumWindowSeconds + maximumLateness);
            if (history is null)
            {
                return default;
            }

            if (history.LastActivityBucket != long.MinValue && currentBucket < history.LastActivityBucket - maximumLateness)
            {
                _observability?.RecordOutOfOrderDetectionEvent();
                return default;
            }

            foreach (var staleBucket in history.Buckets.Keys.Where(bucket => bucket < oldestBucket).ToArray())
            {
                history.TotalPaths -= history.Buckets[staleBucket].Paths.Count;
                _trackedPathTokenCount -= history.Buckets[staleBucket].Paths.Count;
                history.Buckets.Remove(staleBucket);
                _trackedHistoryBucketCount--;
            }

            if (!history.Buckets.TryGetValue(currentBucket, out var bucket))
            {
                if (_trackedHistoryBucketCount >= maximumHistoryBuckets)
                {
                    if (history.Buckets.Count == 0)
                    {
                        _requestHistoryByClientAndSite.Remove(historyKey);
                    }

                    _observability?.RecordDetectionHistoryCapacityRejection();
                    return default;
                }

                bucket = new RequestBucket();
                history.Buckets.Add(currentBucket, bucket);
                _trackedHistoryBucketCount++;
            }

            bucket.RequestCount = SaturatingIncrement(bucket.RequestCount);
            if (webEvent.StatusCode is 401 or 403)
            {
                bucket.AuthenticationFailureCount = SaturatingIncrement(bucket.AuthenticationFailureCount);
            }
            if (webEvent.StatusCode == 404)
            {
                bucket.NotFoundCount = SaturatingIncrement(bucket.NotFoundCount);
            }
            if (pathToken is not null && !bucket.Paths.Contains(pathToken))
            {
                if (history.TotalPaths < Math.Clamp(_options.MaximumTrackedPathsPerHistory, 1, 1024) &&
                    _trackedPathTokenCount < Math.Clamp(_options.MaximumTrackedPathsTotal, 1, 131072))
                {
                    if (bucket.Paths.Add(pathToken))
                    {
                        history.TotalPaths++;
                        _trackedPathTokenCount++;
                    }
                }
                else
                {
                    _observability?.RecordDetectionPathCapacityRejection();
                }
            }

            var requestCount = SumWindow(history.Buckets, currentBucket - rateWindowSeconds + 1, currentBucket,
                static current => current.RequestCount);
            var uniquePathCount = history.Buckets
                .Where(entry => entry.Key >= currentBucket - pathWindowSeconds + 1 && entry.Key <= currentBucket)
                .SelectMany(static entry => entry.Value.Paths)
                .Distinct(StringComparer.Ordinal)
                .Count();
            var authenticationFailureCount = SumWindow(history.Buckets, currentBucket - authenticationFailureWindowSeconds + 1, currentBucket,
                static current => current.AuthenticationFailureCount);
            var notFoundCount = Math.Min(
                SumWindow(history.Buckets, currentBucket - notFoundWindowSeconds + 1, currentBucket,
                    static current => current.NotFoundCount),
                Math.Max(1, _options.NotFoundBurstLookbackLimit));
            history.LastActivityBucket = Math.Max(history.LastActivityBucket, currentBucket);

            if ((++_historyCleanupCounter & 0xff) == 0)
            {
                PruneInactiveHistories(currentBucket - maximumWindowSeconds - maximumLateness + 1);
            }

            _observability?.SetDetectionRequestHistorySnapshot(
                _requestHistoryByClientAndSite.Count, _trackedHistoryBucketCount, _trackedPathTokenCount);

            return new RequestWindowSignals(requestCount, uniquePathCount, authenticationFailureCount, notFoundCount);
        }
    }

    private void PruneInactiveHistories(long oldestActiveBucket)
    {
        foreach (var key in _requestHistoryByClientAndSite
                     .Where(entry => entry.Value.LastActivityBucket < oldestActiveBucket)
                     .Select(static entry => entry.Key)
                     .ToArray())
        {
            if (_requestHistoryByClientAndSite.Remove(key, out var removed))
            {
                _trackedPathTokenCount -= removed.TotalPaths;
                _trackedHistoryBucketCount -= removed.Buckets.Count;
                _observability?.RecordDetectionHistoryPruned();
            }
        }

        _observability?.SetDetectionRequestHistorySnapshot(
            _requestHistoryByClientAndSite.Count, _trackedHistoryBucketCount, _trackedPathTokenCount);
    }

    private void PruneExpiredHistoryBuckets(long oldestBucket)
    {
        foreach (var history in _requestHistoryByClientAndSite.Values)
        {
            foreach (var staleBucket in history.Buckets.Keys.Where(bucket => bucket < oldestBucket).ToArray())
            {
                history.TotalPaths -= history.Buckets[staleBucket].Paths.Count;
                _trackedPathTokenCount -= history.Buckets[staleBucket].Paths.Count;
                history.Buckets.Remove(staleBucket);
                _trackedHistoryBucketCount--;
            }
        }
    }

    private RequestHistory? GetOrCreateHistory(RequestHistoryKey key, long currentBucket, int retentionSeconds)
    {
        if (_requestHistoryByClientAndSite.TryGetValue(key, out var existing))
        {
            return existing;
        }

        var oldestActiveBucket = currentBucket - retentionSeconds + 1;
        if (_requestHistoryByClientAndSite.Count >= Math.Clamp(_options.MaximumTrackedClientHistories, 1, 8192))
        {
            PruneInactiveHistories(oldestActiveBucket);
        }

        if (_requestHistoryByClientAndSite.Count >= Math.Clamp(_options.MaximumTrackedClientHistories, 1, 8192))
        {
            _observability?.RecordDetectionHistoryCapacityRejection();
            return null;
        }

        var created = new RequestHistory();
        _requestHistoryByClientAndSite.Add(key, created);
        return created;
    }

    private static string? GetPathToken(string? path, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > Math.Clamp(maximumLength, 64, 1024))
        {
            return null;
        }

        var pathEnd = path.IndexOfAny(['?', '#']);
        var pathSpan = path.AsSpan(0, pathEnd < 0 ? path.Length : pathEnd).Trim();
        if (pathSpan.IsEmpty)
        {
            return null;
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pathSpan.ToString().ToLowerInvariant())));
    }

    private static long SumWindow(Dictionary<long, RequestBucket> buckets, long oldestBucket, long currentBucket, Func<RequestBucket, long> selector)
    {
        long total = 0;
        foreach (var entry in buckets)
        {
            if (entry.Key >= oldestBucket && entry.Key <= currentBucket)
            {
                total = total > long.MaxValue - selector(entry.Value) ? long.MaxValue : total + selector(entry.Value);
            }
        }

        return total;
    }

    private static long SaturatingIncrement(long value) => value == long.MaxValue ? value : value + 1;

    private sealed record SignalMatch(
        DetectionSignalCode Code,
        DetectionEvidenceFamily Family,
        string Indicator,
        int Weight,
        int FamilyPriority,
        int Order,
        string Reason,
        bool ReasonOnlyWhenGeneric,
        bool RepeatedBehavior);

    private readonly record struct RequestWindowSignals(long RequestCount, int UniquePathCount, long AuthenticationFailureCount, long NotFoundCount);

    private readonly record struct RequestHistoryKey(string ClientIp, SiteIdentityKey SiteIdentity);

    private sealed class RequestHistory
    {
        public Dictionary<long, RequestBucket> Buckets { get; } = [];
        public long LastActivityBucket { get; set; } = long.MinValue;
        public int TotalPaths { get; set; }
    }

    private sealed class RequestBucket
    {
        public long RequestCount { get; set; }
        public long AuthenticationFailureCount { get; set; }
        public long NotFoundCount { get; set; }
        public HashSet<string> Paths { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private bool IsUnrecognizedFileTypeRequest(SecurityEvent webEvent)
    {
        if (!SiteIdentityNormalizer.TryCreate(webEvent, out var siteIdentity))
        {
            return false;
        }

        var extension = ExtractFileExtension(webEvent.Path);
        if (extension is null)
        {
            return false;
        }

        ExtensionHistory knownExtensions;
        lock (_extensionHistorySync)
        {
            if (!_knownExtensionsBySite.TryGetValue(siteIdentity, out knownExtensions!))
            {
                var maximumSites = Math.Clamp(_options.MaximumTrackedExtensionSites, 1, 512);
                if (_knownExtensionsBySite.Count >= maximumSites)
                {
                    _observability?.RecordExtensionCacheCapacityRejection();
                    return false;
                }

                knownExtensions = LoadKnownExtensions(webEvent, siteIdentity);
                _knownExtensionsBySite.Add(siteIdentity, knownExtensions);
                if (!knownExtensions.CanEvaluateUnknown)
                {
                    _observability?.RecordExtensionCacheCapacityRejection();
                }
            }

            _observability?.SetDetectionExtensionSiteCount(_knownExtensionsBySite.Count);
        }

        if (webEvent.StatusCode is >= 200 and < 400)
        {
            if (knownExtensions.TryAdd(extension, Math.Clamp(_options.MaximumExtensionsPerSite, 1, 256)))
            {
                _observability?.RecordExtensionCacheCapacityRejection();
            }
            return false;
        }

        return knownExtensions.CanEvaluateUnknown && !knownExtensions.Contains(extension);
    }

    private ExtensionHistory LoadKnownExtensions(SecurityEvent webEvent, SiteIdentityKey siteIdentity)
    {
        if (_eventStore is null)
        {
            return new ExtensionHistory([]);
        }

        var domainFilter = string.IsNullOrWhiteSpace(webEvent.Domain) ? null : webEvent.Domain;
        var extensions = _eventStore.GetRecent(ExtensionHistoryLimit, domain: domainFilter)
            .Where(previousEvent => SiteIdentityNormalizer.TryCreate(previousEvent, out var previousSite) && previousSite == siteIdentity)
            .Where(static webEvent => webEvent.StatusCode is >= 200 and < 400)
            .Select(static webEvent => ExtractFileExtension(webEvent.Path))
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(static extension => extension.Length <= 32)
            .Take(Math.Clamp(_options.MaximumExtensionsPerSite, 1, 256) + 1)
            .ToArray();

        var maximum = Math.Clamp(_options.MaximumExtensionsPerSite, 1, 256);
        return new ExtensionHistory(extensions.Take(maximum), saturated: extensions.Length > maximum);
    }

    private static string? ExtractFileExtension(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 4096)
        {
            return null;
        }

        var cleanPath = path.Split(['?', '#'], 2)[0].Trim();
        if (cleanPath.Length == 0 || cleanPath.EndsWith("/", StringComparison.Ordinal))
        {
            return null;
        }

        var extension = Path.GetExtension(cleanPath);
        return extension.Length is <= 1 or > 32 ? null : extension.ToLowerInvariant();
    }

    private sealed class ExtensionHistory(IEnumerable<string> extensions, bool saturated = false)
    {
        private readonly HashSet<string> _extensions = new(extensions, StringComparer.OrdinalIgnoreCase);

        public bool CanEvaluateUnknown { get; private set; } = !saturated;

        public bool Contains(string extension) => _extensions.Contains(extension);

        public bool TryAdd(string extension, int maximumCount)
        {
            if (_extensions.Contains(extension))
            {
                return false;
            }

            if (_extensions.Count < maximumCount)
            {
                _extensions.Add(extension);
                return false;
            }

            if (CanEvaluateUnknown)
            {
                CanEvaluateUnknown = false;
                return true;
            }

            return false;
        }
    }

    private static string GetSeverity(int score) => score switch
    {
        >= 8 => "Critical",
        >= 4 => "High",
        >= 1 => "Medium",
        _ => "Low"
    };
}
