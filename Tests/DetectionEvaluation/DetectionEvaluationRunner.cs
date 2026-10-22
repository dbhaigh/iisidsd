using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using iisidsd.Detection;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.Extensions.Options;

namespace iisidsd.DetectionEvaluation;

public static class DetectionEvaluationRunner
{
    public const string DetectorRevision = "heuristic-evidence-v2";

    private static readonly JsonSerializerOptions FixtureJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };

    public static EvaluationReport Evaluate(string fixturePath, DetectionOptions options)
    {
        var fixtureBytes = File.ReadAllBytes(fixturePath);
        var dataset = JsonSerializer.Deserialize<EvaluationDataset>(fixtureBytes, FixtureJsonOptions)
            ?? throw new InvalidDataException("Evaluation fixture is empty or invalid JSON.");
        ValidateDataset(dataset);

        var scenarioResults = dataset.Scenarios
            .Select(scenario => EvaluateScenario(scenario, options))
            .ToArray();
        var overallMetrics = EvaluationMetrics.From(scenarioResults.SelectMany(static scenario => scenario.Events));
        var classMetrics = scenarioResults
            .GroupBy(static scenario => scenario.Class, StringComparer.Ordinal)
            .OrderBy(static grouping => grouping.Key, StringComparer.Ordinal)
            .Select(grouping => new ClassEvaluation(grouping.Key,
                EvaluationMetrics.From(grouping.SelectMany(static scenario => scenario.Events))))
            .ToArray();
        var detectionLatencies = scenarioResults
            .Where(static scenario => scenario.DetectionLatencyMilliseconds.HasValue)
            .Select(static scenario => scenario.DetectionLatencyMilliseconds!.Value)
            .Order()
            .ToArray();

        return new EvaluationReport(
            1,
            typeof(SuspiciousActivityDetector).Assembly.GetName().Version?.ToString()
                ?? "unknown",
            DetectorRevision,
            dataset.DatasetId,
            dataset.Description,
            Convert.ToHexString(SHA256.HashData(fixtureBytes)).ToLowerInvariant(),
            scenarioResults.Sum(static scenario => scenario.Events.Count),
            scenarioResults.Length,
            overallMetrics,
            classMetrics,
            new DetectionLatencySummary(
                scenarioResults.Count(static scenario => scenario.DetectionLatencyMilliseconds.HasValue),
                scenarioResults.Count(static scenario => scenario.ActivityStartEventId is not null && !scenario.DetectionLatencyMilliseconds.HasValue),
                detectionLatencies.Length == 0 ? null : Round(detectionLatencies.Average()),
                Median(detectionLatencies)),
            options,
            dataset.LabelQuality,
            scenarioResults,
            null);
    }

    private static ScenarioEvaluation EvaluateScenario(EvaluationScenario scenario, DetectionOptions options)
    {
        var events = ExpandEvents(scenario);
        var eventStore = new ReplayEventStore();
        var detector = new SuspiciousActivityDetector(Options.Create(options), eventStore);
        var evaluations = new List<EventEvaluation>(events.Count);
        DateTimeOffset? firstDetectionTimestamp = null;
        DateTimeOffset? activityStartTimestamp = null;
        var activityStartIndex = -1;

        for (var index = 0; index < events.Count; index++)
        {
            var fixtureEvent = events[index];
            if (string.Equals(fixtureEvent.Id, scenario.ActivityStartEventId, StringComparison.Ordinal))
            {
                activityStartTimestamp = fixtureEvent.Timestamp;
                activityStartIndex = index;
            }

            var assessment = detector.AnalyzeDetailed(fixtureEvent.ToSecurityEvent());
            var detectedEvent = assessment.Event;
            var isDetected = detectedEvent is not null;
            evaluations.Add(new EventEvaluation(fixtureEvent.Id, scenario.Class, fixtureEvent.ExpectedSuspicious, isDetected,
                isDetected ? detectedEvent!.RiskScore : null,
                isDetected ? detectedEvent!.RiskSeverity : null,
                assessment.Scope.ToString(),
                assessment.Strength.ToString(),
                assessment.EvidenceFamilyCount,
                assessment.Evidence.Select(static evidence => new EvidenceEvaluation(
                    evidence.Code.ToString(), evidence.Family.ToString(), evidence.ConfiguredWeight,
                    evidence.ScoreContribution, evidence.Contributed)).ToArray(),
                isDetected ? detectedEvent!.RiskIndicators ?? [] : []));

            eventStore.Publish(detectedEvent ?? fixtureEvent.ToSecurityEvent());
            if (activityStartIndex >= 0 && index >= activityStartIndex && isDetected && firstDetectionTimestamp is null)
            {
                firstDetectionTimestamp = fixtureEvent.Timestamp;
            }
        }

        var latency = activityStartTimestamp.HasValue && firstDetectionTimestamp.HasValue
            ? Round((firstDetectionTimestamp.Value - activityStartTimestamp.Value).TotalMilliseconds)
            : (double?)null;

        return new ScenarioEvaluation(scenario.Id, scenario.Class, scenario.Description, scenario.ActivityStartEventId,
            EvaluationMetrics.From(evaluations), latency, evaluations);
    }

    private static List<ExpandedEvaluationEvent> ExpandEvents(EvaluationScenario scenario)
    {
        var expanded = new List<ExpandedEvaluationEvent>();
        foreach (var fixtureEvent in scenario.Events)
        {
            var repeat = Math.Max(1, fixtureEvent.Repeat);
            for (var index = 0; index < repeat; index++)
            {
                var eventId = repeat == 1
                    ? fixtureEvent.Id
                    : $"{fixtureEvent.Id}-{index + 1:D3}";
                var clientIp = fixtureEvent.ClientIps is { Length: > 0 }
                    ? fixtureEvent.ClientIps[index % fixtureEvent.ClientIps.Length]
                    : fixtureEvent.ClientIp;
                expanded.Add(new ExpandedEvaluationEvent(
                    eventId,
                    fixtureEvent.Timestamp.AddMilliseconds(fixtureEvent.IntervalMilliseconds * index),
                    fixtureEvent.Server,
                    fixtureEvent.Domain,
                    fixtureEvent.Method,
                    fixtureEvent.Path.Replace("{index}", (index + 1).ToString("D3", CultureInfo.InvariantCulture), StringComparison.Ordinal),
                    clientIp,
                    fixtureEvent.StatusCode,
                    fixtureEvent.UserAgent,
                    fixtureEvent.Properties,
                    fixtureEvent.ExpectedSuspicious));
            }
        }

        return expanded;
    }

    private static void ValidateDataset(EvaluationDataset dataset)
    {
        if (dataset.SchemaVersion != 1 || string.IsNullOrWhiteSpace(dataset.DatasetId) || dataset.Scenarios.Count == 0)
        {
            throw new InvalidDataException("Fixture requires schemaVersion 1, a datasetId, and at least one scenario.");
        }

        var scenarioIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var scenario in dataset.Scenarios)
        {
            if (string.IsNullOrWhiteSpace(scenario.Id) || !scenarioIds.Add(scenario.Id) ||
                string.IsNullOrWhiteSpace(scenario.Class) || scenario.Events.Count == 0)
            {
                throw new InvalidDataException("Each scenario must have a unique id, class, and at least one event.");
            }

            var eventIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var fixtureEvent in scenario.Events)
            {
                if (string.IsNullOrWhiteSpace(fixtureEvent.Id) || fixtureEvent.Repeat < 1 || fixtureEvent.IntervalMilliseconds < 0 ||
                    string.IsNullOrWhiteSpace(fixtureEvent.Method) || fixtureEvent.Path is null || fixtureEvent.ClientIp is null ||
                    fixtureEvent.ClientIps?.Any(string.IsNullOrWhiteSpace) == true)
                {
                    throw new InvalidDataException($"Scenario '{scenario.Id}' contains an invalid event template.");
                }

                for (var index = 0; index < fixtureEvent.Repeat; index++)
                {
                    var eventId = fixtureEvent.Repeat == 1 ? fixtureEvent.Id : $"{fixtureEvent.Id}-{index + 1:D3}";
                    if (!eventIds.Add(eventId))
                    {
                        throw new InvalidDataException($"Scenario '{scenario.Id}' contains duplicate event id '{eventId}'.");
                    }
                }
            }

            if (scenario.ActivityStartEventId is not null && !eventIds.Contains(scenario.ActivityStartEventId))
            {
                throw new InvalidDataException($"Scenario '{scenario.Id}' references an unknown activityStartEventId.");
            }
        }
    }

    private static double Round(double value) => Math.Round(value, 4, MidpointRounding.AwayFromZero);

    private static double? Median(double[] sortedValues)
    {
        if (sortedValues.Length == 0)
        {
            return null;
        }

        var middle = sortedValues.Length / 2;
        return sortedValues.Length % 2 == 0
            ? Round((sortedValues[middle - 1] + sortedValues[middle]) / 2)
            : sortedValues[middle];
    }

    private sealed class ReplayEventStore : IEventStore
    {
        private readonly List<SecurityEvent> _events = [];

        public IReadOnlyList<SecurityEvent> GetRecent(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
            => _events.AsEnumerable()
                .Where(webEvent => clientIp is null || string.Equals(webEvent.ClientIp, clientIp, StringComparison.Ordinal))
                .Where(webEvent => domain is null || string.Equals(webEvent.Domain, domain, StringComparison.Ordinal))
                .Where(webEvent => !suspiciousOnly || webEvent.IsSuspicious)
                .Reverse()
                .Take(limit)
                .ToArray();

        public void Publish(SecurityEvent webEvent) => _events.Add(webEvent);

        public ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken)
            => throw new NotSupportedException("Subscriptions are not used during offline evaluation.");
    }

    private sealed record ExpandedEvaluationEvent(
        string Id,
        DateTimeOffset Timestamp,
        string Server,
        string Domain,
        string Method,
        string Path,
        string ClientIp,
        int StatusCode,
        string UserAgent,
        IReadOnlyDictionary<string, string> Properties,
        bool ExpectedSuspicious)
    {
        public SecurityEvent ToSecurityEvent() => new(
            Timestamp,
            Server,
            Domain,
            Method,
            Path,
            ClientIp,
            StatusCode,
            UserAgent,
            Properties)
        {
            Id = Id
        };
    }
}

public sealed class EvaluationDataset
{
    public int SchemaVersion { get; init; }
    public string DatasetId { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public List<string> LabelQuality { get; init; } = [];
    public List<EvaluationScenario> Scenarios { get; init; } = [];
}

public sealed class EvaluationScenario
{
    public string Id { get; init; } = string.Empty;
    public string Class { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string? ActivityStartEventId { get; init; }
    public List<EvaluationEvent> Events { get; init; } = [];
}

public sealed class EvaluationEvent
{
    public string Id { get; init; } = string.Empty;
    public DateTimeOffset Timestamp { get; init; }
    public string Server { get; init; } = "eval-web-01";
    public string Domain { get; init; } = "evaluation.invalid";
    public string Method { get; init; } = "GET";
    public string Path { get; init; } = "/";
    public string ClientIp { get; init; } = string.Empty;
    public string[]? ClientIps { get; init; }
    public int StatusCode { get; init; } = 200;
    public string UserAgent { get; init; } = string.Empty;
    public Dictionary<string, string> Properties { get; init; } = [];
    public bool ExpectedSuspicious { get; init; }
    public int Repeat { get; init; } = 1;
    public double IntervalMilliseconds { get; init; }

    public SecurityEvent ToSecurityEvent() => new(
        Timestamp,
        Server,
        Domain,
        Method,
        Path,
        ClientIp,
        StatusCode,
        UserAgent,
        Properties)
    {
        Id = Id
    };
}

public sealed record EvaluationReport(
    int SchemaVersion,
    string DetectorVersion,
    string DetectorRevision,
    string DatasetId,
    string DatasetDescription,
    string DatasetSha256,
    int TotalEvents,
    int ScenarioCount,
    EvaluationMetrics Overall,
    IReadOnlyList<ClassEvaluation> PerClass,
    DetectionLatencySummary DetectionLatency,
    DetectionOptions DetectionOptions,
    IReadOnlyList<string> LabelQuality,
    IReadOnlyList<ScenarioEvaluation> Scenarios,
    EvaluationComparison? Comparison);

public sealed record EvaluationComparison(
    bool SameDataset,
    string BaselineDetectorVersion,
    string CandidateDetectorVersion,
    string? BaselineDetectorRevision,
    string CandidateDetectorRevision,
    string BaselineDatasetSha256,
    string CandidateDatasetSha256,
    MetricDelta Overall,
    IReadOnlyList<ClassMetricDelta> PerClass,
    EventBehaviorDelta EventBehavior)
{
    public static EvaluationComparison Compare(EvaluationReport baseline, EvaluationReport candidate)
    {
        var baselineByClass = baseline.PerClass.ToDictionary(static item => item.Class, StringComparer.Ordinal);
        var candidateByClass = candidate.PerClass.ToDictionary(static item => item.Class, StringComparer.Ordinal);
        var classNames = baselineByClass.Keys.Concat(candidateByClass.Keys).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);
        var classDeltas = classNames.Select(className =>
        {
            var hasBaseline = baselineByClass.TryGetValue(className, out var baselineClass);
            var hasCandidate = candidateByClass.TryGetValue(className, out var candidateClass);
            return new ClassMetricDelta(className, hasBaseline, hasCandidate,
                hasBaseline && hasCandidate ? MetricDelta.Between(baselineClass!.Metrics, candidateClass!.Metrics) : null);
        }).ToArray();

        var baselineEvents = baseline.Scenarios
            .SelectMany(scenario => scenario.Events.Select(webEvent => (Key: (scenario.Id, webEvent.EventId), Event: webEvent)))
            .ToDictionary(static item => item.Key, static item => item.Event);
        var candidateEvents = candidate.Scenarios
            .SelectMany(scenario => scenario.Events.Select(webEvent => (Key: (scenario.Id, webEvent.EventId), Event: webEvent)))
            .ToDictionary(static item => item.Key, static item => item.Event);
        var matchingEventKeys = baselineEvents.Keys.Intersect(candidateEvents.Keys).ToArray();
        var eventBehavior = new EventBehaviorDelta(
            matchingEventKeys.Length,
            baselineEvents.Count - matchingEventKeys.Length,
            candidateEvents.Count - matchingEventKeys.Length,
            matchingEventKeys.Count(key => !baselineEvents[key].Detected && candidateEvents[key].Detected),
            matchingEventKeys.Count(key => baselineEvents[key].Detected && !candidateEvents[key].Detected),
            matchingEventKeys.Count(key => (candidateEvents[key].RiskScore ?? 0) > (baselineEvents[key].RiskScore ?? 0)),
            matchingEventKeys.Count(key => (candidateEvents[key].RiskScore ?? 0) < (baselineEvents[key].RiskScore ?? 0)),
            matchingEventKeys.Count(key => (candidateEvents[key].RiskScore ?? 0) == (baselineEvents[key].RiskScore ?? 0)));

        return new EvaluationComparison(
            string.Equals(baseline.DatasetSha256, candidate.DatasetSha256, StringComparison.Ordinal),
            baseline.DetectorVersion,
            candidate.DetectorVersion,
            baseline.DetectorRevision,
            candidate.DetectorRevision,
            baseline.DatasetSha256,
            candidate.DatasetSha256,
            MetricDelta.Between(baseline.Overall, candidate.Overall),
            classDeltas,
            eventBehavior);
    }
}

public sealed record ClassMetricDelta(string Class, bool InBaseline, bool InCandidate, MetricDelta? Delta);
public sealed record EventBehaviorDelta(
    int ComparedEvents,
    int EventsOnlyInBaseline,
    int EventsOnlyInCandidate,
    int DetectionsAdded,
    int DetectionsRemoved,
    int RiskScoresIncreased,
    int RiskScoresDecreased,
    int RiskScoresUnchanged);
public sealed record MetricDelta(
    int TruePositives,
    int FalsePositives,
    int TrueNegatives,
    int FalseNegatives,
    double? Precision,
    double? Recall,
    double? FalsePositiveRate,
    double? FalseNegativeRate)
{
    public static MetricDelta Between(EvaluationMetrics baseline, EvaluationMetrics candidate) => new(
        candidate.TruePositives - baseline.TruePositives,
        candidate.FalsePositives - baseline.FalsePositives,
        candidate.TrueNegatives - baseline.TrueNegatives,
        candidate.FalseNegatives - baseline.FalseNegatives,
        Difference(baseline.Precision, candidate.Precision),
        Difference(baseline.Recall, candidate.Recall),
        Difference(baseline.FalsePositiveRate, candidate.FalsePositiveRate),
        Difference(baseline.FalseNegativeRate, candidate.FalseNegativeRate));

    private static double? Difference(double? baseline, double? candidate)
        => baseline.HasValue && candidate.HasValue
            ? Math.Round(candidate.Value - baseline.Value, 4, MidpointRounding.AwayFromZero)
            : null;
}

public sealed record EvaluationMetrics(
    int TruePositives,
    int FalsePositives,
    int TrueNegatives,
    int FalseNegatives,
    double? Precision,
    double? Recall,
    double? FalsePositiveRate,
    double? FalseNegativeRate)
{
    public static EvaluationMetrics From(IEnumerable<EventEvaluation> events)
    {
        var counts = events.Aggregate((TruePositives: 0, FalsePositives: 0, TrueNegatives: 0, FalseNegatives: 0),
            static (total, current) => current.ExpectedSuspicious
                ? current.Detected ? total with { TruePositives = total.TruePositives + 1 } : total with { FalseNegatives = total.FalseNegatives + 1 }
                : current.Detected ? total with { FalsePositives = total.FalsePositives + 1 } : total with { TrueNegatives = total.TrueNegatives + 1 });

        return new EvaluationMetrics(counts.TruePositives, counts.FalsePositives, counts.TrueNegatives, counts.FalseNegatives,
            Ratio(counts.TruePositives, counts.TruePositives + counts.FalsePositives),
            Ratio(counts.TruePositives, counts.TruePositives + counts.FalseNegatives),
            Ratio(counts.FalsePositives, counts.FalsePositives + counts.TrueNegatives),
            Ratio(counts.FalseNegatives, counts.FalseNegatives + counts.TruePositives));
    }

    private static double? Ratio(int numerator, int denominator)
        => denominator == 0 ? null : Math.Round((double)numerator / denominator, 4, MidpointRounding.AwayFromZero);
}

public sealed record ClassEvaluation(string Class, EvaluationMetrics Metrics);
public sealed record DetectionLatencySummary(int DetectedScenarios, int UndetectedScenarios, double? MeanMilliseconds, double? MedianMilliseconds);
public sealed record ScenarioEvaluation(
    string Id,
    string Class,
    string Description,
    string? ActivityStartEventId,
    EvaluationMetrics Metrics,
    double? DetectionLatencyMilliseconds,
    IReadOnlyList<EventEvaluation> Events);
public sealed record EventEvaluation(
    string EventId,
    string Class,
    bool ExpectedSuspicious,
    bool Detected,
    int? RiskScore,
    string? RiskSeverity,
    string EvidenceScope,
    string EvidenceStrength,
    int EvidenceFamilyCount,
    IReadOnlyList<EvidenceEvaluation> Evidence,
    IReadOnlyList<string> RiskIndicators);
public sealed record EvidenceEvaluation(
    string Code,
    string Family,
    int ConfiguredWeight,
    int ScoreContribution,
    bool Contributed);