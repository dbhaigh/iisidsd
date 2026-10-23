using System.Diagnostics;
using System.Collections.Concurrent;
using iisidsd.Models;
using iisidsd.Observability;
using Microsoft.Extensions.Options;

namespace iisidsd.Detection;

public sealed class DetectionEngine : ISuspiciousActivityDetector
{
    private const int MaximumModules = 32;
    private const int MaximumSignalsPerEvent = 128;
    private const int MaximumSignalKeysPerModule = 64;
    private const string DefaultReason = "IIS ETW request";

    private readonly IReadOnlyList<ConfiguredModule> _modules;
    private readonly IisObservability? _observability;
    private readonly ILogger<DetectionEngine>? _logger;
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _knownSignalKeys = new(StringComparer.Ordinal);

    public DetectionEngine(
        IEnumerable<IDetectionModule> modules,
        IOptions<DetectionModulesOptions> options,
        IisObservability? observability = null,
        ILogger<DetectionEngine>? logger = null)
    {
        var configuredModules = new List<ConfiguredModule>();
        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var module in modules)
        {
            var descriptor = module.Descriptor;
            if (!DetectionModulesOptions.IsValidId(descriptor.Id) ||
                string.IsNullOrWhiteSpace(descriptor.DisplayName) ||
                string.IsNullOrWhiteSpace(descriptor.ConfigurationSection))
            {
                throw new InvalidOperationException("A detection module has invalid descriptor metadata.");
            }

            if (!seenIds.Add(descriptor.Id))
            {
                throw new InvalidOperationException($"Detection module id '{descriptor.Id}' is registered more than once.");
            }

            var settings = options.Value.Modules.FirstOrDefault(pair =>
                string.Equals(pair.Key, descriptor.Id, StringComparison.OrdinalIgnoreCase)).Value;
            configuredModules.Add(new ConfiguredModule(
                module,
                descriptor,
                settings?.Enabled ?? true,
                settings?.Mode ?? (string.Equals(descriptor.Id, "heuristic", StringComparison.Ordinal)
                    ? DetectionModuleMode.Contribute
                    : DetectionModuleMode.Observe)));
        }

        if (configuredModules.Count is 0 or > MaximumModules)
        {
            throw new InvalidOperationException($"Between 1 and {MaximumModules} detection modules must be registered.");
        }

        var registeredIds = configuredModules.Select(static module => module.Descriptor.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var unknownConfiguredIds = options.Value.Modules.Keys.Where(id => !registeredIds.Contains(id)).ToArray();
        if (unknownConfiguredIds.Length > 0)
        {
            throw new InvalidOperationException(
                $"Detection module configuration references unregistered module(s): {string.Join(", ", unknownConfiguredIds)}.");
        }

        _modules = configuredModules.OrderBy(static module => module.Descriptor.Id, StringComparer.Ordinal).ToArray();
        _observability = observability;
        _logger = logger;
        foreach (var module in _modules)
        {
            _knownSignalKeys[module.Descriptor.Id] = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
            _observability?.ConfigureDetectionModule(
                module.Descriptor.Id,
                module.Enabled,
                module.Mode.ToString().ToLowerInvariant());
        }
    }

    public SecurityEvent? Analyze(SecurityEvent webEvent) => AnalyzeDetailed(webEvent).Event;

    public DetectionAssessment AnalyzeDetailed(SecurityEvent webEvent)
    {
        ArgumentNullException.ThrowIfNull(webEvent);
        var matches = new List<ModuleSignal>();
        foreach (var module in _modules)
        {
            if (!module.Enabled) continue;
            var startedAt = Stopwatch.GetTimestamp();
            var signalKeys = Array.Empty<string>();
            string? failureType = null;
            try
            {
                var signals = module.Module.Detect(webEvent)
                    ?? throw new InvalidOperationException("A detection module returned a null signal collection.");
                if (signals.Count > MaximumSignalsPerEvent)
                {
                    throw new InvalidOperationException("A detection module exceeded the per-event signal limit.");
                }

                var moduleKeys = new HashSet<string>(StringComparer.Ordinal);
                for (var order = 0; order < signals.Count; order++)
                {
                    var signal = signals[order];
                    ValidateSignal(signal, module.Descriptor.Id);
                    if (!moduleKeys.Add(signal.Key))
                    {
                        throw new InvalidOperationException("A detection module returned a duplicate signal key for one event.");
                    }

                    var knownKeys = _knownSignalKeys[module.Descriptor.Id];
                    knownKeys.TryAdd(signal.Key, 0);
                    if (knownKeys.Count > MaximumSignalKeysPerModule)
                    {
                        knownKeys.TryRemove(signal.Key, out _);
                        throw new InvalidOperationException("A detection module exceeded the stable signal-key limit.");
                    }

                    matches.Add(new ModuleSignal(module, signal, order));
                }

                signalKeys = moduleKeys.Order(StringComparer.Ordinal).ToArray();
            }
            catch (Exception exception)
            {
                failureType = exception.GetType().Name;
                matches.RemoveAll(match => string.Equals(match.Module.Descriptor.Id, module.Descriptor.Id, StringComparison.Ordinal));
                _logger?.LogWarning(
                    "Detection module {DetectorId} failed. FailureType={FailureType}",
                    module.Descriptor.Id,
                    exception.GetType().Name);
            }
            finally
            {
                _observability?.RecordDetectionModuleEvaluation(
                    module.Descriptor.Id,
                    module.Enabled,
                    module.Mode.ToString().ToLowerInvariant(),
                    Stopwatch.GetElapsedTime(startedAt),
                    signalKeys,
                    failureType);
            }
        }

        var contributingMatches = matches
            .Where(static match => match.Module.Mode == DetectionModuleMode.Contribute)
            .GroupBy(static match => match.Signal.CorrelationKey ?? $"{match.Module.Descriptor.Id}:{match.Signal.Key}", StringComparer.Ordinal)
            .Select(static group => group
                .OrderByDescending(static match => match.Signal.Weight)
                .ThenByDescending(static match => match.Signal.FamilyPriority)
                .ThenBy(static match => match.Module.Descriptor.Id, StringComparer.Ordinal)
                .ThenBy(static match => match.Signal.Key, StringComparer.Ordinal)
                .First())
            .GroupBy(static match => match.Signal.Family)
            .Select(static group => group
                .OrderByDescending(static match => match.Signal.Weight)
                .ThenByDescending(static match => match.Signal.FamilyPriority)
                .ThenBy(static match => match.Module.Descriptor.Id, StringComparer.Ordinal)
                .ThenBy(static match => match.Order)
                .ThenBy(static match => match.Signal.Key, StringComparer.Ordinal)
                .First())
            .ToHashSet();

        var evidence = matches
            .OrderBy(static match => match.Module.Descriptor.Id, StringComparer.Ordinal)
            .ThenBy(static match => match.Order)
            .ThenBy(static match => match.Signal.Key, StringComparer.Ordinal)
            .Select(match => new DetectionEvidence(
                match.Signal.Code,
                match.Signal.Family,
                match.Signal.Indicator,
                match.Signal.Weight,
                contributingMatches.Contains(match) ? match.Signal.Weight : 0,
                contributingMatches.Contains(match),
                DetectorId: match.Module.Descriptor.Id,
                SignalKey: match.Signal.Key,
                CorrelationKey: match.Signal.CorrelationKey,
                Explanation: match.Signal.Explanation,
                Reason: match.Signal.Reason,
                ReasonOnlyWhenGeneric: match.Signal.ReasonOnlyWhenGeneric,
                RepeatedBehavior: match.Signal.RepeatedBehavior,
                FamilyPriority: match.Signal.FamilyPriority,
                Order: match.Order,
                ObserveOnly: match.Module.Mode == DetectionModuleMode.Observe))
            .ToArray();

        long score = 0;
        foreach (var signal in evidence.Where(static signal => signal.Contributed))
        {
            score = Math.Min(int.MaxValue, score + signal.ScoreContribution);
        }

        if (score == 0)
        {
            return new DetectionAssessment(null, DetectionEvidenceScope.None, DetectionEvidenceStrength.None, 0, evidence);
        }

        var contributingSignals = evidence.Where(static signal => signal.Contributed).ToArray();
        var familyCount = contributingSignals.Select(static signal => signal.Family).Distinct().Count();
        var hasRepeatedBehavior = contributingSignals.Any(static signal => signal.RepeatedBehavior);
        var hasSingleRequestEvidence = contributingSignals.Any(static signal => !signal.RepeatedBehavior);
        var scope = hasRepeatedBehavior
            ? hasSingleRequestEvidence ? DetectionEvidenceScope.CorrelatedAttackSequence : DetectionEvidenceScope.RepeatedBehavior
            : DetectionEvidenceScope.SingleRequest;
        var strength = familyCount switch
        {
            <= 1 => DetectionEvidenceStrength.Limited,
            2 => DetectionEvidenceStrength.Supported,
            _ => DetectionEvidenceStrength.Corroborated
        };
        var reason = DefaultReason;
        foreach (var signal in contributingSignals.OrderBy(static signal => signal.DetectorId, StringComparer.Ordinal)
                     .ThenBy(static signal => signal.Order))
        {
            if (signal.Reason is { } signalReason &&
                (!signal.ReasonOnlyWhenGeneric || reason is DefaultReason or "probing/error response"))
            {
                reason = signalReason;
            }
        }

        var riskScore = (int)score;
        var detectedEvent = webEvent with
        {
            IsSuspicious = true,
            DetectionReason = reason,
            RiskScore = riskScore,
            RiskSeverity = GetSeverity(riskScore),
            DetectionEvidence = evidence,
            RiskIndicators = contributingSignals
                .OrderBy(static signal => signal.DetectorId, StringComparer.Ordinal)
                .ThenBy(static signal => signal.Order)
                .Select(static signal => signal.Indicator)
                .Distinct(StringComparer.Ordinal)
                .ToArray()
        };

        return new DetectionAssessment(detectedEvent, scope, strength, familyCount, evidence);
    }

    private static void ValidateSignal(DetectionSignal? signal, string moduleId)
    {
        if (signal is null ||
            !Enum.IsDefined(signal.Code) ||
            !Enum.IsDefined(signal.Family) ||
            signal.Weight < 0 ||
            !IsValidSignalKey(signal.Key) ||
            signal.CorrelationKey is { } correlationKey && !IsValidSignalKey(correlationKey) ||
            string.IsNullOrWhiteSpace(signal.Indicator) || signal.Indicator.Length > 256 ||
            string.IsNullOrWhiteSpace(signal.Explanation) || signal.Explanation.Length > 512 ||
            string.IsNullOrWhiteSpace(signal.Reason) || signal.Reason.Length > 256)
        {
            throw new InvalidOperationException($"Detection module '{moduleId}' returned invalid signal data.");
        }
    }

    private static bool IsValidSignalKey(string value)
        => value.Length is > 0 and <= 64 &&
            value.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_');

    private static string GetSeverity(int score) => score switch
    {
        >= 8 => "Critical",
        >= 4 => "High",
        >= 1 => "Medium",
        _ => "Low"
    };

    private sealed record ConfiguredModule(
        IDetectionModule Module,
        DetectionModuleDescriptor Descriptor,
        bool Enabled,
        DetectionModuleMode Mode);

    private sealed record ModuleSignal(ConfiguredModule Module, DetectionSignal Signal, int Order);
}