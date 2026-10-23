using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text;
using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Storage;

namespace iisidsd.Observability;

public sealed class IisObservability : IDisposable
{
    public const string MeterName = "iisidsd";

    private static readonly double[] DurationBucketBounds =
    [
        0.001,
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1,
        2.5,
        5,
        10
    ];

    private static readonly double[] PipelineLatencyBucketBounds =
    [
        0.001,
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1,
        2.5,
        5,
        10,
        30,
        60
    ];

    private static readonly double[] RiskScoreBucketBounds = [0, 1, 2, 3, 5, 8, 10, 15, 20, 50];
    private static readonly double[] DetectionIndicatorBucketBounds = [0, 1, 2, 3, 5, 10];
    private static readonly string[] SeverityNames = ["low", "medium", "high", "critical", "other"];

    private readonly Meter _meter = new(MeterName, "1.0.0");
    private readonly Counter<long> _etwEventsReceived;
    private readonly Counter<long> _etwEventsAccepted;
    private readonly Counter<long> _etwEventsDropped;
    private readonly Counter<long> _etwEventsMalformed;
    private readonly Counter<long> _eventsProcessed;
    private readonly Counter<long> _eventProcessingFailures;
    private readonly Counter<long> _eventProcessingRetries;
    private readonly Counter<long> _sqliteWriteFailures;
    private readonly Counter<long> _sqliteBusyFailures;
    private readonly Counter<long> _sqliteCorruptionFailures;
    private readonly Counter<long> _sqliteDiskFullFailures;
    private readonly Counter<long> _autoDenyFailures;
    private readonly Counter<long> _suspiciousEvents;
    private readonly Counter<long> _autoDenies;
    private readonly Counter<long> _detectionHistoryPruned;
    private readonly Counter<long> _detectionHistoryCapacityRejections;
    private readonly Counter<long> _detectionPathCapacityRejections;
    private readonly Counter<long> _outOfOrderDetectionEvents;
    private readonly Counter<long> _detectionClockResets;
    private readonly Counter<long> _extensionCacheCapacityRejections;
    private readonly Histogram<double> _sqliteWriteDuration;
    private readonly Histogram<double> _eventPipelineLatency;
    private readonly Counter<long> _detectionEventsAnalyzed;
    private readonly Counter<long> _detectionIndicators;
    private readonly Counter<long> _detectionEventsBySeverity;
    private readonly Histogram<double> _detectionRiskScore;
    private readonly Histogram<double> _detectionIndicatorCount;
    private readonly Counter<long> _detectionModuleEvaluations;
    private readonly Counter<long> _detectionModuleFailures;
    private readonly Counter<long> _detectionModuleSignals;
    private readonly Histogram<double> _detectionModuleProcessingDuration;
    private readonly Counter<long> _eventStreamConnections;
    private readonly Counter<long> _eventStreamFailures;
    private readonly Counter<long> _eventRetentionRuns;
    private readonly Counter<long> _eventRetentionEventsPruned;
    private readonly Counter<long> _eventRetentionFailures;
    private readonly Counter<long> _iisAdministrationFailures;
    private readonly Counter<long> _expiryCleanupCandidates;
    private readonly Counter<long> _expiryCleanupSucceeded;
    private readonly Counter<long> _expiryCleanupSimulated;
    private readonly Counter<long> _expiryCleanupFailed;
    private readonly Counter<long> _recoveryAttempts;
    private readonly Counter<long> _fatalErrors;
    private readonly long[] _durationBucketCounts = new long[DurationBucketBounds.Length];
    private readonly long[] _pipelineLatencyBucketCounts = new long[PipelineLatencyBucketBounds.Length];
    private readonly long[] _riskScoreBucketCounts = new long[RiskScoreBucketBounds.Length];
    private readonly long[] _detectionIndicatorBucketCounts = new long[DetectionIndicatorBucketBounds.Length];
    private readonly long[] _detectionSeverityCounts = new long[SeverityNames.Length];
    private readonly object _recentEventsSync = new();
    private readonly ConcurrentDictionary<string, DetectionModuleHealthSnapshot> _detectionModules = new(StringComparer.Ordinal);
    private readonly Queue<RecentOperationalEvent> _recentOperationalEvents = new();
    private readonly DateTimeOffset _startedAtUtc = DateTimeOffset.UtcNow;
    private long _etwEventsReceivedCount;
    private long _etwEventsAcceptedCount;
    private long _etwEventsDroppedCount;
    private long _etwEventsMalformedCount;
    private long _eventsProcessedCount;
    private long _eventProcessingFailureCount;
    private long _eventProcessingRetryCount;
    private long _sqliteWriteFailureCount;
    private long _sqliteBusyFailureCount;
    private long _sqliteCorruptionFailureCount;
    private long _sqliteDiskFullFailureCount;
    private long _autoDenyFailureCount;
    private long _suspiciousEventsCount;
    private long _autoDeniesCount;
    private long _detectionHistoryPrunedCount;
    private long _detectionHistoryCapacityRejectionCount;
    private long _detectionPathCapacityRejectionCount;
    private long _outOfOrderDetectionEventCount;
    private long _detectionClockResetCount;
    private long _extensionCacheCapacityRejectionCount;
    private long _trackedDetectionHistories;
    private long _trackedHistoryBuckets;
    private long _trackedExtensionSites;
    private long _trackedPathTokens;
    private long _queueDepth;
    private long _queueHighWaterMark;
    private long _lastEventTimestampTicks;
    private long _sqliteWriteDurationCount;
    private long _sqliteWriteDurationTicks;
    private long _pipelineLatencyCount;
    private long _pipelineLatencyTicks;
    private long _detectionEventsAnalyzedCount;
    private long _detectionIndicatorsCount;
    private long _detectionRiskScoreSum;
    private long _eventStreamActiveClientCount;
    private long _eventStreamConnectionCount;
    private long _eventStreamFailureCount;
    private long _eventRetentionRunCount;
    private long _eventRetentionPrunedCount;
    private long _eventRetentionFailureCount;
    private long _iisAdministrationFailureCount;
    private long _expiryCleanupCandidateCount;
    private long _expiryCleanupSucceededCount;
    private long _expiryCleanupSimulatedCount;
    private long _expiryCleanupFailureCount;
    private long _recoveryAttemptCount;
    private long _fatalErrorCount;
    private long _queueCapacity;
    private long _etwSubscriptionState;
    private long _etwSubscriptionChangedAtTicks;
    private long _lastRetentionAtTicks;
    private long _lastEnforcementAtTicks;
    private string? _lastEnforcementOutcome;
    private bool? _lastEnforcementSimulation;

    public IisObservability()
    {
        _etwEventsReceived = _meter.CreateCounter<long>("etw_events_received", "{event}", "ETW events received.");
        _etwEventsAccepted = _meter.CreateCounter<long>("etw_events_accepted", "{event}", "ETW events accepted into the bounded ingestion queue.");
        _etwEventsDropped = _meter.CreateCounter<long>("etw_events_dropped", "{event}", "ETW events dropped from the ingestion queue.");
        _etwEventsMalformed = _meter.CreateCounter<long>("etw_events_malformed", "{event}", "Malformed ETW events rejected before queueing.");
        _eventsProcessed = _meter.CreateCounter<long>("events_processed", "{event}", "ETW events successfully persisted.");
        _eventProcessingFailures = _meter.CreateCounter<long>("event_processing_failures", "{event}", "ETW events that could not be processed.");
        _eventProcessingRetries = _meter.CreateCounter<long>("event_processing_retries", "{retry}", "Retries while persisting queued ETW events.");
        _sqliteWriteFailures = _meter.CreateCounter<long>("sqlite_write_failures", "{failure}", "SQLite write failures.");
        _sqliteBusyFailures = _meter.CreateCounter<long>("sqlite_busy_failures", "{failure}", "SQLite busy or locked failures.");
        _sqliteCorruptionFailures = _meter.CreateCounter<long>("sqlite_corruption_failures", "{failure}", "SQLite corruption or invalid-database failures.");
        _sqliteDiskFullFailures = _meter.CreateCounter<long>("sqlite_disk_full_failures", "{failure}", "SQLite disk-full failures.");
        _autoDenyFailures = _meter.CreateCounter<long>("auto_deny_failures", "{event}", "Automatic IIS actions that failed after event persistence.");
        _suspiciousEvents = _meter.CreateCounter<long>("suspicious_events", "{event}", "Suspicious events successfully persisted.");
        _autoDenies = _meter.CreateCounter<long>("auto_denies", "{action}", "Automatic deny-list actions successfully applied.");
        _detectionHistoryPruned = _meter.CreateCounter<long>("detection_history_pruned", "{history}", "Inactive in-memory detector histories pruned.");
        _detectionHistoryCapacityRejections = _meter.CreateCounter<long>("detection_history_capacity_rejections", "{history}", "New detector histories rejected at configured capacity.");
        _detectionPathCapacityRejections = _meter.CreateCounter<long>("detection_path_capacity_rejections", "{path}", "New unique path tokens rejected at configured capacity.");
        _outOfOrderDetectionEvents = _meter.CreateCounter<long>("detection_events_out_of_order", "{event}", "Events skipped because they exceeded the allowed lateness.");
        _detectionClockResets = _meter.CreateCounter<long>("detection_clock_resets", "{reset}", "In-memory detector windows reset after a system clock rollback.");
        _extensionCacheCapacityRejections = _meter.CreateCounter<long>("detection_extension_cache_capacity_rejections", "{entry}", "Site extension-cache admission or learning rejected at configured capacity.");
        _sqliteWriteDuration = _meter.CreateHistogram<double>("sqlite_write_duration", "s", "Duration of SQLite event writes.");
        _eventPipelineLatency = _meter.CreateHistogram<double>("etw_pipeline_latency", "s", "Time from callback reception to successful event persistence.");
        _detectionEventsAnalyzed = _meter.CreateCounter<long>("detection_events_analyzed", "{event}", "Events successfully analyzed by the detector.");
        _detectionIndicators = _meter.CreateCounter<long>("detection_indicators", "{indicator}", "Risk indicators produced by detector analysis.");
        _detectionEventsBySeverity = _meter.CreateCounter<long>("detection_events_by_severity", "{event}", "Analyzed events by fixed risk severity.");
        _detectionRiskScore = _meter.CreateHistogram<double>("detection_risk_score", "{score}", "Risk score distribution for analyzed events.");
        _detectionIndicatorCount = _meter.CreateHistogram<double>("detection_indicator_count", "{indicator}", "Indicator count distribution per analyzed event.");
        _detectionModuleEvaluations = _meter.CreateCounter<long>("detection_module_evaluations", "{evaluation}", "Events evaluated by a detector module.");
        _detectionModuleFailures = _meter.CreateCounter<long>("detection_module_failures", "{failure}", "Detector module evaluations that failed.");
        _detectionModuleSignals = _meter.CreateCounter<long>("detection_module_signals", "{signal}", "Signals returned by detector modules, including observation-only signals.");
        _detectionModuleProcessingDuration = _meter.CreateHistogram<double>("detection_module_processing_duration", "ms", "Detector module processing time per event.");
        _eventStreamConnections = _meter.CreateCounter<long>("event_stream_connections", "{connection}", "Event stream clients connected.");
        _eventStreamFailures = _meter.CreateCounter<long>("event_stream_failures", "{failure}", "Event stream failures.");
        _eventRetentionRuns = _meter.CreateCounter<long>("event_retention_runs", "{run}", "Event retention runs completed.");
        _eventRetentionEventsPruned = _meter.CreateCounter<long>("event_retention_events_pruned", "{event}", "Events deleted by retention.");
        _eventRetentionFailures = _meter.CreateCounter<long>("event_retention_failures", "{failure}", "Event retention runs that failed.");
        _iisAdministrationFailures = _meter.CreateCounter<long>("iis_administration_failures", "{failure}", "IIS administration operations that failed.");
        _expiryCleanupCandidates = _meter.CreateCounter<long>("iis_expiry_cleanup_candidates", "{entry}", "Expired deny-list entries considered by cleanup.");
        _expiryCleanupSucceeded = _meter.CreateCounter<long>("iis_expiry_cleanup_succeeded", "{entry}", "Expired deny-list entries removed successfully.");
        _expiryCleanupSimulated = _meter.CreateCounter<long>("iis_expiry_cleanup_simulated", "{entry}", "Expired deny-list entries simulated without IIS changes.");
        _expiryCleanupFailed = _meter.CreateCounter<long>("iis_expiry_cleanup_failed", "{failure}", "Expired deny-list entries that could not be removed.");
        _recoveryAttempts = _meter.CreateCounter<long>("recovery_attempts", "{attempt}", "Background recovery attempts.");
        _fatalErrors = _meter.CreateCounter<long>("fatal_errors", "{error}", "Fatal background or process errors recorded.");
        _meter.CreateObservableGauge("queue_depth", () => QueueDepth, "{event}", "Current ETW ingestion queue depth.");
        _meter.CreateObservableGauge("queue_capacity", () => QueueCapacity, "{event}", "Configured ETW ingestion queue capacity.");
        _meter.CreateObservableGauge("queue_high_water_mark", () => QueueHighWaterMark, "{event}", "Maximum ETW ingestion queue depth in this process.");
        _meter.CreateObservableGauge("event_stream_active_clients", () => ActiveEventStreamClients, "{client}", "Current active event stream clients.");
        _meter.CreateObservableGauge("etw_subscription_state", GetEtwSubscriptionStateMeasurements, "{state}", "Current ETW subscription lifecycle state.");
        _meter.CreateObservableGauge("detection_client_histories", () => Interlocked.Read(ref _trackedDetectionHistories), "{history}", "Current in-memory detector client/site histories.");
        _meter.CreateObservableGauge("detection_history_buckets", () => Interlocked.Read(ref _trackedHistoryBuckets), "{bucket}", "Current in-memory detector event-time buckets.");
        _meter.CreateObservableGauge("detection_extension_sites", () => Interlocked.Read(ref _trackedExtensionSites), "{site}", "Current in-memory detector site extension caches.");
        _meter.CreateObservableGauge("detection_path_tokens", () => Interlocked.Read(ref _trackedPathTokens), "{path}", "Current hashed unique paths retained by detector windows.");
        _meter.CreateObservableGauge(
            "last_event_timestamp_seconds",
            () => LastEventTimestamp?.ToUnixTimeMilliseconds() / 1000d ?? 0,
            "s",
            "Unix timestamp of the last successfully processed event.");
    }

    public long EtwEventsDropped => Interlocked.Read(ref _etwEventsDroppedCount);
    public long QueueDepth => Interlocked.Read(ref _queueDepth);
    public long QueueHighWaterMark => Interlocked.Read(ref _queueHighWaterMark);
    public long EtwEventsAccepted => Interlocked.Read(ref _etwEventsAcceptedCount);
    public long EtwEventsMalformed => Interlocked.Read(ref _etwEventsMalformedCount);
    public long EventsProcessed => Interlocked.Read(ref _eventsProcessedCount);
    public long EventProcessingFailures => Interlocked.Read(ref _eventProcessingFailureCount);
    public long EventProcessingRetries => Interlocked.Read(ref _eventProcessingRetryCount);
    public long AutoDenyFailures => Interlocked.Read(ref _autoDenyFailureCount);
    public long QueueCapacity => Interlocked.Read(ref _queueCapacity);
    public long ActiveEventStreamClients => Interlocked.Read(ref _eventStreamActiveClientCount);
    public EtwSubscriptionState EtwSubscriptionState
        => (EtwSubscriptionState)Interlocked.Read(ref _etwSubscriptionState);
    public DateTimeOffset? EtwSubscriptionChangedAtUtc
    {
        get
        {
            var ticks = Interlocked.Read(ref _etwSubscriptionChangedAtTicks);
            return ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
        }
    }

    public OperationalDiagnosticsSnapshot GetOperationalDiagnosticsSnapshot(string version, string configurationRevision)
    {
        string? lastEnforcementOutcome;
        bool? lastEnforcementSimulation;
        lock (_recentEventsSync)
        {
            lastEnforcementOutcome = _lastEnforcementOutcome;
            lastEnforcementSimulation = _lastEnforcementSimulation;
        }

        var enforcementTicks = Interlocked.Read(ref _lastEnforcementAtTicks);
        var retentionTicks = Interlocked.Read(ref _lastRetentionAtTicks);
        return new OperationalDiagnosticsSnapshot(
            _startedAtUtc,
            Math.Max(0, (DateTimeOffset.UtcNow - _startedAtUtc).TotalSeconds),
            version,
            configurationRevision,
            EtwSubscriptionState.ToString().ToLowerInvariant(),
            EtwSubscriptionChangedAtUtc,
            LastEventTimestamp,
            QueueDepth,
            checked((int)QueueCapacity),
            QueueHighWaterMark,
            Interlocked.Read(ref _etwEventsReceivedCount),
            Interlocked.Read(ref _etwEventsAcceptedCount),
            Interlocked.Read(ref _etwEventsDroppedCount),
            Interlocked.Read(ref _etwEventsMalformedCount),
            Interlocked.Read(ref _eventsProcessedCount),
            Interlocked.Read(ref _eventProcessingFailureCount),
            Interlocked.Read(ref _eventProcessingRetryCount),
            Interlocked.Read(ref _detectionEventsAnalyzedCount),
            Interlocked.Read(ref _detectionIndicatorsCount),
            GetDetectionSeverityCounts(),
            ActiveEventStreamClients,
            Interlocked.Read(ref _eventStreamConnectionCount),
            Interlocked.Read(ref _eventStreamFailureCount),
            Interlocked.Read(ref _sqliteWriteFailureCount),
            Interlocked.Read(ref _sqliteBusyFailureCount),
            Interlocked.Read(ref _sqliteCorruptionFailureCount),
            Interlocked.Read(ref _sqliteDiskFullFailureCount),
            Interlocked.Read(ref _eventRetentionRunCount),
            Interlocked.Read(ref _eventRetentionPrunedCount),
            Interlocked.Read(ref _eventRetentionFailureCount),
            retentionTicks == 0 ? null : new DateTimeOffset(retentionTicks, TimeSpan.Zero),
            Interlocked.Read(ref _iisAdministrationFailureCount),
            Interlocked.Read(ref _expiryCleanupCandidateCount),
            Interlocked.Read(ref _expiryCleanupSucceededCount),
            Interlocked.Read(ref _expiryCleanupSimulatedCount),
            Interlocked.Read(ref _expiryCleanupFailureCount),
            Interlocked.Read(ref _recoveryAttemptCount),
            Interlocked.Read(ref _fatalErrorCount),
            lastEnforcementOutcome,
            enforcementTicks == 0 ? null : new DateTimeOffset(enforcementTicks, TimeSpan.Zero),
            lastEnforcementSimulation,
            GetRecentOperationalEvents(),
            GetDetectionModuleHealthSnapshots());
    }

    public void ConfigureDetectionModule(string detectorId, bool enabled, string mode)
    {
        _detectionModules.AddOrUpdate(
            detectorId,
            _ => new DetectionModuleHealthSnapshot(
                detectorId, enabled, mode, enabled ? "not-run" : "disabled", 0, 0, null, null, null,
                new Dictionary<string, long>(StringComparer.Ordinal)),
            (_, current) => current with
            {
                Enabled = enabled,
                Mode = mode,
                Status = enabled && current.EvaluationCount == 0 ? "not-run" : enabled ? current.Status : "disabled"
            });
    }

    public void RecordDetectionModuleEvaluation(
        string detectorId,
        bool enabled,
        string mode,
        TimeSpan duration,
        IReadOnlyList<string> signalKeys,
        string? failureType)
    {
        var elapsedMilliseconds = Math.Max(0, duration.TotalMilliseconds);
        var tags = new TagList { { "detector", detectorId } };
        _detectionModuleEvaluations.Add(1, tags);
        _detectionModuleProcessingDuration.Record(elapsedMilliseconds, tags);
        if (failureType is not null) _detectionModuleFailures.Add(1, tags);
        foreach (var signalKey in signalKeys.Distinct(StringComparer.Ordinal))
        {
            _detectionModuleSignals.Add(1, new TagList { { "detector", detectorId }, { "signal", signalKey } });
        }

        var evaluatedAt = DateTimeOffset.UtcNow;
        _detectionModules.AddOrUpdate(
            detectorId,
            _ => CreateEvaluatedModuleHealth(detectorId, enabled, mode, elapsedMilliseconds, evaluatedAt, signalKeys, failureType),
            (_, current) =>
            {
                var signalCounts = new Dictionary<string, long>(current.SignalCounts, StringComparer.Ordinal);
                foreach (var signalKey in signalKeys.Distinct(StringComparer.Ordinal))
                {
                    signalCounts[signalKey] = signalCounts.GetValueOrDefault(signalKey) + 1;
                }

                return current with
                {
                    Enabled = enabled,
                    Mode = mode,
                    Status = failureType is null ? "healthy" : "degraded",
                    EvaluationCount = current.EvaluationCount + 1,
                    FailureCount = current.FailureCount + (failureType is null ? 0 : 1),
                    LastEvaluatedAtUtc = evaluatedAt,
                    LastProcessingMilliseconds = elapsedMilliseconds,
                    LastFailureType = failureType,
                    SignalCounts = signalCounts
                };
            });
    }

    private static DetectionModuleHealthSnapshot CreateEvaluatedModuleHealth(
        string detectorId,
        bool enabled,
        string mode,
        double elapsedMilliseconds,
        DateTimeOffset evaluatedAt,
        IReadOnlyList<string> signalKeys,
        string? failureType)
        => new(
            detectorId,
            enabled,
            mode,
            failureType is null ? "healthy" : "degraded",
            1,
            failureType is null ? 0 : 1,
            evaluatedAt,
            elapsedMilliseconds,
            failureType,
            signalKeys.Distinct(StringComparer.Ordinal)
                .ToDictionary(static signalKey => signalKey, static _ => 1L, StringComparer.Ordinal));

    private IReadOnlyList<DetectionModuleHealthSnapshot> GetDetectionModuleHealthSnapshots()
        => _detectionModules.Values.OrderBy(static module => module.Id, StringComparer.Ordinal).ToArray();

    public void SetQueueCapacity(int capacity)
        => Interlocked.Exchange(ref _queueCapacity, Math.Max(0, capacity));

    public void SetEtwSubscriptionState(EtwSubscriptionState state)
    {
        Interlocked.Exchange(ref _etwSubscriptionState, (long)state);
        Interlocked.Exchange(ref _etwSubscriptionChangedAtTicks, DateTimeOffset.UtcNow.UtcDateTime.Ticks);
    }

    public void RecordDetectionAnalyzed(SecurityEvent webEvent)
    {
        Interlocked.Increment(ref _detectionEventsAnalyzedCount);
        _detectionEventsAnalyzed.Add(1);
        var indicatorCount = webEvent.RiskIndicators?.Distinct(StringComparer.Ordinal).Count() ?? 0;
        Interlocked.Add(ref _detectionIndicatorsCount, indicatorCount);
        if (indicatorCount > 0) _detectionIndicators.Add(indicatorCount);
        _detectionIndicatorCount.Record(indicatorCount);

        var score = Math.Max(0, webEvent.RiskScore);
        _detectionRiskScore.Record(score);
        Interlocked.Add(ref _detectionRiskScoreSum, score);
        for (var index = 0; index < RiskScoreBucketBounds.Length; index++)
        {
            if (score <= RiskScoreBucketBounds[index]) Interlocked.Increment(ref _riskScoreBucketCounts[index]);
        }

        for (var index = 0; index < DetectionIndicatorBucketBounds.Length; index++)
        {
            if (indicatorCount <= DetectionIndicatorBucketBounds[index]) Interlocked.Increment(ref _detectionIndicatorBucketCounts[index]);
        }

        var severity = GetSeverityIndex(webEvent.RiskSeverity);
        Interlocked.Increment(ref _detectionSeverityCounts[severity]);
        _detectionEventsBySeverity.Add(1, new KeyValuePair<string, object?>("severity", SeverityNames[severity]));
    }

    public void RecordEventStreamStarted()
    {
        Interlocked.Increment(ref _eventStreamActiveClientCount);
        Interlocked.Increment(ref _eventStreamConnectionCount);
        _eventStreamConnections.Add(1);
    }

    public void RecordEventStreamEnded()
    {
        var remaining = Interlocked.Decrement(ref _eventStreamActiveClientCount);
        if (remaining < 0) Interlocked.Exchange(ref _eventStreamActiveClientCount, 0);
    }

    public void RecordEventStreamFailure()
    {
        Interlocked.Increment(ref _eventStreamFailureCount);
        _eventStreamFailures.Add(1);
    }

    public void RecordEventRetentionRun(int? prunedCount)
    {
        Interlocked.Increment(ref _eventRetentionRunCount);
        Interlocked.Exchange(ref _lastRetentionAtTicks, DateTimeOffset.UtcNow.UtcDateTime.Ticks);
        _eventRetentionRuns.Add(1);
        if (prunedCount is null)
        {
            Interlocked.Increment(ref _eventRetentionFailureCount);
            _eventRetentionFailures.Add(1);
            return;
        }

        if (prunedCount > 0)
        {
            Interlocked.Add(ref _eventRetentionPrunedCount, prunedCount.Value);
            _eventRetentionEventsPruned.Add(prunedCount.Value);
        }
    }

    public void RecordIisEnforcementOutcome(string outcome, bool simulation)
    {
        var safeOutcome = outcome switch
        {
            "succeeded" or "failed" or "simulated" or "observed" or "recovery-required" or
            "expired" or "expired-already-removed" or "simulated-expiry" or "skipped-allow-list" or
            "no-matching-sites" or "no-target-domains" or "already-managed" or "pre-existing-unmanaged" or
            "existing-allow-rule" or "not-found" or "already-removed" or "skipped-not-service-owned" or
            "skipped-concurrent-change" or "reverted" => outcome,
            _ => "other"
        };
        lock (_recentEventsSync)
        {
            _lastEnforcementOutcome = safeOutcome;
            _lastEnforcementSimulation = simulation;
            Interlocked.Exchange(ref _lastEnforcementAtTicks, DateTimeOffset.UtcNow.UtcDateTime.Ticks);
        }

        if (safeOutcome is "failed" or "recovery-required")
        {
            Interlocked.Increment(ref _iisAdministrationFailureCount);
            _iisAdministrationFailures.Add(1);
        }
    }

    public void RecordExpiryCleanupCandidate()
    {
        Interlocked.Increment(ref _expiryCleanupCandidateCount);
        _expiryCleanupCandidates.Add(1);
    }

    public void RecordExpiryCleanupSucceeded()
    {
        Interlocked.Increment(ref _expiryCleanupSucceededCount);
        _expiryCleanupSucceeded.Add(1);
    }

    public void RecordExpiryCleanupSimulated()
    {
        Interlocked.Increment(ref _expiryCleanupSimulatedCount);
        _expiryCleanupSimulated.Add(1);
    }

    public void RecordExpiryCleanupFailure()
    {
        Interlocked.Increment(ref _expiryCleanupFailureCount);
        _expiryCleanupFailed.Add(1);
    }

    public void RecordRecoveryAttempt(string component, string failureType = "unknown")
    {
        Interlocked.Increment(ref _recoveryAttemptCount);
        _recoveryAttempts.Add(1);
        AddRecentOperationalEvent(component, "recovery", failureType);
    }

    public void RecordFatalError(string component, string failureType = "unknown")
    {
        Interlocked.Increment(ref _fatalErrorCount);
        _fatalErrors.Add(1);
        AddRecentOperationalEvent(component, "fatal", failureType);
    }

    private RecentOperationalEvent[] GetRecentOperationalEvents()
    {
        lock (_recentEventsSync)
        {
            return _recentOperationalEvents.ToArray();
        }
    }

    private void AddRecentOperationalEvent(string component, string kind, string failureType)
    {
        var safeComponent = component switch
        {
            "etw" or "sqlite" or "iis" or "retention" or "expiry" or "event-stream" or "runtime" => component,
            _ => "other"
        };
        var safeFailureType = string.IsNullOrWhiteSpace(failureType) || failureType.Length > 64 ||
                              failureType.Any(character => !char.IsAsciiLetterOrDigit(character))
            ? "unknown"
            : failureType;
        lock (_recentEventsSync)
        {
            _recentOperationalEvents.Enqueue(new RecentOperationalEvent(
                DateTimeOffset.UtcNow,
                safeComponent,
                kind,
                safeFailureType));
            while (_recentOperationalEvents.Count > 20) _recentOperationalEvents.Dequeue();
        }
    }

    private static int GetSeverityIndex(string? severity)
        => severity?.ToLowerInvariant() switch
        {
            "low" => 0,
            "medium" => 1,
            "high" => 2,
            "critical" => 3,
            _ => 4
        };

    private IReadOnlyDictionary<string, long> GetDetectionSeverityCounts()
    {
        var counts = new Dictionary<string, long>(SeverityNames.Length, StringComparer.Ordinal);
        for (var index = 0; index < SeverityNames.Length; index++)
        {
            counts[SeverityNames[index]] = Interlocked.Read(ref _detectionSeverityCounts[index]);
        }

        return counts;
    }

    public IngestionDiagnosticsSnapshot GetIngestionDiagnosticsSnapshot()
        => new(
            Interlocked.Read(ref _etwEventsReceivedCount),
            Interlocked.Read(ref _etwEventsAcceptedCount),
            Interlocked.Read(ref _etwEventsDroppedCount),
            Interlocked.Read(ref _etwEventsMalformedCount),
            Interlocked.Read(ref _eventsProcessedCount),
            Interlocked.Read(ref _eventProcessingFailureCount),
            Interlocked.Read(ref _autoDenyFailureCount),
            Interlocked.Read(ref _eventProcessingRetryCount));

    public void InitializeIngestionDiagnostics(IngestionDiagnosticsSnapshot snapshot)
    {
        Interlocked.Exchange(ref _etwEventsReceivedCount, snapshot.EventsReceived);
        Interlocked.Exchange(ref _etwEventsAcceptedCount, snapshot.EventsAccepted);
        Interlocked.Exchange(ref _etwEventsDroppedCount, snapshot.EventsDropped);
        Interlocked.Exchange(ref _etwEventsMalformedCount, snapshot.EventsMalformed);
        Interlocked.Exchange(ref _eventsProcessedCount, snapshot.EventsProcessed);
        Interlocked.Exchange(ref _eventProcessingFailureCount, snapshot.ProcessingFailures);
        Interlocked.Exchange(ref _autoDenyFailureCount, snapshot.AutoDenyFailures);
        _etwEventsReceived.Add(snapshot.EventsReceived);
        _etwEventsAccepted.Add(snapshot.EventsAccepted);
        _etwEventsDropped.Add(snapshot.EventsDropped);
        _etwEventsMalformed.Add(snapshot.EventsMalformed);
        _eventsProcessed.Add(snapshot.EventsProcessed);
        _eventProcessingFailures.Add(snapshot.ProcessingFailures);
        _autoDenyFailures.Add(snapshot.AutoDenyFailures);
        Interlocked.Exchange(ref _eventProcessingRetryCount, snapshot.ProcessingRetries);
        _eventProcessingRetries.Add(snapshot.ProcessingRetries);
    }

    public DateTimeOffset? LastEventTimestamp
    {
        get
        {
            var ticks = Interlocked.Read(ref _lastEventTimestampTicks);
            return ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
        }
    }

    public void RecordEtwEventReceived()
    {
        Interlocked.Increment(ref _etwEventsReceivedCount);
        _etwEventsReceived.Add(1);
    }

    public void RecordEtwEventDropped()
    {
        Interlocked.Increment(ref _etwEventsDroppedCount);
        _etwEventsDropped.Add(1);
    }

    public long ReserveQueueItem() => Interlocked.Increment(ref _queueDepth);

    public void RecordQueueItemAccepted(long reservedDepth)
    {
        Interlocked.Increment(ref _etwEventsAcceptedCount);
        _etwEventsAccepted.Add(1);
        UpdateMaximum(ref _queueHighWaterMark, reservedDepth);
    }

    public void RecordQueueItemEnqueued()
    {
        var depth = ReserveQueueItem();
        RecordQueueItemAccepted(depth);
    }

    public void RecordQueueItemDequeued()
    {
        var depth = Interlocked.Decrement(ref _queueDepth);
        if (depth < 0)
        {
            Interlocked.Exchange(ref _queueDepth, 0);
        }
    }

    public void RecordEtwEventMalformed()
    {
        Interlocked.Increment(ref _etwEventsMalformedCount);
        _etwEventsMalformed.Add(1);
    }

    public void RecordEventProcessingFailure()
        => RecordEventProcessingFailure(1);

    public void RecordEventProcessingFailure(long count)
    {
        if (count <= 0)
        {
            return;
        }

        Interlocked.Add(ref _eventProcessingFailureCount, count);
        _eventProcessingFailures.Add(count);
    }

    public void RecordEventProcessingRetry()
    {
        Interlocked.Increment(ref _eventProcessingRetryCount);
        _eventProcessingRetries.Add(1);
    }

    public void RecordAutoDenyFailure()
    {
        Interlocked.Increment(ref _autoDenyFailureCount);
        _autoDenyFailures.Add(1);
    }

    public void RecordEventProcessed(SecurityEvent webEvent)
        => RecordEventProcessed(webEvent, null);

    public void RecordEventProcessed(SecurityEvent webEvent, TimeSpan? pipelineLatency)
    {
        Interlocked.Increment(ref _eventsProcessedCount);
        _eventsProcessed.Add(1);
        UpdateMaximum(ref _lastEventTimestampTicks, webEvent.Timestamp.UtcDateTime.Ticks);
        if (pipelineLatency is { } latency)
        {
            var seconds = Math.Max(0, latency.TotalSeconds);
            _eventPipelineLatency.Record(seconds);
            Interlocked.Increment(ref _pipelineLatencyCount);
            Interlocked.Add(ref _pipelineLatencyTicks, Math.Max(0, latency.Ticks));
            for (var index = 0; index < PipelineLatencyBucketBounds.Length; index++)
            {
                if (seconds <= PipelineLatencyBucketBounds[index])
                {
                    Interlocked.Increment(ref _pipelineLatencyBucketCounts[index]);
                }
            }
        }

        if (webEvent.IsSuspicious)
        {
            Interlocked.Increment(ref _suspiciousEventsCount);
            _suspiciousEvents.Add(1);
        }
    }

    public void RecordAutoDeny()
    {
        Interlocked.Increment(ref _autoDeniesCount);
        _autoDenies.Add(1);
    }

    public void RecordDetectionHistoryPruned()
    {
        Interlocked.Increment(ref _detectionHistoryPrunedCount);
        _detectionHistoryPruned.Add(1);
    }

    public void RecordDetectionHistoryCapacityRejection()
    {
        Interlocked.Increment(ref _detectionHistoryCapacityRejectionCount);
        _detectionHistoryCapacityRejections.Add(1);
    }

    public void RecordDetectionPathCapacityRejection()
    {
        Interlocked.Increment(ref _detectionPathCapacityRejectionCount);
        _detectionPathCapacityRejections.Add(1);
    }

    public void RecordOutOfOrderDetectionEvent()
    {
        Interlocked.Increment(ref _outOfOrderDetectionEventCount);
        _outOfOrderDetectionEvents.Add(1);
    }

    public void RecordDetectionClockReset()
    {
        Interlocked.Increment(ref _detectionClockResetCount);
        _detectionClockResets.Add(1);
    }

    public void RecordExtensionCacheCapacityRejection()
    {
        Interlocked.Increment(ref _extensionCacheCapacityRejectionCount);
        _extensionCacheCapacityRejections.Add(1);
    }

    public void SetDetectionRequestHistorySnapshot(int histories, int historyBuckets, int pathTokens)
    {
        Interlocked.Exchange(ref _trackedDetectionHistories, histories);
        Interlocked.Exchange(ref _trackedHistoryBuckets, historyBuckets);
        Interlocked.Exchange(ref _trackedPathTokens, pathTokens);
    }

    public void SetDetectionExtensionSiteCount(int extensionSites)
        => Interlocked.Exchange(ref _trackedExtensionSites, extensionSites);

    public void RecordSqliteWrite(TimeSpan duration)
    {
        var elapsed = Math.Max(0, duration.TotalSeconds);
        _sqliteWriteDuration.Record(elapsed);
        Interlocked.Increment(ref _sqliteWriteDurationCount);
        Interlocked.Add(ref _sqliteWriteDurationTicks, Math.Max(0, duration.Ticks));

        for (var index = 0; index < DurationBucketBounds.Length; index++)
        {
            if (elapsed <= DurationBucketBounds[index])
            {
                Interlocked.Increment(ref _durationBucketCounts[index]);
            }
        }
    }

    public void RecordSqliteFailure(int errorCode)
    {
        _sqliteWriteFailures.Add(1);
        Interlocked.Increment(ref _sqliteWriteFailureCount);
        switch (errorCode)
        {
            case 5 or 6:
                _sqliteBusyFailures.Add(1);
                Interlocked.Increment(ref _sqliteBusyFailureCount);
                break;
            case 11 or 26:
                _sqliteCorruptionFailures.Add(1);
                Interlocked.Increment(ref _sqliteCorruptionFailureCount);
                break;
            case 13:
                _sqliteDiskFullFailures.Add(1);
                Interlocked.Increment(ref _sqliteDiskFullFailureCount);
                break;
        }
    }

    public string RenderPrometheus()
    {
        var output = new StringBuilder();
        AppendCounter(output, "etw_events_received", "ETW events received.", Interlocked.Read(ref _etwEventsReceivedCount));
        AppendCounter(output, "etw_events_accepted", "ETW events accepted into the bounded ingestion queue.", Interlocked.Read(ref _etwEventsAcceptedCount));
        AppendCounter(output, "etw_events_dropped", "ETW events dropped from the ingestion queue.", Interlocked.Read(ref _etwEventsDroppedCount));
        AppendCounter(output, "etw_events_malformed", "Malformed ETW events rejected before queueing.", Interlocked.Read(ref _etwEventsMalformedCount));
        AppendCounter(output, "events_processed", "ETW events successfully persisted.", Interlocked.Read(ref _eventsProcessedCount));
        AppendCounter(output, "event_processing_failures", "ETW events that could not be processed.", Interlocked.Read(ref _eventProcessingFailureCount));
        AppendCounter(output, "event_processing_retries", "Retries while persisting queued ETW events.", Interlocked.Read(ref _eventProcessingRetryCount));
        AppendCounter(output, "sqlite_write_failures", "SQLite write failures.", Interlocked.Read(ref _sqliteWriteFailureCount));
        AppendCounter(output, "sqlite_busy_failures", "SQLite busy or locked failures.", Interlocked.Read(ref _sqliteBusyFailureCount));
        AppendCounter(output, "sqlite_corruption_failures", "SQLite corruption or invalid-database failures.", Interlocked.Read(ref _sqliteCorruptionFailureCount));
        AppendCounter(output, "sqlite_disk_full_failures", "SQLite disk-full failures.", Interlocked.Read(ref _sqliteDiskFullFailureCount));
        AppendCounter(output, "auto_deny_failures", "Automatic IIS actions that failed after event persistence.", Interlocked.Read(ref _autoDenyFailureCount));
        AppendCounter(output, "suspicious_events", "Suspicious events successfully persisted.", Interlocked.Read(ref _suspiciousEventsCount));
        AppendCounter(output, "auto_denies", "Automatic deny-list actions successfully applied.", Interlocked.Read(ref _autoDeniesCount));
        AppendCounter(output, "detection_history_pruned", "Inactive in-memory detector histories pruned.", Interlocked.Read(ref _detectionHistoryPrunedCount));
        AppendCounter(output, "detection_history_capacity_rejections", "New detector histories rejected at configured capacity.", Interlocked.Read(ref _detectionHistoryCapacityRejectionCount));
        AppendCounter(output, "detection_path_capacity_rejections", "New unique path tokens rejected at configured capacity.", Interlocked.Read(ref _detectionPathCapacityRejectionCount));
        AppendCounter(output, "detection_events_out_of_order", "Events skipped because they exceeded the allowed lateness.", Interlocked.Read(ref _outOfOrderDetectionEventCount));
        AppendCounter(output, "detection_clock_resets", "In-memory detector windows reset after a system clock rollback.", Interlocked.Read(ref _detectionClockResetCount));
        AppendCounter(output, "detection_extension_cache_capacity_rejections", "Site extension-cache admission or learning rejected at configured capacity.", Interlocked.Read(ref _extensionCacheCapacityRejectionCount));
        AppendCounter(output, "detection_events_analyzed", "Events successfully analyzed by the detector.", Interlocked.Read(ref _detectionEventsAnalyzedCount));
        AppendCounter(output, "detection_indicators", "Risk indicators produced by detector analysis.", Interlocked.Read(ref _detectionIndicatorsCount));
        AppendCounter(output, "event_stream_connections", "Event stream clients connected.", Interlocked.Read(ref _eventStreamConnectionCount));
        AppendCounter(output, "event_stream_failures", "Event stream failures.", Interlocked.Read(ref _eventStreamFailureCount));
        AppendCounter(output, "event_retention_runs", "Event retention runs completed.", Interlocked.Read(ref _eventRetentionRunCount));
        AppendCounter(output, "event_retention_events_pruned", "Events deleted by retention.", Interlocked.Read(ref _eventRetentionPrunedCount));
        AppendCounter(output, "event_retention_failures", "Event retention runs that failed.", Interlocked.Read(ref _eventRetentionFailureCount));
        AppendCounter(output, "iis_administration_failures", "IIS administration operations that failed.", Interlocked.Read(ref _iisAdministrationFailureCount));
        AppendCounter(output, "iis_expiry_cleanup_candidates", "Expired deny-list entries considered by cleanup.", Interlocked.Read(ref _expiryCleanupCandidateCount));
        AppendCounter(output, "iis_expiry_cleanup_succeeded", "Expired deny-list entries removed successfully.", Interlocked.Read(ref _expiryCleanupSucceededCount));
        AppendCounter(output, "iis_expiry_cleanup_simulated", "Expired deny-list entries simulated without IIS changes.", Interlocked.Read(ref _expiryCleanupSimulatedCount));
        AppendCounter(output, "iis_expiry_cleanup_failed", "Expired deny-list entries that could not be removed.", Interlocked.Read(ref _expiryCleanupFailureCount));
        AppendCounter(output, "recovery_attempts", "Background recovery attempts.", Interlocked.Read(ref _recoveryAttemptCount));
        AppendCounter(output, "fatal_errors", "Fatal background or process errors recorded.", Interlocked.Read(ref _fatalErrorCount));

        output.AppendLine("# HELP detection_events_by_severity Analyzed events by fixed risk severity.");
        output.AppendLine("# TYPE detection_events_by_severity counter");
        for (var index = 0; index < SeverityNames.Length; index++)
        {
            output.Append("detection_events_by_severity{severity=\"")
                .Append(SeverityNames[index])
                .Append("\"} ")
                .AppendLine(Interlocked.Read(ref _detectionSeverityCounts[index]).ToString(CultureInfo.InvariantCulture));
        }

            AppendDetectionModuleMetrics(output, GetDetectionModuleHealthSnapshots());

        output.AppendLine("# HELP queue_depth Current ETW ingestion queue depth.");
        output.AppendLine("# TYPE queue_depth gauge");
        output.Append("queue_depth ").AppendLine(QueueDepth.ToString(CultureInfo.InvariantCulture));
        AppendGauge(output, "queue_capacity", "Configured ETW ingestion queue capacity.", QueueCapacity);
        AppendGauge(output, "queue_high_water_mark", "Maximum ETW ingestion queue depth in this process.", QueueHighWaterMark);
        AppendGauge(output, "event_stream_active_clients", "Current active event stream clients.", ActiveEventStreamClients);

        output.AppendLine("# HELP etw_subscription_state Current ETW subscription lifecycle state.");
        output.AppendLine("# TYPE etw_subscription_state gauge");
        foreach (var state in Enum.GetValues<EtwSubscriptionState>())
        {
            var stateValue = EtwSubscriptionState == state ? 1 : 0;
            output.Append("etw_subscription_state{state=\"")
                .Append(state.ToString().ToLowerInvariant())
                .Append("\"} ")
                .AppendLine(stateValue.ToString(CultureInfo.InvariantCulture));
        }

        AppendGauge(output, "detection_client_histories", "Current in-memory detector client/site histories.", Interlocked.Read(ref _trackedDetectionHistories));
        AppendGauge(output, "detection_history_buckets", "Current in-memory detector event-time buckets.", Interlocked.Read(ref _trackedHistoryBuckets));
        AppendGauge(output, "detection_extension_sites", "Current in-memory detector site extension caches.", Interlocked.Read(ref _trackedExtensionSites));
        AppendGauge(output, "detection_path_tokens", "Current hashed unique paths retained by detector windows.", Interlocked.Read(ref _trackedPathTokens));

        AppendHistogram(
            output,
            "detection_risk_score",
            "Risk score distribution for analyzed events.",
            RiskScoreBucketBounds,
            _riskScoreBucketCounts,
            Interlocked.Read(ref _detectionEventsAnalyzedCount),
            Interlocked.Read(ref _detectionRiskScoreSum));
        AppendHistogram(
            output,
            "detection_indicator_count",
            "Indicator count distribution per analyzed event.",
            DetectionIndicatorBucketBounds,
            _detectionIndicatorBucketCounts,
            Interlocked.Read(ref _detectionEventsAnalyzedCount),
            Interlocked.Read(ref _detectionIndicatorsCount));

        output.AppendLine("# HELP last_event_timestamp_seconds Unix timestamp of the last successfully processed event.");
        output.AppendLine("# TYPE last_event_timestamp_seconds gauge");
        output.Append("last_event_timestamp_seconds ")
            .AppendLine((LastEventTimestamp?.ToUnixTimeMilliseconds() / 1000d ?? 0).ToString("0.######", CultureInfo.InvariantCulture));

        output.AppendLine("# HELP sqlite_write_duration_seconds Duration of SQLite event writes.");
        output.AppendLine("# TYPE sqlite_write_duration_seconds histogram");
        for (var index = 0; index < DurationBucketBounds.Length; index++)
        {
            output.Append("sqlite_write_duration_seconds_bucket{le=\"")
                .Append(DurationBucketBounds[index].ToString("0.###", CultureInfo.InvariantCulture))
                .Append("\"} ")
                .AppendLine(Interlocked.Read(ref _durationBucketCounts[index]).ToString(CultureInfo.InvariantCulture));
        }

        var count = Interlocked.Read(ref _sqliteWriteDurationCount);
        output.Append("sqlite_write_duration_seconds_bucket{le=\"+Inf\"} ").AppendLine(count.ToString(CultureInfo.InvariantCulture));
        output.Append("sqlite_write_duration_seconds_sum ")
            .AppendLine((Interlocked.Read(ref _sqliteWriteDurationTicks) / (double)TimeSpan.TicksPerSecond).ToString("0.######", CultureInfo.InvariantCulture));
        output.Append("sqlite_write_duration_seconds_count ").AppendLine(count.ToString(CultureInfo.InvariantCulture));

        output.AppendLine("# HELP etw_pipeline_latency_seconds Time from callback reception to successful event persistence.");
        output.AppendLine("# TYPE etw_pipeline_latency_seconds histogram");
        for (var index = 0; index < PipelineLatencyBucketBounds.Length; index++)
        {
            output.Append("etw_pipeline_latency_seconds_bucket{le=\"")
                .Append(PipelineLatencyBucketBounds[index].ToString("0.###", CultureInfo.InvariantCulture))
                .Append("\"} ")
                .AppendLine(Interlocked.Read(ref _pipelineLatencyBucketCounts[index]).ToString(CultureInfo.InvariantCulture));
        }

        var pipelineLatencyCount = Interlocked.Read(ref _pipelineLatencyCount);
        output.Append("etw_pipeline_latency_seconds_bucket{le=\"+Inf\"} ").AppendLine(pipelineLatencyCount.ToString(CultureInfo.InvariantCulture));
        output.Append("etw_pipeline_latency_seconds_sum ")
            .AppendLine((Interlocked.Read(ref _pipelineLatencyTicks) / (double)TimeSpan.TicksPerSecond).ToString("0.######", CultureInfo.InvariantCulture));
        output.Append("etw_pipeline_latency_seconds_count ").AppendLine(pipelineLatencyCount.ToString(CultureInfo.InvariantCulture));
        return output.ToString();
    }

    private static void AppendDetectionModuleMetrics(
        StringBuilder output,
        IReadOnlyList<DetectionModuleHealthSnapshot> modules)
    {
        output.AppendLine("# HELP detection_module_enabled Whether a detector module is enabled.");
        output.AppendLine("# TYPE detection_module_enabled gauge");
        output.AppendLine("# HELP detection_module_healthy Whether the last detector module evaluation succeeded.");
        output.AppendLine("# TYPE detection_module_healthy gauge");
        output.AppendLine("# HELP detection_module_evaluations_total Events evaluated by a detector module.");
        output.AppendLine("# TYPE detection_module_evaluations_total counter");
        output.AppendLine("# HELP detection_module_failures_total Detector module evaluations that failed.");
        output.AppendLine("# TYPE detection_module_failures_total counter");
        output.AppendLine("# HELP detection_module_processing_duration_milliseconds_last Duration of the last detector module evaluation.");
        output.AppendLine("# TYPE detection_module_processing_duration_milliseconds_last gauge");
        output.AppendLine("# HELP detection_module_signal_observations_total Signals returned by detector modules, including observation-only signals.");
        output.AppendLine("# TYPE detection_module_signal_observations_total counter");

        foreach (var module in modules)
        {
            var detectorLabel = $"detector=\"{module.Id}\"";
            output.Append("detection_module_enabled{").Append(detectorLabel).Append("} ")
                .AppendLine(module.Enabled ? "1" : "0");
            output.Append("detection_module_healthy{").Append(detectorLabel).Append("} ")
                .AppendLine(module.Status == "healthy" ? "1" : "0");
            output.Append("detection_module_evaluations_total{").Append(detectorLabel).Append("} ")
                .AppendLine(module.EvaluationCount.ToString(CultureInfo.InvariantCulture));
            output.Append("detection_module_failures_total{").Append(detectorLabel).Append("} ")
                .AppendLine(module.FailureCount.ToString(CultureInfo.InvariantCulture));
            output.Append("detection_module_processing_duration_milliseconds_last{").Append(detectorLabel).Append("} ")
                .AppendLine((module.LastProcessingMilliseconds ?? 0).ToString("0.######", CultureInfo.InvariantCulture));
            foreach (var signal in module.SignalCounts.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
            {
                output.Append("detection_module_signal_observations_total{detector=\"")
                    .Append(module.Id)
                    .Append("\",signal=\"")
                    .Append(signal.Key)
                    .Append("\"} ")
                    .AppendLine(signal.Value.ToString(CultureInfo.InvariantCulture));
            }
        }
    }

    public void Dispose() => _meter.Dispose();

    private static void AppendCounter(StringBuilder output, string name, string description, long value)
    {
        output.Append("# HELP ").Append(name).Append(' ').AppendLine(description);
        output.Append("# TYPE ").Append(name).AppendLine(" counter");
        output.Append(name).Append(' ').AppendLine(value.ToString(CultureInfo.InvariantCulture));
    }

    private static void AppendGauge(StringBuilder output, string name, string description, long value)
    {
        output.Append("# HELP ").Append(name).Append(' ').AppendLine(description);
        output.Append("# TYPE ").Append(name).AppendLine(" gauge");
        output.Append(name).Append(' ').AppendLine(value.ToString(CultureInfo.InvariantCulture));
    }

    private static void AppendHistogram(
        StringBuilder output,
        string name,
        string description,
        IReadOnlyList<double> bounds,
        long[] bucketCounts,
        long count,
        long sum)
    {
        output.Append("# HELP ").Append(name).Append(' ').AppendLine(description);
        output.Append("# TYPE ").Append(name).AppendLine(" histogram");
        for (var index = 0; index < bounds.Count; index++)
        {
            output.Append(name).Append("_bucket{le=\"")
                .Append(bounds[index].ToString("0.###", CultureInfo.InvariantCulture))
                .Append("\"} ")
                .AppendLine(Interlocked.Read(ref bucketCounts[index]).ToString(CultureInfo.InvariantCulture));
        }

        output.Append(name).Append("_bucket{le=\"+Inf\"} ").AppendLine(count.ToString(CultureInfo.InvariantCulture));
        output.Append(name).Append("_sum ").AppendLine(sum.ToString(CultureInfo.InvariantCulture));
        output.Append(name).Append("_count ").AppendLine(count.ToString(CultureInfo.InvariantCulture));
    }

    private IEnumerable<Measurement<long>> GetEtwSubscriptionStateMeasurements()
    {
        var currentState = EtwSubscriptionState;
        return Enum.GetValues<EtwSubscriptionState>()
            .Select(state => new Measurement<long>(
                currentState == state ? 1 : 0,
                new KeyValuePair<string, object?>("state", state.ToString().ToLowerInvariant())))
            .ToArray();
    }

    private static void UpdateMaximum(ref long target, long value)
    {
        var current = Interlocked.Read(ref target);
        while (value > current)
        {
            var observed = Interlocked.CompareExchange(ref target, value, current);
            if (observed == current)
            {
                return;
            }

            current = observed;
        }
    }
}
