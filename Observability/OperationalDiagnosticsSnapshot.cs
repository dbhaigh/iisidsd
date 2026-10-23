namespace iisidsd.Observability;

public enum EtwSubscriptionState
{
    Starting,
    Listening,
    Recovering,
    Disabled,
    Unsupported,
    Stopped
}

public sealed record RecentOperationalEvent(
    DateTimeOffset OccurredAtUtc,
    string Component,
    string Kind,
    string FailureType);

public sealed record OperationalDiagnosticsSnapshot(
    DateTimeOffset StartedAtUtc,
    double UptimeSeconds,
    string Version,
    string ConfigurationRevision,
    string EtwSubscriptionState,
    DateTimeOffset? EtwSubscriptionChangedAtUtc,
    DateTimeOffset? LastSuccessfulEventAtUtc,
    long QueueDepth,
    int QueueCapacity,
    long QueueHighWaterMark,
    long EtwEventsReceived,
    long EtwEventsAccepted,
    long EtwEventsDropped,
    long EtwEventsMalformed,
    long EventsProcessed,
    long ProcessingFailures,
    long ProcessingRetries,
    long DetectionEventsAnalyzed,
    long DetectionIndicators,
    IReadOnlyDictionary<string, long> DetectionEventsBySeverity,
    long ActiveEventStreams,
    long EventStreamConnections,
    long EventStreamFailures,
    long SqliteWriteFailures,
    long SqliteBusyEvents,
    long SqliteCorruptionFailures,
    long SqliteDiskFullFailures,
    long RetentionRuns,
    long RetentionEventsPruned,
    long RetentionFailures,
    DateTimeOffset? LastRetentionRunAtUtc,
    long IisAdministrationFailures,
    long ExpiryCleanupCandidates,
    long ExpiryCleanupSucceeded,
    long ExpiryCleanupSimulated,
    long ExpiryCleanupFailed,
    long RecoveryAttempts,
    long FatalErrors,
    string? LastEnforcementOutcome,
    DateTimeOffset? LastEnforcementOccurredAtUtc,
    bool? LastEnforcementWasSimulation,
    IReadOnlyList<RecentOperationalEvent> RecentOperationalEvents,
    IReadOnlyList<DetectionModuleHealthSnapshot>? DetectionModules = null);

public sealed record DetectionModuleHealthSnapshot(
    string Id,
    bool Enabled,
    string Mode,
    string Status,
    long EvaluationCount,
    long FailureCount,
    DateTimeOffset? LastEvaluatedAtUtc,
    double? LastProcessingMilliseconds,
    string? LastFailureType,
    IReadOnlyDictionary<string, long> SignalCounts);

public sealed record SqliteHealthSnapshot(
    bool Healthy,
    DateTimeOffset? LastCheckedAtUtc,
    long FailureCount,
    string? LastFailureType);