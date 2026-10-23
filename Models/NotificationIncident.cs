namespace iisidsd.Models;

public sealed record NotificationIncident(
    string Id,
    string ClientIp,
    string TargetSite,
    string Summary,
    int RiskScore,
    string RiskSeverity,
    DateTimeOffset EventTimestampUtc,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    IReadOnlyList<DetectionEvidence> Evidence,
    string Status,
    int AttemptCount,
    DateTimeOffset? NextAttemptAtUtc,
    DateTimeOffset? DeliveredAtUtc,
    DateTimeOffset? AcknowledgedAtUtc,
    string? LastFailureType,
    string? AcknowledgedBy);

public sealed record NotificationMessage(
    string IncidentId,
    string ClientIp,
    string TargetSite,
    string Summary,
    int RiskScore,
    string RiskSeverity,
    DateTimeOffset EventTimestampUtc,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    IReadOnlyList<DetectionEvidence> Evidence,
    string DashboardUrl);

public sealed record NotificationQueueStatus(
    int Pending,
    int Retrying,
    int Delivered,
    int Failed,
    int Acknowledged,
    int Dropped);

public enum NotificationEnqueueResult
{
    NotEligible,
    Enqueued,
    Deduplicated,
    CapacityExceeded
}