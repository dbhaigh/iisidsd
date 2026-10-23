namespace iisidsd.Models;

public enum DetectionEvidenceFamily
{
    ResponseOutcome,
    PathShape,
    RequestMethod,
    PathContent,
    UserAgent,
    TrafficPattern
}

public enum DetectionSignalCode
{
    SuspiciousStatus,
    LongPath,
    RepeatedNotFound,
    RepeatedAuthenticationFailure,
    UnusualMethod,
    SuspiciousPathFragment,
    UnknownExtension,
    HighRequestRate,
    PathEnumeration,
    ScannerUserAgent,
    Custom
}

public sealed record DetectionEvidence(
    DetectionSignalCode Code,
    DetectionEvidenceFamily Family,
    string Indicator,
    int ConfiguredWeight,
    int ScoreContribution,
    bool Contributed,
    string DetectorId = "heuristic",
    string SignalKey = "",
    string? CorrelationKey = null,
    string Explanation = "",
    string? Reason = null,
    bool ReasonOnlyWhenGeneric = false,
    bool RepeatedBehavior = false,
    int FamilyPriority = 0,
    int Order = 0,
    bool ObserveOnly = false);