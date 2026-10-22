using iisidsd.Models;

namespace iisidsd.Detection;

public enum DetectionEvidenceScope
{
    None,
    SingleRequest,
    RepeatedBehavior,
    CorrelatedAttackSequence
}

public enum DetectionEvidenceStrength
{
    None,
    Limited,
    Supported,
    Corroborated
}

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
    ScannerUserAgent
}

public sealed record DetectionEvidence(
    DetectionSignalCode Code,
    DetectionEvidenceFamily Family,
    string Indicator,
    int ConfiguredWeight,
    int ScoreContribution,
    bool Contributed);

public sealed record DetectionAssessment(
    SecurityEvent? Event,
    DetectionEvidenceScope Scope,
    DetectionEvidenceStrength Strength,
    int EvidenceFamilyCount,
    IReadOnlyList<DetectionEvidence> Evidence);