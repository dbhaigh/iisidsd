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

public sealed record DetectionAssessment(
    SecurityEvent? Event,
    DetectionEvidenceScope Scope,
    DetectionEvidenceStrength Strength,
    int EvidenceFamilyCount,
    IReadOnlyList<DetectionEvidence> Evidence);