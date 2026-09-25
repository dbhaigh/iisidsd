namespace iisidsd.Models;

public sealed record DeniedIpRecord(
    string ClientIp,
    string Domain,
    int HighestRiskScore,
    string DetectionReason,
    DateTimeOffset DetectedAt,
    bool IsDenied,
    DateTimeOffset? BanStarted,
    DateTimeOffset? BanEnds,
    int BanDurationHours,
    int BanCount);
