namespace iisidsd.Models;

public sealed record IpFinding(
    string ClientIp,
    int RequestCount,
    int SuspiciousRequestCount,
    int HighestRiskScore,
    string HighestRiskSeverity,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    IReadOnlyList<string> Domains,
    IReadOnlyList<string> DetectionReasons,
    IReadOnlyList<string> RiskIndicators,
    bool IsDenied = false,
    int BanCount = 0,
    DateTimeOffset? BanStarted = null,
    DateTimeOffset? BanEnds = null,
    int BanDurationHours = 0);
