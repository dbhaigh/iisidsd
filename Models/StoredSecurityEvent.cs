namespace iisidsd.Models;

public sealed record StoredSecurityEvent(
    long SequenceId,
    string EventId,
    DateTimeOffset Timestamp,
    string Server,
    string Domain,
    string Method,
    string Path,
    string ClientIp,
    int StatusCode,
    string UserAgent,
    IReadOnlyDictionary<string, string> Properties,
    bool IsSuspicious,
    string? DetectionReason,
    int RiskScore,
    string RiskSeverity,
    IReadOnlyList<string> RiskIndicators);
