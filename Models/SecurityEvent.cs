namespace iisidsd.Models;

public sealed record SecurityEvent(
    DateTimeOffset Timestamp,
    string Server,
    string Domain,
    string Method,
    string Path,
    string ClientIp,
    int StatusCode,
    string UserAgent,
    IReadOnlyDictionary<string, string> Properties,
    bool IsSuspicious = false,
    string? DetectionReason = null,
    int RiskScore = 0,
    string RiskSeverity = "Low",
    IReadOnlyList<string>? RiskIndicators = null)
{
    public string Id { get; } = Guid.NewGuid().ToString("N");
}
