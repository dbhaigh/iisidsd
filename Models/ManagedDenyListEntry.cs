namespace iisidsd.Models;

public sealed record ManagedDenyListEntry(
    string SiteName,
    string ClientIp,
    DateTimeOffset? ExpiresAt,
    string State,
    long AuditId);
