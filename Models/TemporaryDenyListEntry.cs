namespace iisidsd.Models;

public sealed record TemporaryDenyListEntry(
    string SiteName,
    string ClientIp,
    DateTimeOffset ExpiresAt);
