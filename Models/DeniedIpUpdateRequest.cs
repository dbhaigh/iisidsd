namespace iisidsd.Models;

public sealed record DeniedIpUpdateRequest(
    string ClientIp,
    IReadOnlyList<string>? Domains = null,
    string? Reason = null);
