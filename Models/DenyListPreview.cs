namespace iisidsd.Models;

public sealed record DenyListPreviewRequest(
    string SiteName,
    string ClientIp,
    string? Reason = null,
    IReadOnlyList<string>? Evidence = null);

public sealed record DenyListPreview(
    string SiteName,
    string ClientIp,
    string Rule,
    DateTimeOffset? ExpiresAt,
    string EnforcementMode,
    bool AllowListed,
    bool WouldMutate,
    string ExistingRuleState,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<string> ApplicationPools,
    IReadOnlyList<string> OtherSitesSharingPools,
    IReadOnlyList<string> Warnings);
