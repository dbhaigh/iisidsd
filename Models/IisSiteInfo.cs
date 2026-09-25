namespace iisidsd.Models;

public sealed record IisSiteInfo(
    long SiteId,
    string Name,
    string State,
    IReadOnlyList<string> Bindings,
    IReadOnlyList<string> Domains);
