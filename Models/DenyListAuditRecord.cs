namespace iisidsd.Models;

/// <summary>Describes an audited deny-list action and its final outcome.</summary>
public sealed record DenyListAuditRecord(
    long Id,
    string Actor,
    string Action,
    string SiteName,
    string ClientIp,
    string Reason,
    DateTimeOffset OccurredAt,
    bool DryRun,
    string Outcome,
    DateTimeOffset? ExpiresAt);
