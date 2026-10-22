using iisidsd.Models;

namespace iisidsd.Iis;

public interface IIisDenyListService
{
    IReadOnlyList<string> GetDeniedIps(string siteName);
    DenyListPreview? PreviewDeniedIp(DenyListPreviewRequest request, string actor = "manual");
    bool AddDeniedIp(
        string siteName,
        string clientIp,
        string actor = "manual",
        string reason = "Manual deny-list request",
        SecurityEvent? securityEvent = null,
        string? domain = null);
    IReadOnlyList<string> AddDeniedIpToDomains(
        string clientIp,
        IEnumerable<string> domains,
        string actor = "manual",
        string reason = "Manual deny-list request",
        SecurityEvent? securityEvent = null);
    bool RemoveDeniedIp(string siteName, string clientIp, string actor = "manual", string reason = "Manual deny-list removal");
    DenyListRemovalStatus RemoveDeniedIpWithStatus(
        string siteName,
        string clientIp,
        string actor = "manual",
        string reason = "Manual deny-list removal")
        => RemoveDeniedIp(siteName, clientIp, actor, reason)
            ? DenyListRemovalStatus.Removed
            : DenyListRemovalStatus.Failed;
    bool RemoveExpiredDeniedIp(TemporaryDenyListEntry entry);
    void ReconcilePendingManagedDenies();
}

public enum DenyListRemovalStatus
{
    Removed,
    Observed,
    Simulated,
    NotFound,
    NotServiceOwned,
    RecoveryRequired,
    ConcurrentChange,
    Failed,
    Invalid
}
