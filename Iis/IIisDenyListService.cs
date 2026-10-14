using iisidsd.Models;

namespace iisidsd.Iis;

public interface IIisDenyListService
{
    IReadOnlyList<string> GetDeniedIps(string siteName);
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
    bool RemoveExpiredDeniedIp(TemporaryDenyListEntry entry);
}
