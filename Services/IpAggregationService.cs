using iisidsd.Models;
using iisidsd.Storage;

namespace iisidsd.Services;

public sealed class IpAggregationService(
    IFindingStore findingStore,
    IBanCountService banCountService) : IIpAggregationService
{
    private readonly IFindingStore _findingStore = findingStore;
    private readonly IBanCountService _banCountService = banCountService;

    public IReadOnlyList<IpFinding> GetFindings(int limit, string? domain = null)
    {
        var findings = _findingStore.List(Math.Clamp(limit, 1, FindingStoreLimits.MaximumListLimit), domain)
            .Take(FindingStoreLimits.MaximumListLimit)
            .ToArray();
        var banCounts = _banCountService.GetBanCounts(findings.Select(static finding => finding.ClientIp), domain);

        return findings
            .Select(finding => finding with
            {
                BanCount = banCounts.TryGetValue(finding.ClientIp, out var banCount) ? banCount.BanCount : 0
            })
            .ToArray();
    }

    public IpFinding? GetFinding(string clientIp, string? domain = null)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
        {
            return null;
        }

        var finding = _findingStore.Get(clientIp, domain);
        return finding is null
            ? null
            : finding with { BanCount = _banCountService.GetBanCount(clientIp, domain).BanCount };
    }
}
