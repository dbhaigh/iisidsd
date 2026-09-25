using iisidsd.Models;

namespace iisidsd.Services;

public interface IIpAggregationService
{
    IReadOnlyList<IpFinding> GetFindings(int limit, string? domain = null);
    IpFinding? GetFinding(string clientIp, string? domain = null);
}
