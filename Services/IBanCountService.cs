using iisidsd.Models;

namespace iisidsd.Services;

public interface IBanCountService
{
    IReadOnlyList<BanCountRecord> GetBanCounts(int limit, string? domain = null);
    IReadOnlyDictionary<string, BanCountRecord> GetBanCounts(IEnumerable<string> clientIps, string? domain = null);
    BanCountRecord GetBanCount(string clientIp, string? domain = null);
    BanCountRecord SetBanCount(string clientIp, int banCount, string? domain = null);
    void IncrementBanCounts(string clientIp, IEnumerable<string> domains);
}
