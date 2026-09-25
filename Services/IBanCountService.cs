using iisidsd.Models;

namespace iisidsd.Services;

public interface IBanCountService
{
    IReadOnlyList<BanCountRecord> GetBanCounts(int limit);
    IReadOnlyDictionary<string, BanCountRecord> GetBanCounts(IEnumerable<string> clientIps);
    BanCountRecord GetBanCount(string clientIp);
    BanCountRecord SetBanCount(string clientIp, int banCount);
}
