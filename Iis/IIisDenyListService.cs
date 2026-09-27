namespace iisidsd.Iis;

public interface IIisDenyListService
{
    IReadOnlyList<string> GetDeniedIps(string siteName);
    bool AddDeniedIp(string siteName, string clientIp);
    IReadOnlyList<string> AddDeniedIpToDomains(string clientIp, IEnumerable<string> domains);
    bool RemoveDeniedIp(string siteName, string clientIp);
}
