namespace iisidsd.Iis;

public interface IIisDenyListService
{
    IReadOnlyList<string> GetDeniedIps(string siteName);
    bool AddDeniedIp(string siteName, string clientIp);
    bool RemoveDeniedIp(string siteName, string clientIp);
}
