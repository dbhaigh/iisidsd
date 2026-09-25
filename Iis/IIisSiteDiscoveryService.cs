using iisidsd.Models;

namespace iisidsd.Iis;

public interface IIisSiteDiscoveryService
{
    IReadOnlyList<IisSiteInfo> GetSites();
    IisSiteInfo? FindSiteByDomain(string domain);
}
