using System.Xml.Linq;
using iisidsd.Models;
using Microsoft.Web.Administration;

namespace iisidsd.Iis;

public sealed class IisDenyListService(ILogger<IisDenyListService> logger, IIisSiteDiscoveryService siteDiscoveryService) : IIisDenyListService
{
    private readonly AppCmdRunner _appCmd = new(logger);
    private readonly IIisSiteDiscoveryService _siteDiscoveryService = siteDiscoveryService;
    private readonly ILogger<IisDenyListService> _logger = logger;

    public IReadOnlyList<string> GetDeniedIps(string siteName)
    {
        if (string.IsNullOrWhiteSpace(siteName))
        {
            return [];
        }

        var result = _appCmd.Run("list", "config", siteName, "/section:system.webServer/security/ipSecurity", "/xml");
        if (!result.Success || string.IsNullOrWhiteSpace(result.Output))
        {
            return [];
        }

        var document = XDocument.Parse(result.Output);
        return document.Descendants("add")
            .Where(entry => !string.Equals((string?)entry.Attribute("allowed"), "true", StringComparison.OrdinalIgnoreCase))
            .Select(entry => (string?)entry.Attribute("ipAddress") ?? string.Empty)
            .Where(static ip => !string.IsNullOrWhiteSpace(ip))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public bool AddDeniedIp(string siteName, string clientIp)
        => WriteDeniedIp(siteName, clientIp);

    public IReadOnlyList<string> AddDeniedIpToDomains(string clientIp, IEnumerable<string> domains)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
        {
            return [];
        }

        var targetDomains = (domains ?? []).Select(NormalizeDomain).Where(static domain => !string.IsNullOrWhiteSpace(domain)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (targetDomains.Length == 0)
        {
            return [];
        }

        var sites = _siteDiscoveryService.GetSites();
        var targetSites = sites
            .Where(site => site.Domains.Any(siteDomain => targetDomains.Any(targetDomain => string.Equals(NormalizeDomain(siteDomain), targetDomain, StringComparison.OrdinalIgnoreCase))))
            .Select(site => site.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var updatedSites = new List<string>(targetSites.Length);
        foreach (var siteName in targetSites)
        {
            if (WriteDeniedIp(siteName, clientIp))
            {
                updatedSites.Add(siteName);
            }
        }

        if (updatedSites.Count == 0)
        {
            _logger.LogWarning("No matching IIS sites were updated for client IP {ClientIp} and domains {Domains}.", clientIp, string.Join(", ", targetDomains));
        }

        return updatedSites;
    }

    public bool RemoveDeniedIp(string siteName, string clientIp)
    {
        if (string.IsNullOrWhiteSpace(siteName) || string.IsNullOrWhiteSpace(clientIp))
        {
            return false;
        }

        try
        {
            using var manager = new ServerManager();
            var section = manager.GetApplicationHostConfiguration().GetSection("system.webServer/security/ipSecurity", siteName);
            var collection = section.GetCollection();
            var entry = collection.Cast<ConfigurationElement>().FirstOrDefault(element => string.Equals((string?)element["ipAddress"], clientIp, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
            {
                return true;
            }

            collection.Remove(entry);
            manager.CommitChanges();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to remove deny-list entry for {ClientIp} on site {SiteName}.", clientIp, siteName);
            return false;
        }
    }

    private bool WriteDeniedIp(string siteName, string clientIp)
    {
        if (string.IsNullOrWhiteSpace(siteName) || string.IsNullOrWhiteSpace(clientIp))
        {
            return false;
        }

        try
        {
            using var manager = new ServerManager();
            var section = manager.GetApplicationHostConfiguration().GetSection("system.webServer/security/ipSecurity", siteName);
            var collection = section.GetCollection();
            var existing = collection.Cast<ConfigurationElement>().FirstOrDefault(element => string.Equals((string?)element["ipAddress"], clientIp, StringComparison.OrdinalIgnoreCase));
            if (existing is not null)
            {
                if (!Equals(existing["allowed"], false))
                {
                    existing["allowed"] = false;
                    manager.CommitChanges();
                }

                return true;
            }

            var entry = collection.CreateElement("add");
            entry["ipAddress"] = clientIp;
            entry["allowed"] = false;
            collection.Add(entry);
            manager.CommitChanges();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to add deny-list entry for {ClientIp} on site {SiteName}.", clientIp, siteName);
            return false;
        }
    }

    private static string NormalizeDomain(string domain)
    {
        var value = domain.Trim().TrimEnd('.');
        var colonIndex = value.LastIndexOf(':');
        return colonIndex > -1 && value.IndexOf(':') == colonIndex ? value[..colonIndex] : value;
    }
}
