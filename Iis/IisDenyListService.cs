using System.Xml.Linq;

namespace iisidsd.Iis;

public sealed class IisDenyListService(ILogger<IisDenyListService> logger) : IIisDenyListService
{
    private readonly AppCmdRunner _appCmd = new(logger);
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
    {
        if (string.IsNullOrWhiteSpace(siteName) || string.IsNullOrWhiteSpace(clientIp))
        {
            return false;
        }

        if (GetDeniedIps(siteName).Contains(clientIp, StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        var rule = $"/+[ipAddress='{clientIp}',allowed='False']";
        var result = _appCmd.Run("set", "config", siteName, "/section:system.webServer/security/ipSecurity", rule, "/commit:apphost");
        if (!result.Success)
        {
            _logger.LogWarning("Failed to add deny-list entry for {ClientIp} on site {SiteName}.", clientIp, siteName);
        }

        return result.Success;
    }

    public bool RemoveDeniedIp(string siteName, string clientIp)
    {
        if (string.IsNullOrWhiteSpace(siteName) || string.IsNullOrWhiteSpace(clientIp))
        {
            return false;
        }

        var rule = $"/-[ipAddress='{clientIp}']";
        var result = _appCmd.Run("set", "config", siteName, "/section:system.webServer/security/ipSecurity", rule, "/commit:apphost");
        if (!result.Success)
        {
            _logger.LogWarning("Failed to remove deny-list entry for {ClientIp} on site {SiteName}.", clientIp, siteName);
        }

        return result.Success;
    }
}
