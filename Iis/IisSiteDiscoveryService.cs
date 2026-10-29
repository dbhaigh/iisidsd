using System.Xml.Linq;
using iisidsd.Models;

namespace iisidsd.Iis;

public sealed class IisSiteDiscoveryService(
    ILogger<IisSiteDiscoveryService> logger,
    IAppCmdRunner appCmdRunner) : IIisSiteDiscoveryService
{
    public IReadOnlyList<IisSiteInfo> GetSites()
    {
        var result = appCmdRunner.Run("list", "site", "/xml");
        if (!result.Success)
        {
            logger.LogWarning("Unable to discover IIS sites using appcmd. Error={AppCmdError}", result.Error);
            return [];
        }

        if (string.IsNullOrWhiteSpace(result.Output))
        {
            logger.LogWarning("IIS site discovery returned no output from appcmd.");
            return [];
        }

        var document = XDocument.Parse(result.Output);
        var sites = document.Descendants("SITE")
            .Select(site =>
            {
                var bindings = ParseBindings((string?)site.Attribute("bindings"));
                return new IisSiteInfo(
                    ParseLong((string?)site.Attribute("SITE.ID") ?? (string?)site.Attribute("id")),
                    (string?)site.Attribute("SITE.NAME") ?? string.Empty,
                    (string?)site.Attribute("state") ?? string.Empty,
                    bindings,
                    bindings.Select(ParseDomain)
                        .Where(static domain => !string.IsNullOrWhiteSpace(domain))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Order(StringComparer.OrdinalIgnoreCase)
                        .ToArray());
            })
            .Where(static site => !string.IsNullOrWhiteSpace(site.Name))
            .OrderBy(static site => site.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (sites.Length == 0)
        {
            logger.LogInformation("IIS site discovery completed, but appcmd returned no configured sites.");
        }

        return sites;
    }

    public IisSiteInfo? FindSiteByDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return null;
        }

        var normalizedDomain = NormalizeDomain(domain);
        return GetSites().FirstOrDefault(site => site.Domains.Any(value => string.Equals(value, normalizedDomain, StringComparison.OrdinalIgnoreCase)));
    }

    private static long ParseLong(string? value)
        => long.TryParse(value, out var parsed) ? parsed : 0;

    private static IReadOnlyList<string> ParseBindings(string? bindings)
        => string.IsNullOrWhiteSpace(bindings)
            ? []
            : bindings.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

    private static string ParseDomain(string binding)
    {
        var parts = binding.Split(':', StringSplitOptions.TrimEntries);
        return parts.Length >= 3 ? NormalizeDomain(parts[2]) : string.Empty;
    }

    internal static string NormalizeDomain(string domain)
    {
        var value = domain.Trim().TrimEnd('.');
        var colonIndex = value.LastIndexOf(':');
        return colonIndex > -1 && value.IndexOf(':') == colonIndex ? value[..colonIndex] : value;
    }
}
