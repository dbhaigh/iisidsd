using System.Xml.Linq;
using iisidsd.Models;

namespace iisidsd.Iis;

public sealed class IisSiteDiscoveryService(ILogger<IisSiteDiscoveryService> logger) : IIisSiteDiscoveryService
{
    private readonly AppCmdRunner _appCmd = new(logger);

    public IReadOnlyList<IisSiteInfo> GetSites()
    {
        var result = _appCmd.Run("list", "site", "/xml");
        if (!result.Success || string.IsNullOrWhiteSpace(result.Output))
        {
            return [];
        }

        var document = XDocument.Parse(result.Output);
        return document.Descendants("SITE")
            .Select(site =>
            {
                var bindings = ParseBindings((string?)site.Attribute("bindings"));
                return new IisSiteInfo(
                    ParseLong((string?)site.Attribute("id")),
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

    private static string NormalizeDomain(string domain)
    {
        var value = domain.Trim().TrimEnd('.');
        var colonIndex = value.LastIndexOf(':');
        return colonIndex > -1 && value.IndexOf(':') == colonIndex ? value[..colonIndex] : value;
    }
}
