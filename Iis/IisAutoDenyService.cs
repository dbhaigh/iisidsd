using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Services;
using Microsoft.Extensions.Options;

namespace iisidsd.Iis;

public sealed class IisAutoDenyService(
    IIisDenyListService denyListService,
    IBanCountService banCountService,
    IOptions<IisAdminOptions> adminOptions,
    ILogger<IisAutoDenyService> logger) : IIisAutoDenyService
{
    private const string RepeatedNotFoundIndicator = "multiple 404 responses from the same client IP";

    public void Apply(SecurityEvent securityEvent)
    {
        if (!adminOptions.Value.EnableDenyListChanges)
        {
            return;
        }

        var indicators = securityEvent.RiskIndicators ?? [];
        var repeatedNotFound = indicators.Contains(RepeatedNotFoundIndicator, StringComparer.Ordinal);
        var corroboratedCritical = string.Equals(securityEvent.RiskSeverity, "Critical", StringComparison.OrdinalIgnoreCase) &&
            indicators.Distinct(StringComparer.Ordinal).Skip(1).Any();
        if (!securityEvent.IsSuspicious || (!repeatedNotFound && !corroboratedCritical))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(securityEvent.ClientIp) || string.IsNullOrWhiteSpace(securityEvent.Domain))
        {
            return;
        }

        var updatedSites = denyListService.AddDeniedIpToDomains(securityEvent.ClientIp, [securityEvent.Domain]);
        if (updatedSites.Count == 0)
        {
            logger.LogWarning(
                "Automatic deny-list update found no matching IIS sites for client IP {ClientIp} and domain {Domain}.",
                securityEvent.ClientIp,
                securityEvent.Domain);
            return;
        }

        banCountService.IncrementBanCounts(securityEvent.ClientIp, [securityEvent.Domain]);
        logger.LogInformation(
            "Automatically added client IP {ClientIp} to {SiteCount} IIS deny list(s) for domain {Domain} due to {RiskSeverity} severity.",
            securityEvent.ClientIp,
            updatedSites.Count,
            securityEvent.Domain,
            securityEvent.RiskSeverity);
    }
}
