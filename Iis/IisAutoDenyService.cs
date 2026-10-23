using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Services;
using Microsoft.Extensions.Options;

namespace iisidsd.Iis;

public sealed class IisAutoDenyService(
    IIisDenyListService denyListService,
    IBanCountService banCountService,
    IIpAllowList ipAllowList,
    IOptions<IisAdminOptions> adminOptions,
    ILogger<IisAutoDenyService> logger,
    IisObservability? observability = null) : IIisAutoDenyService
{
    private const string RepeatedNotFoundIndicator = "multiple 404 responses from the same client IP";
    private readonly IisObservability _observability = observability ?? new();

    public void Apply(SecurityEvent securityEvent)
    {
        var policy = adminOptions.Value.GetEnforcementPolicy();
        var indicators = securityEvent.RiskIndicators ?? [];
        var distinctIndicators = indicators.Distinct(StringComparer.Ordinal).ToArray();
        var repeatedNotFound = distinctIndicators.Contains(RepeatedNotFoundIndicator, StringComparer.Ordinal);
        var critical = string.Equals(securityEvent.RiskSeverity, "Critical", StringComparison.OrdinalIgnoreCase);
        var requireMultipleIndicators = adminOptions.Value.RequireMultipleIndicators;
        if (!securityEvent.IsSuspicious ||
            (!repeatedNotFound && !critical) ||
            (requireMultipleIndicators && distinctIndicators.Length < 2))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(securityEvent.ClientIp) || string.IsNullOrWhiteSpace(securityEvent.Domain))
        {
            return;
        }

        var reason = $"{securityEvent.DetectionReason ?? "Suspicious activity"}; indicators: {string.Join(", ", distinctIndicators)}";
        var allowListed = ipAllowList.Contains(securityEvent.ClientIp);
        var updatedSites = denyListService.AddDeniedIpToDomains(
            securityEvent.ClientIp,
            [securityEvent.Domain],
            "system:auto-deny",
            reason,
            securityEvent);

        if (allowListed)
        {
            return;
        }

        if (!policy.CanMutate)
        {
            logger.LogInformation(
                "Automatic deny-list action evaluated in {EnforcementMode} mode. RiskScore={RiskScore} RiskSeverity={RiskSeverity}",
                policy.Mode,
                securityEvent.RiskScore,
                securityEvent.RiskSeverity);
            return;
        }

        if (updatedSites.Count == 0)
        {
            logger.LogWarning(
                "Automatic deny-list update found no matching IIS sites. RiskScore={RiskScore} RiskSeverity={RiskSeverity}",
                securityEvent.RiskScore,
                securityEvent.RiskSeverity);
            return;
        }

        _observability.RecordAutoDeny();
        banCountService.IncrementBanCounts(securityEvent.ClientIp, [securityEvent.Domain]);

        logger.LogInformation(
            "Automatic deny-list action applied to {SiteCount} IIS site(s). RiskScore={RiskScore} RiskSeverity={RiskSeverity}",
            updatedSites.Count,
            securityEvent.RiskScore,
            securityEvent.RiskSeverity);
    }
}
