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
        if (!adminOptions.Value.EnableDenyListChanges)
        {
            return;
        }

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

        if (ipAllowList.Contains(securityEvent.ClientIp))
        {
            logger.LogInformation(
                "Automatic deny-list action skipped for an allow-listed IP. ClientIp={ClientIp} Domain={Domain} RiskScore={RiskScore} RiskSeverity={RiskSeverity} DetectionReason={DetectionReason}",
                securityEvent.ClientIp,
                securityEvent.Domain,
                securityEvent.RiskScore,
                securityEvent.RiskSeverity,
                securityEvent.DetectionReason);
            return;
        }

        var reason = $"{securityEvent.DetectionReason ?? "Suspicious activity"}; indicators: {string.Join(", ", distinctIndicators)}";
        var updatedSites = denyListService.AddDeniedIpToDomains(
            securityEvent.ClientIp,
            [securityEvent.Domain],
            "system:auto-deny",
            reason,
            securityEvent);
        if (updatedSites.Count == 0 && !adminOptions.Value.DryRun)
        {
            logger.LogWarning(
                "Automatic deny-list update found no matching IIS sites. ClientIp={ClientIp} Domain={Domain} RiskScore={RiskScore} RiskSeverity={RiskSeverity} DetectionReason={DetectionReason}",
                securityEvent.ClientIp,
                securityEvent.Domain,
                securityEvent.RiskScore,
                securityEvent.RiskSeverity,
                securityEvent.DetectionReason);
            return;
        }

        if (adminOptions.Value.DryRun)
        {
            logger.LogInformation(
                "Dry-run automatic deny-list action. ClientIp={ClientIp} Domain={Domain} RiskScore={RiskScore} RiskSeverity={RiskSeverity} DetectionReason={DetectionReason}",
                securityEvent.ClientIp,
                securityEvent.Domain,
                securityEvent.RiskScore,
                securityEvent.RiskSeverity,
                securityEvent.DetectionReason);
            return;
        }

        _observability.RecordAutoDeny();
        banCountService.IncrementBanCounts(securityEvent.ClientIp, [securityEvent.Domain]);

        logger.LogInformation(
            "Automatic deny-list action applied to {SiteCount} IIS site(s). ClientIp={ClientIp} Domain={Domain} RiskScore={RiskScore} RiskSeverity={RiskSeverity} DetectionReason={DetectionReason}",
            securityEvent.ClientIp,
            updatedSites.Count,
            securityEvent.Domain,
            securityEvent.RiskScore,
            securityEvent.RiskSeverity,
            securityEvent.DetectionReason);
    }
}
