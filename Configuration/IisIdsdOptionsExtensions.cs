using iisidsd.Iis;
using iisidsd.Detection;
using iisidsd.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace iisidsd.Configuration;

public static class IisIdsdOptionsExtensions
{
    public static IServiceCollection AddIisIdsdOptions(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<IisEtwOptions>()
            .Bind(configuration.GetSection(IisEtwOptions.SectionName))
            .ValidateDataAnnotations()
            .Validate(options => options.ProviderId != Guid.Empty, "IisEtw:ProviderId must not be empty.")
            .ValidateOnStart();

        services.AddOptions<TrustedProxyOptions>()
            .Bind(configuration.GetSection(TrustedProxyOptions.SectionName))
            .ValidateDataAnnotations()
            .Validate(options => options.TryGetCanonicalProxies(out _),
                "TrustedProxies must contain valid exact IP addresses and must list at least one address when enabled.")
            .ValidateOnStart();

        services.AddOptions<DashboardOptions>()
            .Bind(configuration.GetSection(DashboardOptions.SectionName))
            .ValidateDataAnnotations()
            .Validate(options => options.TryGetCanonicalAllowedHosts(out _),
                "Dashboard:AllowedHosts must contain valid hostnames or exact IP addresses without ports or wildcards.")
            .ValidateOnStart();

        services.AddOptions<DetectionOptions>()
            .Bind(configuration.GetSection(DetectionOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<DetectionModulesOptions>()
            .Bind(configuration.GetSection(DetectionModulesOptions.SectionName))
            .Validate(options => options.IsValid(),
                "DetectionModules must contain at most 32 valid lowercase module ids with valid mode values.")
            .ValidateOnStart();

        services.AddOptions<NotificationOptions>()
            .Bind(configuration.GetSection(NotificationOptions.SectionName))
            .ValidateDataAnnotations()
            .Validate(options => options.IsValid(),
                "Notifications must use a supported provider, valid severity, bounded retry settings, and a loopback dashboard URL.")
            .ValidateOnStart();

        services.AddOptions<TrayOptions>()
            .Bind(configuration.GetSection(TrayOptions.SectionName))
            .ValidateDataAnnotations()
            .Validate(options =>
                Uri.TryCreate(options.BrowserUrl, UriKind.Absolute, out var uri) &&
                (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps),
                "Tray:BrowserUrl must be an absolute HTTP or HTTPS URL.")
            .ValidateOnStart();

        services.AddOptions<StorageOptions>()
            .Bind(configuration.GetSection(StorageOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<IisAdminOptions>()
            .Bind(configuration.GetSection(IisAdminOptions.SectionName))
            .ValidateDataAnnotations()
            .Validate(options => IisAdminOptions.IsValidEnforcementMode(options.EnforcementMode),
                "IisAdmin:EnforcementMode must be Observe, Simulate, or Enforce.")
            .Validate(options => IisIpAllowList.IsValidAllowList(options.AllowList),
                "IisAdmin:AllowList must contain only valid IP addresses or CIDR ranges.")
            .ValidateOnStart();

        return services;
    }
}
