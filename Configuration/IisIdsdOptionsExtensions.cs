using iisidsd.Iis;
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

        services.AddOptions<DetectionOptions>()
            .Bind(configuration.GetSection(DetectionOptions.SectionName))
            .ValidateDataAnnotations()
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
            .Validate(options => IisIpAllowList.IsValidAllowList(options.AllowList),
                "IisAdmin:AllowList must contain only valid IP addresses or CIDR ranges.")
            .ValidateOnStart();

        return services;
    }
}
