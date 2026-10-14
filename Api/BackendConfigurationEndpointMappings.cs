using iisidsd.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;

namespace iisidsd.Api;

public static class BackendConfigurationEndpointMappings
{
    public static void MapBackendConfigurationEndpoints(this WebApplication webApp)
    {
        webApp.MapGet("/api/configuration", async Task<Ok<BackendConfigurationResponse>> (
            IBackendConfigurationStore configurationStore,
            CancellationToken cancellationToken) =>
            TypedResults.Ok(new BackendConfigurationResponse(
                await configurationStore.GetSettingsAsync(cancellationToken),
                RestartRequired: false)))
            .WithName("GetBackendConfiguration")
            .WithSummary("Get editable backend configuration")
            .WithDescription("Returns the supported non-secret settings from appsettings.json.")
            .Produces<BackendConfigurationResponse>()
            .RequireAuthorization("DashboardAdministrator");

        webApp.MapPatch("/api/configuration", async Task<Results<Ok<BackendConfigurationResponse>, ValidationProblem>> (
            IBackendConfigurationStore configurationStore,
            UpdateBackendConfigurationRequest request,
            CancellationToken cancellationToken) =>
        {
            var result = await configurationStore.SaveSettingsAsync(request.Settings, cancellationToken);
            if (!result.Saved)
            {
                return TypedResults.ValidationProblem(
                    result.Errors.ToDictionary(pair => pair.Key, pair => pair.Value));
            }

            return TypedResults.Ok(new BackendConfigurationResponse(
                await configurationStore.GetSettingsAsync(cancellationToken),
                RestartRequired: true));
        })
            .WithName("PatchBackendConfiguration")
            .WithSummary("Update backend configuration")
            .WithDescription("Validates and saves a partial update to supported non-secret appsettings.json settings. A service restart is required for changes to take effect.")
            .Produces<BackendConfigurationResponse>()
            .ProducesValidationProblem()
            .RequireAuthorization("DashboardAdministrator");
    }
}
