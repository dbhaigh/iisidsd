using System.Text.Json;

namespace iisidsd.Api;

/// <summary>Returns the supported, non-secret backend settings shown by the dashboard.</summary>
public sealed record BackendConfigurationResponse(
    JsonElement Settings,
    string Revision,
    bool RestartRequired);

/// <summary>Provides partial updates for supported backend settings saved in appsettings.json.</summary>
public sealed record UpdateBackendConfigurationRequest(JsonElement Settings, string ExpectedRevision);
