using System.Text.Json;

namespace iisidsd.Configuration;

public interface IBackendConfigurationStore
{
    Task<JsonElement> GetSettingsAsync(CancellationToken cancellationToken);
    Task<BackendConfigurationSaveResult> SaveSettingsAsync(JsonElement settings, CancellationToken cancellationToken);
}

public sealed record BackendConfigurationSaveResult(
    bool Saved,
    IReadOnlyDictionary<string, string[]> Errors);
