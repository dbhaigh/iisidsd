using System.Text.Json;

namespace iisidsd.Configuration;

public interface IBackendConfigurationStore
{
    Task<JsonElement> GetSettingsAsync(CancellationToken cancellationToken);
    Task<BackendConfigurationSnapshot> GetConfigurationSnapshotAsync(CancellationToken cancellationToken);
    Task<BackendConfigurationSaveResult> SaveSettingsAsync(JsonElement settings, CancellationToken cancellationToken);
    Task<BackendConfigurationSaveResult> SaveSettingsAsync(
        JsonElement settings,
        string expectedRevision,
        CancellationToken cancellationToken);
}

public sealed record BackendConfigurationSnapshot(JsonElement Settings, string Revision);

public sealed record BackendConfigurationSaveResult(
    bool Saved,
    IReadOnlyDictionary<string, string[]> Errors,
    string? Revision = null,
    string? CurrentRevision = null,
    bool Conflict = false);
