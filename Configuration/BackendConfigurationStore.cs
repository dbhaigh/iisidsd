using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using iisidsd.Iis;
using iisidsd.Models;

namespace iisidsd.Configuration;

public sealed class BackendConfigurationStore(IHostEnvironment hostEnvironment) : IBackendConfigurationStore
{
    private static readonly string[] EditableSections =
    [
        "Urls",
        "Logging",
        "IisEtw",
        "Detection",
        "Notifications",
        "Storage",
        "IisAdmin",
        "Dashboard",
        "Tray",
        "OpenTelemetry"
    ];

    private static readonly byte[] RevisionKey = RandomNumberGenerator.GetBytes(32);

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    private static readonly JsonSerializerOptions InputSerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true
    };

    private readonly string _settingsPath = Path.Combine(hostEnvironment.ContentRootPath, "appsettings.json");
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public async Task<JsonElement> GetSettingsAsync(CancellationToken cancellationToken)
    {
        return (await GetConfigurationSnapshotAsync(cancellationToken)).Settings;
    }

    public async Task<BackendConfigurationSnapshot> GetConfigurationSnapshotAsync(CancellationToken cancellationToken)
    {
        var contents = await File.ReadAllTextAsync(_settingsPath, cancellationToken);
        var root = JsonNode.Parse(contents) as JsonObject
            ?? throw new InvalidDataException("The appsettings.json root must be a JSON object.");
        var settings = new EditableBackendConfiguration
        {
            Urls = ReadRootValue(root, "Urls", "http://localhost:5080"),
            Logging = ReadSection(root, "Logging", new LoggingSettings()),
            IisEtw = ReadSection(root, "IisEtw", new IisEtwOptions()),
            Detection = ReadSection(root, "Detection", new DetectionOptions()),
            Notifications = ReadSection(root, NotificationOptions.SectionName, new NotificationOptions()),
            Storage = ReadSection(root, "Storage", new StorageOptions()),
            IisAdmin = ReadSection(root, "IisAdmin", new IisAdminOptions()),
            Dashboard = ReadSection(root, DashboardOptions.SectionName, new DashboardOptions()),
            Tray = ReadSection(root, "Tray", new TrayOptions()),
            OpenTelemetry = ReadSection(root, "OpenTelemetry", new OpenTelemetrySettings())
        };
        settings = settings with
        {
            Urls = RedactUrls(settings.Urls),
            Tray = new TrayOptions { BrowserUrl = RedactEndpoint(settings.Tray.BrowserUrl) },
            OpenTelemetry = settings.OpenTelemetry with
            {
                OtlpEndpoint = RedactEndpoint(settings.OpenTelemetry.OtlpEndpoint)
            }
        };

        return new BackendConfigurationSnapshot(
            JsonSerializer.SerializeToElement(settings, SerializerOptions),
            ComputeRevision(contents));
    }

    public async Task<BackendConfigurationSaveResult> SaveSettingsAsync(
        JsonElement settings,
        CancellationToken cancellationToken)
    {
        var snapshot = await GetConfigurationSnapshotAsync(cancellationToken);
        return await SaveSettingsAsync(settings, snapshot.Revision, cancellationToken);
    }

    public async Task<BackendConfigurationSaveResult> SaveSettingsAsync(
        JsonElement settings,
        string expectedRevision,
        CancellationToken cancellationToken)
    {
        var errors = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        if (settings.ValueKind != JsonValueKind.Object)
        {
            AddError(errors, "settings", "Settings must be a JSON object.");
            return new BackendConfigurationSaveResult(false, ToReadOnlyErrors(errors));
        }

        ValidateUniqueProperties(settings, "settings", errors);
        var submittedSections = settings.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var section in submittedSections)
        {
            if (!EditableSections.Contains(section, StringComparer.OrdinalIgnoreCase))
            {
                AddError(errors, $"settings.{section}", "This setting is not editable from the dashboard.");
            }
        }

        if (errors.Count > 0)
        {
            return new BackendConfigurationSaveResult(false, ToReadOnlyErrors(errors));
        }

        if (submittedSections.Count == 0)
        {
            AddError(errors, "settings", "At least one setting must be provided.");
            return new BackendConfigurationSaveResult(false, ToReadOnlyErrors(errors));
        }

        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            var currentSnapshot = await GetConfigurationSnapshotAsync(cancellationToken);
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(expectedRevision),
                    Convert.FromHexString(currentSnapshot.Revision)))
            {
                return new BackendConfigurationSaveResult(
                    false,
                    new Dictionary<string, string[]>(),
                    CurrentRevision: currentSnapshot.Revision,
                    Conflict: true);
            }

            var currentSettings = currentSnapshot.Settings;
            var mergedSettings = JsonNode.Parse(currentSettings.GetRawText()) as JsonObject
                ?? throw new InvalidDataException("Unable to load the editable backend settings.");
            var patch = JsonNode.Parse(settings.GetRawText()) as JsonObject
                ?? throw new InvalidDataException("The configuration patch must be a JSON object.");
            MergeObjects(mergedSettings, patch);

            using var mergedDocument = JsonDocument.Parse(mergedSettings.ToJsonString(SerializerOptions));
            EditableBackendConfiguration? configuration;
            try
            {
                configuration = mergedDocument.RootElement.Deserialize<EditableBackendConfiguration>(InputSerializerOptions);
            }
            catch (JsonException exception)
            {
                AddError(errors, "settings", exception.Message);
                return new BackendConfigurationSaveResult(false, ToReadOnlyErrors(errors));
            }

            if (configuration is null ||
                configuration.Logging?.LogLevel is null ||
                configuration.IisEtw is null ||
                configuration.Detection is null ||
                configuration.Notifications is null ||
                configuration.Storage is null ||
                configuration.IisAdmin is null ||
                configuration.Dashboard is null ||
                configuration.Tray is null ||
                configuration.OpenTelemetry is null)
            {
                AddError(errors, "settings", "The configuration is missing one or more required sections.");
                return new BackendConfigurationSaveResult(false, ToReadOnlyErrors(errors));
            }

            Validate(configuration, errors);
            if (errors.Count > 0)
            {
                return new BackendConfigurationSaveResult(false, ToReadOnlyErrors(errors));
            }

            var root = await ReadSettingsFileAsync(cancellationToken);
            var existingUrls = ReadRootValue(root, "Urls", "http://localhost:5080");
            var urlsToSave = string.Equals(configuration.Urls, RedactUrls(existingUrls), StringComparison.Ordinal)
                ? existingUrls
                : configuration.Urls;
            var existingBrowserUrl = ReadSectionValue(root, "Tray", "BrowserUrl", "http://localhost:5080/");
            var browserUrlToSave = string.Equals(
                configuration.Tray.BrowserUrl,
                RedactEndpoint(existingBrowserUrl),
                StringComparison.Ordinal)
                ? existingBrowserUrl
                : configuration.Tray.BrowserUrl;
            var existingOtlpEndpoint = ReadSectionValue(root, "OpenTelemetry", "OtlpEndpoint", "");
            var endpointToSave = string.Equals(
                configuration.OpenTelemetry.OtlpEndpoint,
                RedactEndpoint(existingOtlpEndpoint),
                StringComparison.Ordinal)
                ? existingOtlpEndpoint
                : configuration.OpenTelemetry.OtlpEndpoint;

            var replacement = JsonSerializer.SerializeToNode(configuration with
            {
                Urls = urlsToSave,
                Tray = new TrayOptions { BrowserUrl = browserUrlToSave },
                OpenTelemetry = configuration.OpenTelemetry with { OtlpEndpoint = endpointToSave }
            }, SerializerOptions) as JsonObject
                ?? throw new InvalidDataException("Unable to serialize backend settings.");
            MergeObjects(root, replacement);

            var temporaryDirectory = Path.Combine(Path.GetDirectoryName(_settingsPath)!, "data");
            Directory.CreateDirectory(temporaryDirectory);
            var temporaryPath = Path.Combine(temporaryDirectory, $"appsettings.{Guid.NewGuid():N}.tmp");
            try
            {
                var serialized = root.ToJsonString(SerializerOptions);
                await File.WriteAllTextAsync(temporaryPath, serialized, new UTF8Encoding(false), cancellationToken);
                File.Move(temporaryPath, _settingsPath, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }
        }
        finally
        {
            _writeLock.Release();
        }

        var savedSnapshot = await GetConfigurationSnapshotAsync(cancellationToken);
        return new BackendConfigurationSaveResult(true, new Dictionary<string, string[]>(), savedSnapshot.Revision);
    }

    private static string ComputeRevision(string contents)
        => Convert.ToHexString(HMACSHA256.HashData(RevisionKey, Encoding.UTF8.GetBytes(contents)))[..24].ToLowerInvariant();

    private async Task<JsonObject> ReadSettingsFileAsync(CancellationToken cancellationToken)
    {
        var contents = await File.ReadAllTextAsync(_settingsPath, cancellationToken);
        return JsonNode.Parse(contents) as JsonObject
            ?? throw new InvalidDataException("The appsettings.json root must be a JSON object.");
    }

    private static T ReadSection<T>(JsonObject root, string section, T defaultValue)
        where T : class
    {
        var value = FindProperty(root, section)?.Value;
        return value?.Deserialize<T>(SerializerOptions) ?? defaultValue;
    }

    private static string ReadRootValue(JsonObject root, string name, string defaultValue)
        => FindProperty(root, name)?.Value?.GetValue<string>() ?? defaultValue;

    private static string ReadSectionValue(JsonObject root, string section, string key, string defaultValue)
    {
        var sectionValue = FindProperty(root, section)?.Value as JsonObject;
        var value = sectionValue is null
            ? FindProperty(root, section)?.Value
            : FindProperty(sectionValue, key)?.Value;
        return value?.GetValue<string>() ?? defaultValue;
    }

    private static KeyValuePair<string, JsonNode?>? FindProperty(JsonObject value, string name)
    {
        foreach (var property in value)
        {
            if (string.Equals(property.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return property;
            }
        }

        return null;
    }

    private static void Validate(EditableBackendConfiguration configuration, Dictionary<string, List<string>> errors)
    {
        ValidateDataAnnotations(configuration.IisEtw, "settings.IisEtw", errors);
        ValidateDataAnnotations(configuration.Detection, "settings.Detection", errors);
        ValidateDataAnnotations(configuration.Notifications, "settings.Notifications", errors);
        ValidateDataAnnotations(configuration.Storage, "settings.Storage", errors);
        ValidateDataAnnotations(configuration.IisAdmin, "settings.IisAdmin", errors);
        ValidateDataAnnotations(configuration.Dashboard, "settings.Dashboard", errors);
        ValidateDataAnnotations(configuration.Tray, "settings.Tray", errors);
        if (configuration.Logging.LogLevel.Count == 0)
        {
            AddError(errors, "settings.Logging.LogLevel", "At least one log level must be configured.");
        }

        foreach (var logLevel in configuration.Logging.LogLevel)
        {
            ValidateLogLevel(logLevel.Value, $"settings.Logging.LogLevel.{logLevel.Key}", errors);
        }

        if (configuration.IisEtw.ProviderId == Guid.Empty)
        {
            AddError(errors, "settings.IisEtw.ProviderId", "ProviderId must not be empty.");
        }

        if (!configuration.Notifications.IsValid())
        {
            AddError(errors, "settings.Notifications", "Provider, severity, retry settings, and local dashboard URL must be valid; delivery requires an explicit provider.");
        }

        if (configuration.IisAdmin.AllowList is null ||
            !IisIpAllowList.IsValidAllowList(configuration.IisAdmin.AllowList))
        {
            AddError(errors, "settings.IisAdmin.AllowList", "AllowList must contain only valid IP addresses or CIDR ranges.");
        }

        if (!IisAdminOptions.IsValidEnforcementMode(configuration.IisAdmin.EnforcementMode))
        {
            AddError(errors, "settings.IisAdmin.EnforcementMode", "EnforcementMode must be Observe, Simulate, or Enforce.");
        }

        if (!configuration.Dashboard.TryGetCanonicalAllowedHosts(out _))
        {
            AddError(errors, "settings.Dashboard.AllowedHosts", "AllowedHosts must contain valid hostnames or exact IP addresses without ports or wildcards.");
        }

        if (!Uri.TryCreate(configuration.Tray.BrowserUrl, UriKind.Absolute, out var browserUri) ||
            (browserUri.Scheme != Uri.UriSchemeHttp && browserUri.Scheme != Uri.UriSchemeHttps) ||
            !string.IsNullOrEmpty(browserUri.UserInfo))
        {
            AddError(errors, "settings.Tray.BrowserUrl", "BrowserUrl must be an absolute HTTP or HTTPS URL without credentials.");
        }

        var urls = configuration.Urls?.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries) ?? [];
        if (urls.Length == 0 || urls.Any(url =>
                !Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
                !string.IsNullOrEmpty(uri.UserInfo)))
        {
            AddError(errors, "settings.Urls", "Urls must contain one or more absolute HTTP or HTTPS listener addresses without credentials.");
        }

        var otlpEndpoint = configuration.OpenTelemetry.OtlpEndpoint;
        if (!string.IsNullOrWhiteSpace(otlpEndpoint) &&
            (!Uri.TryCreate(otlpEndpoint, UriKind.Absolute, out var endpointUri) ||
             (endpointUri.Scheme != Uri.UriSchemeHttp && endpointUri.Scheme != Uri.UriSchemeHttps) ||
             !string.IsNullOrEmpty(endpointUri.UserInfo)))
        {
            AddError(errors, "settings.OpenTelemetry.OtlpEndpoint", "OtlpEndpoint must be empty or an HTTP/HTTPS URL without credentials.");
        }
    }

    private static void ValidateDataAnnotations(object value, string prefix, Dictionary<string, List<string>> errors)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(value, new ValidationContext(value), results, validateAllProperties: true);
        foreach (var result in results)
        {
            var field = result.MemberNames.FirstOrDefault();
            AddError(errors, field is null ? prefix : $"{prefix}.{field}", result.ErrorMessage ?? "The value is invalid.");
        }
    }

    private static void ValidateUniqueProperties(JsonElement value, string path, Dictionary<string, List<string>> errors)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in value.EnumerateObject())
            {
                var propertyPath = $"{path}.{property.Name}";
                if (!names.Add(property.Name))
                {
                    AddError(errors, propertyPath, "Duplicate setting names are not allowed.");
                }

                ValidateUniqueProperties(property.Value, propertyPath, errors);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in value.EnumerateArray())
            {
                ValidateUniqueProperties(item, $"{path}[{index}]", errors);
                index++;
            }
        }
    }

    private static void MergeObjects(JsonObject target, JsonObject updates)
    {
        foreach (var update in updates)
        {
            var existing = FindProperty(target, update.Key);
            if (existing?.Value is JsonObject existingObject && update.Value is JsonObject updateObject)
            {
                MergeObjects(existingObject, updateObject);
            }
            else if (existing is not null)
            {
                target[existing.Value.Key] = update.Value?.DeepClone();
            }
            else
            {
                target[update.Key] = update.Value?.DeepClone();
            }
        }
    }

    private static string RedactEndpoint(string? endpoint)
    {
        if (Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.UserInfo))
        {
            return new UriBuilder(uri) { UserName = "", Password = "" }.Uri.ToString();
        }

        return endpoint?.Contains('@', StringComparison.Ordinal) == true ? "[redacted]" : endpoint ?? "";
    }

    private static string RedactUrls(string urls)
        => string.Join(
            ';',
            urls.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(RedactEndpoint));

    private static void ValidateLogLevel(string level, string field, Dictionary<string, List<string>> errors)
    {
        if (!new[] { "Trace", "Debug", "Information", "Warning", "Error", "Critical", "None" }
                .Contains(level, StringComparer.OrdinalIgnoreCase))
        {
            AddError(errors, field, "Log level must be Trace, Debug, Information, Warning, Error, Critical, or None.");
        }
    }

    private static void AddError(Dictionary<string, List<string>> errors, string field, string message)
    {
        if (!errors.TryGetValue(field, out var messages))
        {
            messages = [];
            errors[field] = messages;
        }

        messages.Add(message);
    }

    private static IReadOnlyDictionary<string, string[]> ToReadOnlyErrors(Dictionary<string, List<string>> errors)
        => errors.ToDictionary(pair => pair.Key, pair => pair.Value.ToArray(), StringComparer.OrdinalIgnoreCase);

    private sealed record EditableBackendConfiguration
    {
        public string Urls { get; init; } = "http://localhost:5080";
        public LoggingSettings Logging { get; init; } = new();
        public IisEtwOptions IisEtw { get; init; } = new();
        public DetectionOptions Detection { get; init; } = new();
        public NotificationOptions Notifications { get; init; } = new();
        public StorageOptions Storage { get; init; } = new();
        public IisAdminOptions IisAdmin { get; init; } = new();
        public DashboardOptions Dashboard { get; init; } = new();
        public TrayOptions Tray { get; init; } = new();
        public OpenTelemetrySettings OpenTelemetry { get; init; } = new();
    }

    private sealed record LoggingSettings
    {
        public Dictionary<string, string> LogLevel { get; init; } = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Default"] = "Information",
            ["Microsoft.Hosting.Lifetime"] = "Information"
        };
    }

    private sealed record OpenTelemetrySettings
    {
        public string OtlpEndpoint { get; init; } = "";
    }
}
