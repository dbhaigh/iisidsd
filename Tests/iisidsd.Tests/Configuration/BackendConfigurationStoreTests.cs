using System.Text.Json;
using System.Text.Json.Nodes;
using iisidsd.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace iisidsd.Tests.Configuration;

public sealed class BackendConfigurationStoreTests : IAsyncLifetime
{
    private readonly string _contentRoot = Path.Combine(Path.GetTempPath(), "iisidsd-configuration-tests", Guid.NewGuid().ToString("N"));
    private BackendConfigurationStore _store = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_contentRoot);
        await File.WriteAllTextAsync(Path.Combine(_contentRoot, "appsettings.json"), TestSettings);
        _store = new BackendConfigurationStore(new TestHostEnvironment(_contentRoot));
    }

    public Task DisposeAsync()
    {
        if (Directory.Exists(_contentRoot))
        {
            Directory.Delete(_contentRoot, recursive: true);
        }

        return Task.CompletedTask;
    }

    [Fact]
    public async Task GetSettingsAsync_ReturnsSupportedSettingsWithoutSecrets()
    {
        var settings = await _store.GetSettingsAsync(CancellationToken.None);
        var json = settings.GetRawText();

        Assert.Contains("\"IisEtw\"", json);
        Assert.Contains("\"Detection\"", json);
        Assert.Contains("\"Storage\"", json);
        Assert.DoesNotContain("hidden-secret", json);
        Assert.DoesNotContain("Kestrel", json);
        Assert.Equal(
            "https://collector.example/v1",
            settings.GetProperty("OpenTelemetry").GetProperty("OtlpEndpoint").GetString());
    }

    [Fact]
    public async Task SaveSettingsAsync_UpdatesValuesAndPreservesUnexposedSettingsAndEndpointCredentials()
    {
        using var request = JsonDocument.Parse("""{"Detection":{"RateThreshold":90}}""");

        var result = await _store.SaveSettingsAsync(request.RootElement, CancellationToken.None);

        Assert.True(result.Saved);
        Assert.Empty(result.Errors);
        var saved = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(_contentRoot, "appsettings.json")))!.AsObject();
        Assert.Equal("http://127.0.0.1:5080", saved["Urls"]!.GetValue<string>());
        Assert.Equal(90, saved["Detection"]!["RateThreshold"]!.GetValue<int>());
        Assert.Equal("hidden-secret", saved["Kestrel"]!["Certificates"]!["Default"]!["Password"]!.GetValue<string>());
        Assert.Equal("https://user:secret@collector.example/v1", saved["OpenTelemetry"]!["OtlpEndpoint"]!.GetValue<string>());
        Assert.Equal("preserve-me", saved["CustomExtension"]!["Value"]!.GetValue<string>());
    }

    [Fact]
    public async Task SaveSettingsAsync_RejectsInvalidValuesWithoutChangingTheFile()
    {
        var original = await File.ReadAllTextAsync(Path.Combine(_contentRoot, "appsettings.json"));
        var settings = await _store.GetSettingsAsync(CancellationToken.None);
        var settingsNode = JsonNode.Parse(settings.GetRawText())!.AsObject();
        settingsNode["IisEtw"]!["ProviderId"] = Guid.Empty.ToString();
        using var request = JsonDocument.Parse(settingsNode.ToJsonString());

        var result = await _store.SaveSettingsAsync(request.RootElement, CancellationToken.None);

        Assert.False(result.Saved);
        Assert.Contains("settings.IisEtw.ProviderId", result.Errors.Keys);
        Assert.Equal(original, await File.ReadAllTextAsync(Path.Combine(_contentRoot, "appsettings.json")));
    }

      [Theory]
      [InlineData("""{"Urls":"https://user:secret@127.0.0.1:5080"}""", "settings.Urls")]
      [InlineData("""{"IisEtw":{"IngestionBufferSize":0}}""", "settings.IisEtw.IngestionBufferSize")]
      [InlineData("""{"IisEtw":{"ProcessingBatchSize":0}}""", "settings.IisEtw.ProcessingBatchSize")]
      [InlineData("""{"Storage":{"JournalMode":"OFF"}}""", "settings.Storage.JournalMode")]
      [InlineData("""{"Storage":{"SynchronousMode":"OFF"}}""", "settings.Storage.SynchronousMode")]
      [InlineData("""{"Storage":{"BusyTimeoutSeconds":0}}""", "settings.Storage.BusyTimeoutSeconds")]
      [InlineData("""{"IisAdmin":{"AllowList":["192.0.2.1/99"]}}""", "settings.IisAdmin.AllowList")]
      [InlineData("""{"IisAdmin":{"EnforcementMode":"immediate"}}""", "settings.IisAdmin.EnforcementMode")]
      [InlineData("""{"Dashboard":{"AllowedHosts":["*"]}}""", "settings.Dashboard.AllowedHosts")]
      [InlineData("""{"OpenTelemetry":{"OtlpEndpoint":"https://user:secret@collector.example/v1"}}""", "settings.OpenTelemetry.OtlpEndpoint")]
      public async Task SaveSettingsAsync_RejectsUnsafeAndOutOfRangePatchesWithoutChangingTheFile(
        string json,
        string expectedError)
      {
        var original = await File.ReadAllTextAsync(Path.Combine(_contentRoot, "appsettings.json"));
        using var request = JsonDocument.Parse(json);

        var result = await _store.SaveSettingsAsync(request.RootElement, CancellationToken.None);

        Assert.False(result.Saved);
        Assert.Contains(expectedError, result.Errors.Keys);
        Assert.Equal(original, await File.ReadAllTextAsync(Path.Combine(_contentRoot, "appsettings.json")));
      }

    private const string TestSettings = """
        {
          "Urls": "http://127.0.0.1:5080",
          "Logging": {
            "LogLevel": {
              "Default": "Information",
              "Microsoft.Hosting.Lifetime": "Information"
            }
          },
          "IisEtw": {
            "Enabled": true,
            "ProviderName": "Microsoft-Windows-IIS-Logging",
            "ProviderId": "7e8ad27f-b271-4ea2-a783-a47bde29143b",
            "SessionName": "iisidsd-test",
            "SubscriptionBufferSize": 1000,
            "IngestionBufferSize": 10000
          },
          "Detection": {},
          "Storage": {},
          "IisAdmin": {},
          "Dashboard": {
            "RemoteAccessEnabled": false
          },
          "Tray": {
            "BrowserUrl": "http://127.0.0.1:5080/"
          },
          "OpenTelemetry": {
            "OtlpEndpoint": "https://user:secret@collector.example/v1"
          },
          "Kestrel": {
            "Certificates": {
              "Default": {
                "Password": "hidden-secret"
              }
            }
          },
          "CustomExtension": {
            "Value": "preserve-me"
          }
        }
        """;

    private sealed class TestHostEnvironment(string contentRootPath) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "iisidsd.Tests";
        public string ContentRootPath { get; set; } = contentRootPath;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
