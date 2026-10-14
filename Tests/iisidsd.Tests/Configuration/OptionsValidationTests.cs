using iisidsd.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Configuration;

public sealed class OptionsValidationTests
{
    public static IEnumerable<object[]> InvalidSettings =>
    [
        ["IisEtw:SubscriptionBufferSize", "0"],
        ["Detection:StatusScoreWeight", "-1"],
        ["Tray:BrowserUrl", "file:///C:/invalid"],
        ["Storage:EventRetentionDays", "0"],
        ["IisAdmin:AllowList:0", "invalid-address"]
    ];

    [Theory]
    [MemberData(nameof(InvalidSettings))]
    public async Task InvalidOptions_FailDuringHostStartup(string key, string value)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [key] = value })
            .Build();
        using var host = new HostBuilder()
            .ConfigureServices(services => services.AddIisIdsdOptions(configuration))
            .Build();

        await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync());
    }

    [Fact]
    public async Task DefaultOptions_PassStartupValidation()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection()
            .Build();
        using var host = new HostBuilder()
            .ConfigureServices(services => services.AddIisIdsdOptions(configuration))
            .Build();

        await host.StartAsync();
        await host.StopAsync();
    }
}
