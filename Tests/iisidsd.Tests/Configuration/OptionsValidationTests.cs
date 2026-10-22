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
        ["Detection:NotFoundBurstWindowSeconds", "0"],
        ["Detection:NotFoundBurstThreshold", "1"],
        ["Detection:AuthenticationFailureThreshold", "1"],
        ["Detection:AuthenticationFailureWindowSeconds", "0"],
        ["Detection:RateWindowSeconds", "301"],
        ["Detection:MaximumTrackedClientHistories", "0"],
        ["Detection:MaximumTrackedHistoryBuckets", "262145"],
        ["Detection:MaximumTrackedPathsPerHistory", "1025"],
        ["Detection:MaximumTrackedPathsTotal", "131073"],
        ["Detection:MaximumTrackedPathLengthCharacters", "63"],
        ["Detection:MaximumTrackedExtensionSites", "2049"],
        ["Detection:MaximumExtensionsPerSite", "257"],
        ["Detection:MaximumEventLatenessSeconds", "31"],
        ["TrustedProxies:Enabled", "true"],
        ["TrustedProxies:ForwardLimit", "11"],
        ["TrustedProxies:TrustedProxyIps:0", "127.0.0.1/8"],
        ["Dashboard:AllowedHosts:0", "*"],
        ["Dashboard:AllowedHosts:0", "dashboard.example:443"],
        ["Tray:BrowserUrl", "file:///C:/invalid"],
        ["Storage:EventRetentionDays", "0"],
        ["IisAdmin:AllowList:0", "invalid-address"],
        ["IisAdmin:EnforcementMode", "enabled"],
        ["IisAdmin:EnforcementMode", "1"],
        ["IisAdmin:EnforcementMode", "99"]
    ];

    [Theory]
    [InlineData(false, false, null, DenyListEnforcementMode.Observe, false)]
    [InlineData(true, true, null, DenyListEnforcementMode.Simulate, false)]
    [InlineData(true, false, null, DenyListEnforcementMode.Enforce, true)]
    [InlineData(true, false, "Observe", DenyListEnforcementMode.Observe, false)]
    [InlineData(true, false, "Simulate", DenyListEnforcementMode.Simulate, false)]
    [InlineData(true, false, "Enforce", DenyListEnforcementMode.Enforce, true)]
    [InlineData(false, false, "Enforce", DenyListEnforcementMode.Observe, false)]
    [InlineData(true, true, "Enforce", DenyListEnforcementMode.Simulate, false)]
    public void EnforcementPolicy_PreservesLegacySafetySettings(
        bool enabled,
        bool dryRun,
        string? explicitMode,
        DenyListEnforcementMode expectedMode,
        bool expectedCanMutate)
    {
        var policy = new IisAdminOptions
        {
            EnableDenyListChanges = enabled,
            DryRun = dryRun,
            EnforcementMode = explicitMode
        }.GetEnforcementPolicy();

        Assert.Equal(expectedMode, policy.Mode);
        Assert.Equal(expectedCanMutate, policy.CanMutate);
    }

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
