using iisidsd.Configuration;
using iisidsd.Detection;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Services;
using iisidsd.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Integration;

public sealed class FindingsAutoDenyIntegrationTests
{
    [Fact]
    public async Task SuspiciousEvent_PersistsFindingAndAuditsDryRunAutoDeny()
    {
        var contentRoot = Path.Combine(Path.GetTempPath(), "iisidsd-integration-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(contentRoot);
        var appCmd = new RecordingAppCmdRunner();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ContentRootPath = contentRoot,
            EnvironmentName = "Development"
        });
        builder.WebHost.UseTestServer();
        builder.Services.Configure<StorageOptions>(options =>
        {
            options.DatabasePath = Path.Combine(contentRoot, "events.sqlite3");
            options.EventRetentionLimit = 100;
        });
        builder.Services.Configure<IisEtwOptions>(options => options.SubscriptionBufferSize = 100);
        builder.Services.Configure<DetectionOptions>(options =>
        {
            options.RateThreshold = 1000;
            options.PathScanUniquePathThreshold = 1000;
        });
        builder.Services.Configure<IisAdminOptions>(options =>
        {
            options.EnableDenyListChanges = true;
            options.DryRun = true;
            options.RequireMultipleIndicators = true;
        });
        builder.Services.AddSingleton<IisObservability>();
        builder.Services.AddSingleton<IFindingStore, SqliteFindingStore>();
        builder.Services.AddSingleton<IEventStore, SqliteEventStore>();
        builder.Services.AddSingleton<IDenyListStore, SqliteDenyListStore>();
        builder.Services.AddSingleton<IBanCountService, BanCountService>();
        builder.Services.AddSingleton<IIpAllowList, IisIpAllowList>();
        builder.Services.AddSingleton<IIisSiteDiscoveryService, FakeSiteDiscoveryService>();
        builder.Services.AddSingleton<IAppCmdRunner>(appCmd);
        builder.Services.AddSingleton<IIisDenyListService, IisDenyListService>();
        builder.Services.AddSingleton<IIisAutoDenyService, IisAutoDenyService>();
        builder.Services.AddSingleton<ISuspiciousActivityDetector, SuspiciousActivityDetector>();
        builder.Services.AddHostedService<EventDbInitializer>();

        var app = builder.Build();
        try
        {
            await app.StartAsync();
            var services = app.Services;
            var originalEvent = new SecurityEvent(
                DateTimeOffset.UtcNow,
                "server01",
                "example.test",
                "TRACE",
                "/.env",
                "203.0.113.90",
                404,
                "sqlmap/1.0",
                new Dictionary<string, string>());
            var suspiciousEvent = services.GetRequiredService<ISuspiciousActivityDetector>().Analyze(originalEvent);

            Assert.NotNull(suspiciousEvent);
            Assert.True(suspiciousEvent.IsSuspicious);
            Assert.True(suspiciousEvent.RiskScore >= 8);
            services.GetRequiredService<IEventStore>().Publish(suspiciousEvent);
            services.GetRequiredService<IIisAutoDenyService>().Apply(suspiciousEvent);

            var finding = Assert.IsType<IpFinding>(
                services.GetRequiredService<IFindingStore>().Get(originalEvent.ClientIp));
            Assert.Equal(1, finding.RequestCount);
            Assert.Equal(1, finding.SuspiciousRequestCount);
            Assert.Equal(suspiciousEvent.RiskScore, finding.HighestRiskScore);
            Assert.Contains("example.test", finding.Domains);
            Assert.Contains("known scanner user-agent", finding.RiskIndicators);

            var audits = services.GetRequiredService<IDenyListStore>().GetRecentAudit(10);
            Assert.Equal(2, audits.Count);
            Assert.All(audits, audit =>
            {
                Assert.Equal("system:auto-deny", audit.Actor);
                Assert.Equal("add", audit.Action);
                Assert.True(audit.DryRun);
            });
            Assert.Contains(audits, audit => audit.Outcome == "requested");
            Assert.Contains(audits, audit => audit.Outcome == "simulated");
            Assert.Empty(appCmd.Calls);
        }
        finally
        {
            await app.StopAsync();
            await app.DisposeAsync();
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(contentRoot))
            {
                Directory.Delete(contentRoot, recursive: true);
            }
        }
    }

    private sealed class RecordingAppCmdRunner : IAppCmdRunner
    {
        public List<string[]> Calls { get; } = [];

        public (bool Success, string Output, string Error) Run(params string[] arguments)
        {
            Calls.Add(arguments);
            return (true, string.Empty, string.Empty);
        }
    }

    private sealed class FakeSiteDiscoveryService : IIisSiteDiscoveryService
    {
        public IReadOnlyList<IisSiteInfo> GetSites() => [];
        public IisSiteInfo? FindSiteByDomain(string domain) => null;
    }
}
