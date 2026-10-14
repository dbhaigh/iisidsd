using iisidsd.Configuration;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Iis;

public sealed class IisAutoDenyServiceTests
{
    [Fact]
    public void Apply_HighSeverityWithoutRepeatedEvidence_DoesNothing()
    {
        var denyListService = new FakeIisDenyListService(["example.test-site"]);
        var banCountService = new FakeBanCountService();
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true });
        var service = new IisAutoDenyService(
            denyListService,
            banCountService,
            new IisIpAllowList(options),
            options,
            NullLogger<IisAutoDenyService>.Instance);
        var securityEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/admin",
            "203.0.113.7",
            404,
            "unit-test",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            DetectionReason: "suspicious request URI",
            RiskScore: 5,
            RiskSeverity: "High",
            RiskIndicators: ["suspicious request URI pattern"]);

        service.Apply(securityEvent);

        Assert.Empty(denyListService.Requests);
        Assert.Empty(banCountService.IncrementRequests);
    }

    [Fact]
    public void Apply_RepeatedNotFoundEvidence_AddsToDenyListAndIncrementsBanCount()
    {
        var denyListService = new FakeIisDenyListService(["example.test-site"]);
        var banCountService = new FakeBanCountService();
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var service = new IisAutoDenyService(
            denyListService,
            banCountService,
            new IisIpAllowList(options),
            options,
            NullLogger<IisAutoDenyService>.Instance);
        var securityEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/missing",
            "203.0.113.7",
            404,
            "unit-test",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            DetectionReason: "repeated not found probing",
            RiskScore: 4,
            RiskSeverity: "High",
            RiskIndicators: ["suspicious status code", "multiple 404 responses from the same client IP"]);

        service.Apply(securityEvent);

        Assert.Single(denyListService.Requests);
        Assert.Equal("203.0.113.7", denyListService.Requests[0].ClientIp);
        Assert.Equal("example.test", Assert.Single(denyListService.Requests[0].Domains));
        Assert.Equal("system:auto-deny", denyListService.Requests[0].Actor);
        Assert.Single(banCountService.IncrementRequests);
    }

    [Fact]
    public void Apply_CriticalEventWithMultipleIndicators_AddsToDenyList()
    {
        var denyListService = new FakeIisDenyListService(["example.test-site"]);
        var banCountService = new FakeBanCountService();
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var service = new IisAutoDenyService(
            denyListService,
            banCountService,
            new IisIpAllowList(options),
            options,
            NullLogger<IisAutoDenyService>.Instance);
        var securityEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "TRACE",
            "/.env",
            "203.0.113.7",
            404,
            "sqlmap/1.0",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            DetectionReason: "known security scanner user-agent",
            RiskScore: 12,
            RiskSeverity: "Critical",
            RiskIndicators: ["suspicious status", "suspicious request URI pattern", "known scanner user-agent"]);

        service.Apply(securityEvent);

        Assert.Single(denyListService.Requests);
        Assert.Single(banCountService.IncrementRequests);
    }

    [Fact]
    public void Apply_MediumSeverityEvent_DoesNothing()
    {
        var denyListService = new FakeIisDenyListService(["example.test-site"]);
        var banCountService = new FakeBanCountService();
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true });
        var service = new IisAutoDenyService(
            denyListService,
            banCountService,
            new IisIpAllowList(options),
            options,
            NullLogger<IisAutoDenyService>.Instance);
        var securityEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/missing",
            "203.0.113.8",
            404,
            "unit-test",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            DetectionReason: "probing/error response",
            RiskScore: 1,
            RiskSeverity: "Medium",
            RiskIndicators: ["suspicious status code (401/403/404)"]);

        service.Apply(securityEvent);

        Assert.Empty(denyListService.Requests);
        Assert.Empty(banCountService.IncrementRequests);
    }

    [Fact]
    public void Apply_WhenDenyListChangesDisabled_DoesNothing()
    {
        var denyListService = new FakeIisDenyListService(["example.test-site"]);
        var banCountService = new FakeBanCountService();
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = false });
        var service = new IisAutoDenyService(
            denyListService,
            banCountService,
            new IisIpAllowList(options),
            options,
            NullLogger<IisAutoDenyService>.Instance);
        var securityEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "TRACE",
            "/home",
            "203.0.113.9",
            404,
            "sqlmap/1.0",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            DetectionReason: "known security scanner user-agent",
            RiskScore: 10,
            RiskSeverity: "Critical",
            RiskIndicators: ["known scanner user-agent"]);

        service.Apply(securityEvent);

        Assert.Empty(denyListService.Requests);
        Assert.Empty(banCountService.IncrementRequests);
    }

    [Fact]
    public void Apply_RequireMultipleIndicatorsSkipsSingleIndicatorRepeatedNotFound()
    {
        var denyListService = new FakeIisDenyListService(["example.test-site"]);
        var banCountService = new FakeBanCountService();
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true });
        var service = new IisAutoDenyService(
            denyListService,
            banCountService,
            new IisIpAllowList(options),
            options,
            NullLogger<IisAutoDenyService>.Instance);
        var securityEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/missing",
            "203.0.113.10",
            404,
            "unit-test",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            RiskSeverity: "High",
            RiskIndicators: ["multiple 404 responses from the same client IP"]);

        service.Apply(securityEvent);

        Assert.Empty(denyListService.Requests);
    }

    [Fact]
    public void Apply_AllowListedIpIsNeverDenied()
    {
        var denyListService = new FakeIisDenyListService(["example.test-site"]);
        var banCountService = new FakeBanCountService();
        var options = Options.Create(new IisAdminOptions
        {
            EnableDenyListChanges = true,
            AllowList = ["203.0.113.0/24"]
        });
        var service = new IisAutoDenyService(
            denyListService,
            banCountService,
            new IisIpAllowList(options),
            options,
            NullLogger<IisAutoDenyService>.Instance);
        var securityEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "TRACE",
            "/.env",
            "203.0.113.11",
            404,
            "sqlmap/1.0",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            RiskSeverity: "Critical",
            RiskIndicators: ["path traversal", "known scanner user-agent"]);

        service.Apply(securityEvent);

        Assert.Empty(denyListService.Requests);
        Assert.Empty(banCountService.IncrementRequests);
    }

    [Fact]
    public void Apply_DryRunLogsPlannedDenyWithoutIncrementingBanCounts()
    {
        var denyListService = new FakeIisDenyListService(["example.test-site"]);
        var banCountService = new FakeBanCountService();
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = true });
        var service = new IisAutoDenyService(
            denyListService,
            banCountService,
            new IisIpAllowList(options),
            options,
            NullLogger<IisAutoDenyService>.Instance);
        var securityEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "TRACE",
            "/.env",
            "203.0.113.12",
            404,
            "sqlmap/1.0",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            RiskSeverity: "Critical",
            RiskIndicators: ["path traversal", "known scanner user-agent"]);

        service.Apply(securityEvent);

        Assert.Single(denyListService.Requests);
        Assert.Empty(banCountService.IncrementRequests);
    }

    private sealed class FakeIisDenyListService(IReadOnlyList<string> sitesToUpdate) : IIisDenyListService
    {
        public List<(string ClientIp, IReadOnlyList<string> Domains, string Actor, string Reason)> Requests { get; } = [];

        public IReadOnlyList<string> GetDeniedIps(string siteName) => [];

        public bool AddDeniedIp(
            string siteName,
            string clientIp,
            string actor = "manual",
            string reason = "Manual deny-list request",
            SecurityEvent? securityEvent = null,
            string? domain = null) => true;

        public IReadOnlyList<string> AddDeniedIpToDomains(
            string clientIp,
            IEnumerable<string> domains,
            string actor = "manual",
            string reason = "Manual deny-list request",
            SecurityEvent? securityEvent = null)
        {
            Requests.Add((clientIp, domains.ToArray(), actor, reason));
            return sitesToUpdate;
        }

        public bool RemoveDeniedIp(string siteName, string clientIp, string actor = "manual", string reason = "Manual deny-list removal") => true;

        public bool RemoveExpiredDeniedIp(TemporaryDenyListEntry entry) => true;
    }

    private sealed class FakeBanCountService : IBanCountService
    {
        public List<(string ClientIp, IReadOnlyList<string> Domains)> IncrementRequests { get; } = [];

        public IReadOnlyList<BanCountRecord> GetBanCounts(int limit, string? domain = null) => [];

        public IReadOnlyDictionary<string, BanCountRecord> GetBanCounts(IEnumerable<string> clientIps, string? domain = null)
            => new Dictionary<string, BanCountRecord>(StringComparer.OrdinalIgnoreCase);

        public BanCountRecord GetBanCount(string clientIp, string? domain = null)
            => new(clientIp, 0, DateTimeOffset.UtcNow);

        public BanCountRecord SetBanCount(string clientIp, int banCount, string? domain = null)
            => new(clientIp, banCount, DateTimeOffset.UtcNow);

        public void IncrementBanCounts(string clientIp, IEnumerable<string> domains)
            => IncrementRequests.Add((clientIp, domains.ToArray()));
    }
}
