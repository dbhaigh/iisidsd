using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Services;
using iisidsd.Storage;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Services;

public sealed class IpAggregationServiceTests
{
    [Fact]
    public void GetFindings_GroupsEventsAndAppliesBanCounts()
    {
        var eventStore = new InMemoryEventStore(Options.Create(new IisEtwOptions { RetentionLimit = 100, SubscriptionBufferSize = 10 }));
        var suspiciousEvent = new SecurityEvent(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            "server01",
            "alpha.test",
            "GET",
            "/admin/../config",
            "198.51.100.24",
            404,
            "agent-a",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            DetectionReason: "HTTP status 404",
            RiskScore: 60,
            RiskSeverity: "High",
            RiskIndicators: ["path traversal"]);
        var followUpEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "beta.test",
            "GET",
            "/home",
            "198.51.100.24",
            200,
            "agent-a",
            new Dictionary<string, string>());

        eventStore.Publish(suspiciousEvent);
        eventStore.Publish(followUpEvent);

        var service = new IpAggregationService(
            eventStore,
            new FakeBanCountService(new Dictionary<string, BanCountRecord>(StringComparer.OrdinalIgnoreCase)
            {
                ["198.51.100.24"] = new("198.51.100.24", 3, DateTimeOffset.UtcNow)
            }),
            Options.Create(new StorageOptions { EventRetentionLimit = 100 }));

        var finding = Assert.Single(service.GetFindings(10));

        Assert.Equal("198.51.100.24", finding.ClientIp);
        Assert.Equal(2, finding.RequestCount);
        Assert.Equal(1, finding.SuspiciousRequestCount);
        Assert.Equal(60, finding.HighestRiskScore);
        Assert.Equal(3, finding.BanCount);
        Assert.Contains("alpha.test", finding.Domains);
        Assert.Contains("beta.test", finding.Domains);
    }

    private sealed class FakeBanCountService(IReadOnlyDictionary<string, BanCountRecord> records) : IBanCountService
    {
        private readonly IReadOnlyDictionary<string, BanCountRecord> _records = records;

        public IReadOnlyList<BanCountRecord> GetBanCounts(int limit)
            => _records.Values.Take(limit).ToArray();

        public IReadOnlyDictionary<string, BanCountRecord> GetBanCounts(IEnumerable<string> clientIps)
            => clientIps
                .Where(_records.ContainsKey)
                .ToDictionary(ip => ip, ip => _records[ip], StringComparer.OrdinalIgnoreCase);

        public BanCountRecord GetBanCount(string clientIp)
            => _records.TryGetValue(clientIp, out var record)
                ? record
                : new BanCountRecord(clientIp, 0, DateTimeOffset.UtcNow);

        public BanCountRecord SetBanCount(string clientIp, int banCount)
            => throw new NotSupportedException();
    }
}
