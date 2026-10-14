using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Services;
using iisidsd.Storage;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Services;

public sealed class IpAggregationServiceTests
{
    [Fact]
    public void GetFindings_ClampsLimitBeforeBanCountLookup()
    {
        var timestamp = DateTimeOffset.UtcNow;
        var oversizedFindings = Enumerable.Range(0, FindingStoreLimits.MaximumListLimit + 1)
            .Select(index => new IpFinding(
                $"client-{index}",
                1,
                1,
                1,
                "Medium",
                timestamp,
                timestamp,
                [],
                [],
                []))
            .ToArray();
        var findingStore = new OversizedFindingStore(oversizedFindings);
        var banCountService = new RecordingBanCountService();
        var service = new IpAggregationService(findingStore, banCountService);

        var findings = service.GetFindings(int.MaxValue);

        Assert.Equal(FindingStoreLimits.MaximumListLimit, findingStore.RequestedLimit);
        Assert.Equal(FindingStoreLimits.MaximumListLimit, findings.Count);
        Assert.Equal(FindingStoreLimits.MaximumListLimit, banCountService.RequestedClientIpCount);
    }

    [Fact]
    public async Task SqliteFindingStore_ListClampsExtremeLimit()
    {
        await using var context = await TestContext.CreateAsync();
        var findingStore = Assert.IsType<SqliteFindingStore>(context.FindingStore);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = context.DatabasePath
        }.ToString());
        connection.Open();
        using var transaction = connection.BeginTransaction();
        var timestamp = DateTimeOffset.UtcNow;
        for (var index = 0; index <= FindingStoreLimits.MaximumListLimit; index++)
        {
            findingStore.Upsert(new SecurityEvent(
                timestamp.AddTicks(index),
                "server01",
                "example.test",
                "GET",
                "/probe",
                $"2001:db8::{index:x}",
                404,
                "unit-test",
                new Dictionary<string, string>(),
                IsSuspicious: true,
                DetectionReason: "test",
                RiskScore: 1,
                RiskSeverity: "Medium"), connection, transaction);
        }

        transaction.Commit();

        Assert.Equal(FindingStoreLimits.MaximumListLimit, findingStore.List(int.MaxValue).Count);
    }

    [Fact]
    public async Task GetFindings_GroupsEventsAndAppliesBanCounts()
    {
        await using var context = await TestContext.CreateAsync();
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

        context.EventStore.Publish(suspiciousEvent);
        context.EventStore.Publish(followUpEvent);

        var service = new IpAggregationService(
            context.FindingStore,
            new FakeBanCountService(
                new Dictionary<string, BanCountRecord>(StringComparer.OrdinalIgnoreCase)
                {
                    ["198.51.100.24"] = new("198.51.100.24", 3, DateTimeOffset.UtcNow)
                }));

        var finding = Assert.Single(service.GetFindings(10));

        Assert.Equal("198.51.100.24", finding.ClientIp);
        Assert.Equal(2, finding.RequestCount);
        Assert.Equal(1, finding.SuspiciousRequestCount);
        Assert.Equal(60, finding.HighestRiskScore);
        Assert.Equal(3, finding.BanCount);
        Assert.Contains("alpha.test", finding.Domains);
        Assert.Contains("beta.test", finding.Domains);
    }

    [Fact]
    public async Task GetFindings_UsesDomainScopedBanCountsWhenFiltered()
    {
        await using var context = await TestContext.CreateAsync();
        context.EventStore.Publish(new SecurityEvent(
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
            RiskIndicators: ["path traversal"]));
        context.EventStore.Publish(new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "beta.test",
            "GET",
            "/home",
            "198.51.100.24",
            200,
            "agent-a",
            new Dictionary<string, string>()));

        var service = new IpAggregationService(
            context.FindingStore,
            new FakeBanCountService(
                new Dictionary<string, BanCountRecord>(StringComparer.OrdinalIgnoreCase)
                {
                    ["198.51.100.24"] = new("198.51.100.24", 3, DateTimeOffset.UtcNow)
                },
                new Dictionary<string, IReadOnlyDictionary<string, BanCountRecord>>(StringComparer.OrdinalIgnoreCase)
                {
                    ["alpha.test"] = new Dictionary<string, BanCountRecord>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["198.51.100.24"] = new("198.51.100.24", 1, DateTimeOffset.UtcNow)
                    }
                }));

        var finding = Assert.Single(service.GetFindings(10, "alpha.test"));

        Assert.Equal("198.51.100.24", finding.ClientIp);
        Assert.Equal(1, finding.RequestCount);
        Assert.Equal(1, finding.SuspiciousRequestCount);
        Assert.Equal(1, finding.BanCount);
        Assert.Single(finding.Domains);
        Assert.Equal("alpha.test", finding.Domains[0]);
    }

    private sealed class FakeBanCountService(
        IReadOnlyDictionary<string, BanCountRecord> aggregateRecords,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, BanCountRecord>>? recordsByDomain = null) : IBanCountService
    {
        private readonly IReadOnlyDictionary<string, BanCountRecord> _aggregateRecords = aggregateRecords;
        private readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, BanCountRecord>> _recordsByDomain =
            recordsByDomain ?? new Dictionary<string, IReadOnlyDictionary<string, BanCountRecord>>(StringComparer.OrdinalIgnoreCase);

        public IReadOnlyList<BanCountRecord> GetBanCounts(int limit, string? domain = null)
            => SelectRecords(domain).Values.Take(limit).ToArray();

        public IReadOnlyDictionary<string, BanCountRecord> GetBanCounts(IEnumerable<string> clientIps, string? domain = null)
        {
            var records = SelectRecords(domain);
            return clientIps
                .Where(records.ContainsKey)
                .ToDictionary(ip => ip, ip => records[ip], StringComparer.OrdinalIgnoreCase);
        }

        public BanCountRecord GetBanCount(string clientIp, string? domain = null)
        {
            var records = SelectRecords(domain);
            return records.TryGetValue(clientIp, out var record)
                ? record
                : new BanCountRecord(clientIp, 0, DateTimeOffset.UtcNow);
        }

        public BanCountRecord SetBanCount(string clientIp, int banCount, string? domain = null)
            => throw new NotSupportedException();

        public void IncrementBanCounts(string clientIp, IEnumerable<string> domains)
            => throw new NotSupportedException();

        private IReadOnlyDictionary<string, BanCountRecord> SelectRecords(string? domain)
            => string.IsNullOrWhiteSpace(domain)
                ? _aggregateRecords
                : _recordsByDomain.TryGetValue(domain, out var records)
                    ? records
                    : new Dictionary<string, BanCountRecord>(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class OversizedFindingStore(IReadOnlyList<IpFinding> findings) : IFindingStore
    {
        public int RequestedLimit { get; private set; }
        public void Upsert(SecurityEvent webEvent) => throw new NotSupportedException();
        public void Upsert(SecurityEvent webEvent, SqliteConnection connection, SqliteTransaction transaction) => throw new NotSupportedException();
        public int BackfillFromExistingEvents() => throw new NotSupportedException();
        public IpFinding? Get(string clientIp, string? domain = null) => throw new NotSupportedException();

        public IReadOnlyList<IpFinding> List(int limit, string? domain = null)
        {
            RequestedLimit = limit;
            return findings;
        }

        public int Prune(DateTimeOffset olderThan) => throw new NotSupportedException();
    }

    private sealed class RecordingBanCountService : IBanCountService
    {
        public int RequestedClientIpCount { get; private set; }
        public IReadOnlyList<BanCountRecord> GetBanCounts(int limit, string? domain = null) => [];

        public IReadOnlyDictionary<string, BanCountRecord> GetBanCounts(IEnumerable<string> clientIps, string? domain = null)
        {
            RequestedClientIpCount = clientIps.Count();
            return new Dictionary<string, BanCountRecord>();
        }

        public BanCountRecord GetBanCount(string clientIp, string? domain = null)
            => new(clientIp, 0, DateTimeOffset.UtcNow);

        public BanCountRecord SetBanCount(string clientIp, int banCount, string? domain = null) => throw new NotSupportedException();
        public void IncrementBanCounts(string clientIp, IEnumerable<string> domains) => throw new NotSupportedException();
    }

    private sealed class TestContext : IAsyncDisposable
    {
        private readonly string _rootPath;

        private TestContext(string rootPath, IEventStore eventStore, IFindingStore findingStore)
        {
            _rootPath = rootPath;
            EventStore = eventStore;
            FindingStore = findingStore;
        }

        public IEventStore EventStore { get; }
        public IFindingStore FindingStore { get; }
        public string DatabasePath => Path.Combine(_rootPath, "data", "test.sqlite3");

        public static async Task<TestContext> CreateAsync()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), "iisidsd-finding-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(rootPath);
            var environment = new TestHostEnvironment(rootPath);
            var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
            var findingStore = new SqliteFindingStore(storageOptions, environment);
            var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
            await initializer.StartAsync(CancellationToken.None);

            var eventStore = new SqliteEventStore(
                Options.Create(new IisEtwOptions { SubscriptionBufferSize = 10 }),
                storageOptions,
                environment,
                findingStore,
                new IisObservability());
            return new TestContext(rootPath, eventStore, findingStore);
        }

        public ValueTask DisposeAsync()
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(_rootPath))
            {
                Directory.Delete(_rootPath, recursive: true);
            }

            return ValueTask.CompletedTask;
        }
    }

    private sealed class TestHostEnvironment(string contentRootPath) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "iisidsd.Tests";
        public string ContentRootPath { get; set; } = contentRootPath;
        public IFileProvider ContentRootFileProvider { get; set; } = new PhysicalFileProvider(contentRootPath);
    }
}
