using iisidsd.Configuration;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Iis;

public sealed class IisDenyListServiceTests
{
    [Fact]
    public void AddDeniedIp_DryRunAuditsIntentAndDoesNotStoreExpiry()
    {
        var options = Options.Create(new IisAdminOptions
        {
            EnableDenyListChanges = true,
            TemporaryBanMinutes = 15,
            DryRun = true
        });
        var store = new FakeDenyListStore();
        var service = CreateService(options, store, new FakeSiteDiscoveryService());

        var succeeded = service.AddDeniedIp("Example Site", "203.0.113.20", "DOMAIN\\admin", "manual review");

        Assert.True(succeeded);
        var audit = Assert.Single(store.Audits);
        Assert.Equal("DOMAIN\\admin", audit.Actor);
        Assert.Equal("add", audit.Action);
        Assert.Equal("manual review", audit.Reason);
        Assert.Equal("dry-run", audit.Outcome);
        Assert.True(audit.DryRun);
        Assert.NotNull(audit.ExpiresAt);
        Assert.Empty(store.Expiries);
    }

    [Fact]
    public void AddDeniedIpToDomains_DryRunDoesNotDiscoverSites()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = true });
        var store = new FakeDenyListStore();
        var siteDiscovery = new FakeSiteDiscoveryService(throwOnGetSites: true);
        var service = CreateService(options, store, siteDiscovery);

        var updatedSites = service.AddDeniedIpToDomains(
            "203.0.113.21",
            ["example.test"],
            "system:auto-deny",
            "suspicious request");

        Assert.Empty(updatedSites);
        Assert.Equal(0, siteDiscovery.GetSitesCalls);
        var audit = Assert.Single(store.Audits);
        Assert.Equal("*", audit.SiteName);
        Assert.Contains("example.test", audit.Reason);
        Assert.Equal("dry-run", audit.Outcome);
    }

    [Fact]
    public void AddDeniedIp_AllowListedAddressIsSkippedAndAudited()
    {
        var options = Options.Create(new IisAdminOptions
        {
            EnableDenyListChanges = true,
            AllowList = ["203.0.113.0/24"],
            DryRun = false
        });
        var store = new FakeDenyListStore();
        var service = CreateService(options, store, new FakeSiteDiscoveryService());

        var succeeded = service.AddDeniedIp("Example Site", "203.0.113.22", "DOMAIN\\admin", "manual review");

        Assert.False(succeeded);
        var audit = Assert.Single(store.Audits);
        Assert.Equal("skipped-allow-list", audit.Outcome);
        Assert.False(audit.DryRun);
    }

    [Fact]
    public void AddDeniedIp_PreExistingPermanentRuleDoesNotReceiveTemporaryExpiry()
    {
        var options = Options.Create(new IisAdminOptions
        {
            EnableDenyListChanges = true,
            TemporaryBanMinutes = 15,
            DryRun = false
        });
        var store = new FakeDenyListStore();
        var writer = new FakeIisDenyListWriter { Status = IisDenyListMutationStatus.AlreadyDenied };
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var succeeded = service.AddDeniedIp("Example Site", "203.0.113.26", "manual", "manual review");

        Assert.True(succeeded);
        Assert.Empty(store.Expiries);
        Assert.Equal(0, writer.PrepareNewEntryCalls);
        var audit = Assert.Single(store.Audits);
        Assert.Equal("already-denied-permanent", audit.Outcome);
        Assert.Null(audit.ExpiresAt);
    }

    [Fact]
    public void AddDeniedIp_DoesNotChangeAnExistingAllowRule()
    {
        var options = Options.Create(new IisAdminOptions
        {
            EnableDenyListChanges = true,
            TemporaryBanMinutes = 15,
            DryRun = false
        });
        var store = new FakeDenyListStore();
        var writer = new FakeIisDenyListWriter { Status = IisDenyListMutationStatus.ExistingAllowRule };
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var succeeded = service.AddDeniedIp("Example Site", "203.0.113.27", "manual", "manual review");

        Assert.False(succeeded);
        Assert.Empty(store.Expiries);
        Assert.Equal(0, writer.PrepareNewEntryCalls);
        var audit = Assert.Single(store.Audits);
        Assert.Equal("existing-allow-rule", audit.Outcome);
        Assert.Null(audit.ExpiresAt);
    }

    [Fact]
    public void AddDeniedIp_SchedulesExpiryOnlyForNewlyCreatedRule()
    {
        var options = Options.Create(new IisAdminOptions
        {
            EnableDenyListChanges = true,
            TemporaryBanMinutes = 15,
            DryRun = false
        });
        var store = new FakeDenyListStore();
        var writer = new FakeIisDenyListWriter();
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var succeeded = service.AddDeniedIp("Example Site", "203.0.113.28", "manual", "manual review");

        Assert.True(succeeded);
        Assert.Single(store.Expiries);
        Assert.Equal(1, writer.PrepareNewEntryCalls);
        Assert.NotNull(Assert.Single(store.Audits).ExpiresAt);
    }

    [Fact]
    public void RemoveExpiredDeniedIp_DryRunKeepsExpiryAndAuditsIntent()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = true });
        var store = new FakeDenyListStore();
        var expiredAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        store.SetExpiry("Example Site", "203.0.113.23", expiredAt);
        var service = CreateService(options, store, new FakeSiteDiscoveryService());

        var removed = service.RemoveExpiredDeniedIp(new TemporaryDenyListEntry("Example Site", "203.0.113.23", expiredAt));

        Assert.False(removed);
        Assert.Equal(expiredAt, store.GetExpiry("Example Site", "203.0.113.23"));
        var audit = Assert.Single(store.Audits);
        Assert.Equal("system:expiry-cleaner", audit.Actor);
        Assert.Equal("expire", audit.Action);
        Assert.Equal("dry-run", audit.Outcome);
    }

    [Fact]
    public void RemoveDeniedIp_UsesWriterAndClearsExpiryAfterSuccess()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        store.SetExpiry("Example Site", "203.0.113.24", DateTimeOffset.UtcNow.AddMinutes(5));
        var writer = new FakeIisDenyListWriter();
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var removed = service.RemoveDeniedIp("Example Site", "203.0.113.24");

        Assert.True(removed);
        Assert.Equal(1, writer.RemoveCalls);
        Assert.False(writer.RemoveDeniedRulesOnly);
        Assert.Null(store.GetExpiry("Example Site", "203.0.113.24"));
        Assert.Equal("succeeded", Assert.Single(store.Audits).Outcome);
    }

    [Fact]
    public void RemoveExpiredDeniedIp_UsesWriterAndClearsExpiryAfterSuccess()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        var expiredAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        store.SetExpiry("Example Site", "203.0.113.24", expiredAt);
        var writer = new FakeIisDenyListWriter();
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var removed = service.RemoveExpiredDeniedIp(new TemporaryDenyListEntry("Example Site", "203.0.113.24", expiredAt));

        Assert.True(removed);
        Assert.Equal(1, writer.RemoveCalls);
        Assert.True(writer.RemoveDeniedRulesOnly);
        Assert.Null(store.GetExpiry("Example Site", "203.0.113.24"));
        Assert.Equal("succeeded", Assert.Single(store.Audits).Outcome);
    }

    [Fact]
    public void RemoveExpiredDeniedIp_WriterFailureIsAuditedAndKeepsExpiry()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        var expiredAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        store.SetExpiry("Example Site", "203.0.113.24", expiredAt);
        var writer = new FakeIisDenyListWriter
        {
            RemoveStatus = IisDenyListMutationStatus.Failed,
            RemoveException = new InvalidOperationException("IIS configuration update failed")
        };
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var removed = service.RemoveExpiredDeniedIp(new TemporaryDenyListEntry("Example Site", "203.0.113.24", expiredAt));

        Assert.False(removed);
        Assert.Equal(expiredAt, store.GetExpiry("Example Site", "203.0.113.24"));
        Assert.Equal("failed", Assert.Single(store.Audits).Outcome);
    }

    private static IisDenyListService CreateService(
        IOptions<IisAdminOptions> options,
        IDenyListStore store,
        IIisSiteDiscoveryService siteDiscovery,
        IAppCmdRunner? appCmdRunner = null,
        IIisDenyListWriter? denyListWriter = null)
    {
        var logger = NullLogger<IisDenyListService>.Instance;
        var allowList = new IisIpAllowList(options);
        return new IisDenyListService(
            logger,
            siteDiscovery,
            store,
            allowList,
            options,
            appCmdRunner ?? new FakeAppCmdRunner(),
            denyListWriter ?? new FakeIisDenyListWriter());
    }

    private sealed class FakeSiteDiscoveryService(bool throwOnGetSites = false) : IIisSiteDiscoveryService
    {
        public int GetSitesCalls { get; private set; }

        public IReadOnlyList<IisSiteInfo> GetSites()
        {
            GetSitesCalls++;
            if (throwOnGetSites)
            {
                throw new InvalidOperationException("Site discovery must not run during a dry run.");
            }

            return [];
        }

        public IisSiteInfo? FindSiteByDomain(string domain) => null;
    }

    private sealed class FakeAppCmdRunner : IAppCmdRunner
    {
        public List<string[]> Calls { get; } = [];
        public (bool Success, string Output, string Error) Result { get; init; } = (false, string.Empty, "No configured result.");
        public Exception? ExceptionToThrow { get; init; }

        public (bool Success, string Output, string Error) Run(params string[] arguments)
        {
            Calls.Add(arguments);
            if (ExceptionToThrow is not null)
            {
                throw ExceptionToThrow;
            }

            return Result;
        }
    }

    private sealed class FakeIisDenyListWriter : IIisDenyListWriter
    {
        public IisDenyListMutationStatus Status { get; init; } = IisDenyListMutationStatus.Added;
        public IisDenyListMutationStatus RemoveStatus { get; init; } = IisDenyListMutationStatus.Removed;
        public Exception? RemoveException { get; init; }
        public int PrepareNewEntryCalls { get; private set; }
        public int RemoveCalls { get; private set; }
        public bool RemoveDeniedRulesOnly { get; private set; }

        public IisDenyListMutationResult EnsureDenied(string siteName, string clientIp, Action prepareNewEntry)
        {
            if (Status == IisDenyListMutationStatus.Added)
            {
                PrepareNewEntryCalls++;
                prepareNewEntry();
            }

            return new IisDenyListMutationResult(Status);
        }

        public IisDenyListMutationResult RemoveDenied(string siteName, string clientIp, bool deniedRulesOnly = false)
        {
            RemoveCalls++;
            RemoveDeniedRulesOnly = deniedRulesOnly;
            return new IisDenyListMutationResult(RemoveStatus, RemoveException);
        }
    }

    private sealed class FakeDenyListStore : IDenyListStore
    {
        private readonly Dictionary<(string Site, string Ip), DateTimeOffset> _expiries = [];
        private long _nextAuditId;

        public List<DenyListAuditRecord> Audits { get; } = [];
        public IReadOnlyDictionary<(string Site, string Ip), DateTimeOffset> Expiries => _expiries;

        public long BeginAudit(DenyListAuditRecord record)
        {
            var id = ++_nextAuditId;
            Audits.Add(record with { Id = id });
            return id;
        }

        public void CompleteAudit(long auditId, string outcome)
        {
            var index = Audits.FindIndex(record => record.Id == auditId);
            Audits[index] = Audits[index] with { Outcome = outcome };
        }

        public void SetAuditExpiry(long auditId, DateTimeOffset? expiresAt)
        {
            var index = Audits.FindIndex(record => record.Id == auditId);
            Audits[index] = Audits[index] with { ExpiresAt = expiresAt };
        }

        public IReadOnlyList<DenyListAuditRecord> GetRecentAudit(int limit)
            => Audits.TakeLast(limit).Reverse().ToArray();
        public DenyListAuditRecord? GetLastAutoDeny()
            => Audits.LastOrDefault(record =>
                string.Equals(record.Actor, "system:auto-deny", StringComparison.Ordinal) &&
                string.Equals(record.Action, "add", StringComparison.Ordinal));

        public DateTimeOffset? GetExpiry(string siteName, string clientIp)
            => _expiries.TryGetValue((siteName, clientIp), out var expiresAt) ? expiresAt : null;

        public void SetExpiry(string siteName, string clientIp, DateTimeOffset expiresAt)
            => _expiries[(siteName, clientIp)] = expiresAt;

        public void RemoveExpiry(string siteName, string clientIp)
            => _expiries.Remove((siteName, clientIp));

        public IReadOnlyList<TemporaryDenyListEntry> GetExpired(DateTimeOffset now, int limit, TemporaryDenyListEntry? after = null)
            => _expiries
                .Where(entry => entry.Value <= now)
                .Select(entry => new TemporaryDenyListEntry(entry.Key.Site, entry.Key.Ip, entry.Value))
                .OrderBy(entry => entry.ExpiresAt)
                .ThenBy(entry => entry.SiteName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(entry => entry.ClientIp, StringComparer.OrdinalIgnoreCase)
                .Where(entry => after is null ||
                    entry.ExpiresAt > after.ExpiresAt ||
                    (entry.ExpiresAt == after.ExpiresAt &&
                     (string.Compare(entry.SiteName, after.SiteName, StringComparison.OrdinalIgnoreCase) > 0 ||
                      (string.Equals(entry.SiteName, after.SiteName, StringComparison.OrdinalIgnoreCase) &&
                       string.Compare(entry.ClientIp, after.ClientIp, StringComparison.OrdinalIgnoreCase) > 0))))
                .Take(limit)
                .ToArray();
    }
}
