using iisidsd.Configuration;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Observability;
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
        var writer = new FakeIisDenyListWriter();
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var succeeded = service.AddDeniedIp("Example Site", "203.0.113.20", "DOMAIN\\admin", "manual review");

        Assert.True(succeeded);
        Assert.Contains(store.Audits, audit => audit.Outcome == "requested");
        var audit = Assert.Single(store.Audits, audit => audit.Outcome == "simulated");
        Assert.Equal("DOMAIN\\admin", audit.Actor);
        Assert.Equal("add", audit.Action);
        Assert.Equal("manual review", audit.Reason);
        Assert.Equal("simulated", audit.Outcome);
        Assert.True(audit.DryRun);
        Assert.NotNull(audit.ExpiresAt);
        Assert.Empty(store.Expiries);
        Assert.Equal(0, writer.EnsureCalls);
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
        var audit = Assert.Single(store.Audits, audit => audit.Outcome == "simulated");
        Assert.Equal("*", audit.SiteName);
        Assert.Equal("simulated", audit.Outcome);
    }

    [Fact]
    public void AddDeniedIpToDomains_MatchesObservedSiteNameWhenBindingHasNoHostName()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        var site = new IisSiteInfo(1, "Example Site", "Started", ["http/*:80:"], []);
        var siteDiscovery = new FakeSiteDiscoveryService(sites: [site]);
        var writer = new FakeIisDenyListWriter();
        var service = CreateService(options, store, siteDiscovery, denyListWriter: writer);
        var securityEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "www.example.test",
            "GET",
            "/",
            "203.0.113.23",
            200,
            "unit-test",
            new Dictionary<string, string> { ["s-sitename"] = "Example Site" });

        var updatedSites = service.AddDeniedIpToDomains(
            securityEvent.ClientIp,
            [securityEvent.Domain],
            "system:auto-deny",
            "suspicious request",
            securityEvent);

        Assert.Equal(["Example Site"], updatedSites);
        Assert.Equal(1, writer.EnsureCalls);
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
        var audit = Assert.Single(store.Audits, audit => audit.Outcome == "skipped-allow-list");
        Assert.Equal("skipped-allow-list", audit.Outcome);
        Assert.False(audit.DryRun);
    }

    [Fact]
    public void AddDeniedIp_WhenMutationMasterSwitchIsOff_AuditsObservationAndDoesNotCallIisWriter()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = false, DryRun = false });
        var store = new FakeDenyListStore();
        var writer = new FakeIisDenyListWriter();
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var succeeded = service.AddDeniedIp("Example Site", "203.0.113.29", "manual", "safety check");

        Assert.False(succeeded);
        Assert.Contains(store.Audits, audit => audit.Outcome == "requested");
        Assert.Contains(store.Audits, audit => audit.Outcome == "observed");
        Assert.Equal(0, writer.EnsureCalls);
    }

    [Fact]
    public void AddDeniedIp_FailureUpdatesOperationalDiagnostics()
    {
        using var observability = new IisObservability();
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var writer = new FakeIisDenyListWriter { Status = IisDenyListMutationStatus.Failed };
        var service = CreateService(
            options,
            new FakeDenyListStore(),
            new FakeSiteDiscoveryService(),
            denyListWriter: writer,
            observability: observability);

        Assert.False(service.AddDeniedIp("Example Site", "203.0.113.75"));

        var snapshot = observability.GetOperationalDiagnosticsSnapshot("test", "test");
        Assert.Equal("failed", snapshot.LastEnforcementOutcome);
        Assert.Equal(1, snapshot.IisAdministrationFailures);
        Assert.Contains("iis_administration_failures 1", observability.RenderPrometheus());
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

        Assert.False(succeeded);
        Assert.Empty(store.Expiries);
        Assert.Equal(0, writer.PrepareNewEntryCalls);
        Assert.Contains(store.Audits, audit => audit.Outcome == "attempted");
        var audit = Assert.Single(store.Audits, audit => audit.Outcome == "pre-existing-unmanaged");
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
        var audit = Assert.Single(store.Audits, audit => audit.Outcome == "existing-allow-rule");
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
        Assert.NotNull(Assert.Single(store.Audits, audit => audit.Outcome == "succeeded").ExpiresAt);
    }

    [Fact]
    public void RemoveExpiredDeniedIp_DryRunKeepsExpiryAndAuditsIntent()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = true });
        var store = new FakeDenyListStore();
        var expiredAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        store.SetExpiry("Example Site", "203.0.113.23", expiredAt);
        store.SeedManaged("Example Site", "203.0.113.23", expiredAt);
        var service = CreateService(options, store, new FakeSiteDiscoveryService());

        var removed = service.RemoveExpiredDeniedIp(new TemporaryDenyListEntry("Example Site", "203.0.113.23", expiredAt));

        Assert.False(removed);
        Assert.Equal(expiredAt, store.GetExpiry("Example Site", "203.0.113.23"));
        var audit = Assert.Single(store.Audits, audit => audit.Outcome == "simulated-expiry");
        Assert.Equal("system:expiry-cleaner", audit.Actor);
        Assert.Equal("expire", audit.Action);
        Assert.Equal("simulated-expiry", audit.Outcome);
    }

    [Fact]
    public void RemoveDeniedIp_UsesWriterAndClearsExpiryAfterSuccess()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        store.SetExpiry("Example Site", "203.0.113.24", DateTimeOffset.UtcNow.AddMinutes(5));
        store.SeedManaged("Example Site", "203.0.113.24", store.GetExpiry("Example Site", "203.0.113.24"));
        var writer = new FakeIisDenyListWriter();
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var removed = service.RemoveDeniedIp("Example Site", "203.0.113.24");

        Assert.True(removed);
        Assert.Equal(1, writer.RemoveCalls);
        Assert.Null(store.GetExpiry("Example Site", "203.0.113.24"));
        Assert.Contains(store.Audits, audit => audit.Outcome == "succeeded");
    }

    [Fact]
    public void RemoveExpiredDeniedIp_UsesWriterAndClearsExpiryAfterSuccess()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        var expiredAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        store.SetExpiry("Example Site", "203.0.113.24", expiredAt);
        store.SeedManaged("Example Site", "203.0.113.24", expiredAt);
        var writer = new FakeIisDenyListWriter();
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var removed = service.RemoveExpiredDeniedIp(new TemporaryDenyListEntry("Example Site", "203.0.113.24", expiredAt));

        Assert.True(removed);
        Assert.Equal(1, writer.RemoveCalls);
        Assert.Null(store.GetExpiry("Example Site", "203.0.113.24"));
        Assert.Contains(store.Audits, audit => audit.Outcome == "expired");
    }

    [Fact]
    public void RemoveExpiredDeniedIp_WriterFailureIsAuditedAndKeepsExpiry()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        var expiredAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        store.SetExpiry("Example Site", "203.0.113.24", expiredAt);
        store.SeedManaged("Example Site", "203.0.113.24", expiredAt);
        var writer = new FakeIisDenyListWriter
        {
            RemoveStatus = IisDenyListMutationStatus.Failed,
            RemoveException = new InvalidOperationException("IIS configuration update failed")
        };
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var removed = service.RemoveExpiredDeniedIp(new TemporaryDenyListEntry("Example Site", "203.0.113.24", expiredAt));

        Assert.False(removed);
        Assert.Equal(expiredAt, store.GetExpiry("Example Site", "203.0.113.24"));
        Assert.Contains(store.Audits, audit => audit.Outcome == "failed");
    }

    [Fact]
    public void AddDeniedIp_AllowListedIpv4AndIpv6CannotReachWriter()
    {
        var options = Options.Create(new IisAdminOptions
        {
            EnableDenyListChanges = true,
            DryRun = false,
            AllowList = ["192.0.2.0/24", "2001:db8:abcd::/48"]
        });
        var store = new FakeDenyListStore();
        var writer = new FakeIisDenyListWriter();
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        Assert.False(service.AddDeniedIp("Example Site", "192.0.2.44"));
        Assert.False(service.AddDeniedIp("Example Site", "2001:db8:abcd::44"));

        Assert.Equal(0, writer.EnsureCalls);
        Assert.Equal(2, store.Audits.Count(audit => audit.Outcome == "skipped-allow-list"));
    }

    [Theory]
    [InlineData("Observe", false, "observed")]
    [InlineData("Simulate", true, "simulated")]
    public void AddDeniedIp_ObserveAndSimulateNeverMutateIis(string mode, bool expectedResult, string outcome)
    {
        var options = Options.Create(new IisAdminOptions
        {
            EnableDenyListChanges = true,
            DryRun = false,
            EnforcementMode = mode
        });
        var store = new FakeDenyListStore();
        var writer = new FakeIisDenyListWriter();
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        Assert.Equal(expectedResult, service.AddDeniedIp("Example Site", "203.0.113.40"));

        Assert.Equal(0, writer.EnsureCalls);
        Assert.Contains(store.Audits, audit => audit.Outcome == outcome);
    }

    [Fact]
    public void RemoveDeniedIp_DoesNotRemoveUnownedAdministratorRule()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        var writer = new FakeIisDenyListWriter
        {
            Inspection = new("Example Site", "203.0.113.41", "denied", [], [])
        };
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var status = service.RemoveDeniedIpWithStatus("Example Site", "203.0.113.41");

        Assert.Equal(DenyListRemovalStatus.NotServiceOwned, status);
        Assert.Equal(0, writer.RemoveCalls);
        Assert.Contains(store.Audits, audit => audit.Outcome == "skipped-not-service-owned");
    }

    [Fact]
    public void PreviewDeniedIp_ReportsRuleExpiryEvidenceAndSharedPoolImpactWithoutMutation()
    {
        var options = Options.Create(new IisAdminOptions
        {
            EnableDenyListChanges = true,
            DryRun = false,
            TemporaryBanMinutes = 15
        });
        var store = new FakeDenyListStore();
        var writer = new FakeIisDenyListWriter
        {
            Inspection = new IisDenyListInspection(
                "Example Site",
                "203.0.113.42",
                "missing",
                ["SharedPool"],
                ["Other Site"])
        };
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        var preview = Assert.IsType<DenyListPreview>(service.PreviewDeniedIp(
            new DenyListPreviewRequest("Example Site", "203.0.113.42", "review", ["multiple indicators"]),
            "DOMAIN\\admin"));

        Assert.True(preview.WouldMutate);
        Assert.Equal("ipAddress=203.0.113.42; allowed=false", preview.Rule);
        Assert.InRange(preview.ExpiresAt!.Value, DateTimeOffset.UtcNow.AddMinutes(14), DateTimeOffset.UtcNow.AddMinutes(16));
        Assert.Contains("multiple indicators", preview.Evidence);
        Assert.Equal("SharedPool", Assert.Single(preview.ApplicationPools));
        Assert.Equal("Other Site", Assert.Single(preview.OtherSitesSharingPools));
        Assert.Contains(preview.Warnings, warning => warning.Contains("shared", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(0, writer.EnsureCalls);
        Assert.Single(store.Audits);
    }

    [Fact]
    public void AddDeniedIp_RetriesBoundedTransientIisFailureAndCompletesOwnership()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        var writer = new FakeIisDenyListWriter();
        writer.EnsureResults.Enqueue(new IisDenyListMutationResult(
            IisDenyListMutationStatus.Failed,
            new IOException("transient IIS configuration lock")));
        writer.EnsureResults.Enqueue(new IisDenyListMutationResult(IisDenyListMutationStatus.Added));
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        Assert.True(service.AddDeniedIp("Example Site", "203.0.113.43"));

        Assert.Equal(2, writer.EnsureCalls);
        Assert.Equal("active", store.GetManagedDeny("Example Site", "203.0.113.43")?.State);
        Assert.Contains(store.Audits, audit => audit.Outcome == "succeeded");
    }

    [Fact]
    public void RemoveDeniedIp_AlreadyRemovedRuleClearsOnlyOwnedMetadata()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        store.SeedManaged("Example Site", "203.0.113.44", null);
        var writer = new FakeIisDenyListWriter { RemoveStatus = IisDenyListMutationStatus.NotFound };
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        Assert.True(service.RemoveDeniedIp("Example Site", "203.0.113.44"));

        Assert.Null(store.GetManagedDeny("Example Site", "203.0.113.44"));
        Assert.Contains(store.Audits, audit => audit.Outcome == "already-removed");
    }

    [Fact]
    public void ReconcilePendingAdd_PreservesAmbiguousDeniedRuleForAdministratorReview()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        store.SeedPending("Example Site", "203.0.113.45", null, "pending-add", 7);
        var writer = new FakeIisDenyListWriter
        {
            Inspection = new IisDenyListInspection("Example Site", "203.0.113.45", "denied", [], [])
        };
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        service.ReconcilePendingManagedDenies();

        Assert.Equal("recovery-required", store.GetManagedDeny("Example Site", "203.0.113.45")?.State);
        Assert.Contains(store.Audits, audit => audit.Action == "recover" && audit.Outcome == "recovery-required");
    }

    [Fact]
    public void ReconcilePendingRemove_ClearsJournalAfterIisRemovalCompletedBeforeDatabaseCommit()
    {
        var options = Options.Create(new IisAdminOptions { EnableDenyListChanges = true, DryRun = false });
        var store = new FakeDenyListStore();
        store.SeedPending("Example Site", "203.0.113.46", DateTimeOffset.UtcNow.AddMinutes(-1), "pending-remove", 8);
        var writer = new FakeIisDenyListWriter
        {
            Inspection = new IisDenyListInspection("Example Site", "203.0.113.46", "missing", [], [])
        };
        var service = CreateService(options, store, new FakeSiteDiscoveryService(), denyListWriter: writer);

        service.ReconcilePendingManagedDenies();

        Assert.Null(store.GetManagedDeny("Example Site", "203.0.113.46"));
        Assert.Contains(store.Audits, audit => audit.Action == "recover" && audit.Outcome == "reverted");
    }

    private static IisDenyListService CreateService(
        IOptions<IisAdminOptions> options,
        IDenyListStore store,
        IIisSiteDiscoveryService siteDiscovery,
        IAppCmdRunner? appCmdRunner = null,
        IIisDenyListWriter? denyListWriter = null,
        IisObservability? observability = null)
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
            denyListWriter ?? new FakeIisDenyListWriter(),
            observability);
    }

    private sealed class FakeSiteDiscoveryService(
        bool throwOnGetSites = false,
        IReadOnlyList<IisSiteInfo>? sites = null) : IIisSiteDiscoveryService
    {
        public int GetSitesCalls { get; private set; }

        public IReadOnlyList<IisSiteInfo> GetSites()
        {
            GetSitesCalls++;
            if (throwOnGetSites)
            {
                throw new InvalidOperationException("Site discovery must not run during a dry run.");
            }

            return sites ?? [];
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
        public IisDenyListInspection Inspection { get; init; } = new("Example Site", "203.0.113.1", "missing", [], []);
        public Queue<IisDenyListMutationResult> EnsureResults { get; } = new();
        public int EnsureCalls { get; private set; }
        public int PrepareNewEntryCalls { get; private set; }
        public int RemoveCalls { get; private set; }

        public IisDenyListInspection Inspect(string siteName, string clientIp)
            => Inspection with { SiteName = siteName, ClientIp = clientIp };

        public IisDenyListMutationResult EnsureDenied(string siteName, string clientIp, Action prepareNewEntry)
        {
            EnsureCalls++;
            var result = EnsureResults.Count > 0
                ? EnsureResults.Dequeue()
                : new IisDenyListMutationResult(Status);
            if (result.Status is IisDenyListMutationStatus.Added or IisDenyListMutationStatus.Failed)
            {
                PrepareNewEntryCalls++;
                prepareNewEntry();
            }

            return result;
        }

        public IisDenyListMutationResult RemoveDenied(string siteName, string clientIp)
        {
            RemoveCalls++;
            return new IisDenyListMutationResult(RemoveStatus, RemoveException);
        }
    }

    private sealed class FakeDenyListStore : IDenyListStore
    {
        public IDisposable AcquireMutationLock() => new NoopDisposable();
        private readonly Dictionary<(string Site, string Ip), DateTimeOffset> _expiries = [];
        private readonly Dictionary<(string Site, string Ip), ManagedDenyListEntry> _managed = [];
        private long _nextAuditId;

        public List<DenyListAuditRecord> Audits { get; } = [];
        public IReadOnlyDictionary<(string Site, string Ip), DateTimeOffset> Expiries => _expiries;

        public long BeginAudit(DenyListAuditRecord record)
        {
            var id = ++_nextAuditId;
            Audits.Add(record with { Id = id });
            return id;
        }

        public long RecordAudit(DenyListAuditRecord record)
        {
            var id = ++_nextAuditId;
            Audits.Add(record with { Id = id });
            return id;
        }

        public void SeedManaged(string siteName, string clientIp, DateTimeOffset? expiresAt)
            => _managed[(siteName, clientIp)] = new ManagedDenyListEntry(siteName, clientIp, expiresAt, "active", 0);

        public void SeedPending(string siteName, string clientIp, DateTimeOffset? expiresAt, string state, long auditId)
            => _managed[(siteName, clientIp)] = new ManagedDenyListEntry(siteName, clientIp, expiresAt, state, auditId);

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

        public ManagedDenyListEntry? GetManagedDeny(string siteName, string clientIp)
            => _managed.TryGetValue((siteName, clientIp), out var entry) ? entry : null;

        public IReadOnlyList<ManagedDenyListEntry> GetPendingManagedDenies(int limit)
            => _managed.Values.Where(entry => entry.State != "active").Take(limit).ToArray();

        public bool TryPrepareManagedDeny(ManagedDenyListEntry entry)
            => _managed.TryAdd((entry.SiteName, entry.ClientIp), entry);

        public bool CompleteManagedDeny(string siteName, string clientIp, DateTimeOffset? expiresAt, long auditId)
        {
            if (!_managed.ContainsKey((siteName, clientIp)))
            {
                return false;
            }

            _managed[(siteName, clientIp)] = new ManagedDenyListEntry(siteName, clientIp, expiresAt, "active", auditId);
            RemoveExpiry(siteName, clientIp);
            if (expiresAt is { } expiry)
            {
                SetExpiry(siteName, clientIp, expiry);
            }

            return true;
        }

        public bool TryTransitionManagedDeny(string siteName, string clientIp, string expectedState, long expectedAuditId, string state, long auditId)
        {
            if (!_managed.TryGetValue((siteName, clientIp), out var entry) ||
                entry.State != expectedState || entry.AuditId != expectedAuditId)
            {
                return false;
            }

            _managed[(siteName, clientIp)] = entry with { State = state, AuditId = auditId };
            return true;
        }

        public bool TryRemoveManagedDeny(string siteName, string clientIp, string expectedState, long expectedAuditId)
        {
            if (!_managed.TryGetValue((siteName, clientIp), out var entry) ||
                entry.State != expectedState || entry.AuditId != expectedAuditId)
            {
                return false;
            }

            _managed.Remove((siteName, clientIp));
            RemoveExpiry(siteName, clientIp);
            return true;
        }

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

        private sealed class NoopDisposable : IDisposable
        {
            public void Dispose() { }
        }
    }
}
