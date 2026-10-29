using System.Runtime.InteropServices;
using System.Xml.Linq;
using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Networking;
using iisidsd.Observability;
using iisidsd.Storage;
using Microsoft.Extensions.Options;

namespace iisidsd.Iis;

public sealed class IisDenyListService : IIisDenyListService
{
    private const string ExpiryCleanupActor = "system:expiry-cleaner";
    private const string ExpiryCleanupReason = "Temporary ban expired";
    private readonly IAppCmdRunner _appCmd;
    private readonly IIisSiteDiscoveryService _siteDiscoveryService;
    private readonly IDenyListStore _denyListStore;
    private readonly IIpAllowList _ipAllowList;
    private readonly IIisDenyListWriter _iisDenyListWriter;
    private readonly IisAdminOptions _adminOptions;
    private readonly IisObservability? _observability;
    private readonly ILogger<IisDenyListService> _logger;
    private readonly Lock _mutationSync = new();

    public IisDenyListService(
        ILogger<IisDenyListService> logger,
        IIisSiteDiscoveryService siteDiscoveryService,
        IDenyListStore denyListStore,
        IIpAllowList ipAllowList,
        IOptions<IisAdminOptions> adminOptions)
        : this(
            logger,
            siteDiscoveryService,
            denyListStore,
            ipAllowList,
            adminOptions,
            new AppCmdRunner(logger),
            new IisDenyListWriter())
    {
    }

    public IisDenyListService(
        ILogger<IisDenyListService> logger,
        IIisSiteDiscoveryService siteDiscoveryService,
        IDenyListStore denyListStore,
        IIpAllowList ipAllowList,
        IOptions<IisAdminOptions> adminOptions,
        IAppCmdRunner appCmdRunner)
        : this(logger, siteDiscoveryService, denyListStore, ipAllowList, adminOptions, appCmdRunner, new IisDenyListWriter())
    {
    }

    public IisDenyListService(
        ILogger<IisDenyListService> logger,
        IIisSiteDiscoveryService siteDiscoveryService,
        IDenyListStore denyListStore,
        IIpAllowList ipAllowList,
        IOptions<IisAdminOptions> adminOptions,
        IAppCmdRunner appCmdRunner,
        IIisDenyListWriter iisDenyListWriter,
        IisObservability? observability = null)
    {
        _appCmd = appCmdRunner;
        _siteDiscoveryService = siteDiscoveryService;
        _denyListStore = denyListStore;
        _ipAllowList = ipAllowList;
        _iisDenyListWriter = iisDenyListWriter;
        _adminOptions = ValidateOptions(adminOptions.Value);
        _observability = observability;
        _logger = logger;
    }

    public IReadOnlyList<string> GetDeniedIps(string siteName)
    {
        if (!IisDenyListWriter.IsValidSiteName(siteName) ||
            !_siteDiscoveryService.GetSites().Any(site => string.Equals(site.Name, siteName, StringComparison.OrdinalIgnoreCase)))
        {
            return [];
        }

        var result = _appCmd.Run("list", "config", siteName, "/section:system.webServer/security/ipSecurity", "/xml");
        if (!result.Success || string.IsNullOrWhiteSpace(result.Output))
        {
            return [];
        }

        var document = XDocument.Parse(result.Output);
        return document.Descendants("add")
            .Where(entry => !string.Equals((string?)entry.Attribute("allowed"), "true", StringComparison.OrdinalIgnoreCase))
            .Select(entry => (string?)entry.Attribute("ipAddress") ?? string.Empty)
            .Where(static ip => !string.IsNullOrWhiteSpace(ip))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public DenyListPreview? PreviewDeniedIp(DenyListPreviewRequest request, string actor = "manual")
    {
        if (request is null ||
            !IisDenyListWriter.IsValidSiteName(request.SiteName) ||
            !IisIpAllowList.TryNormalizeAddress(request.ClientIp, out var normalizedIp) ||
            request.Evidence is { Count: > 32 } ||
            request.Evidence?.Any(value => value is null || value.Length > 512 || value.Any(char.IsControl)) == true ||
            request.Reason?.Length > 512 || request.Reason?.Any(char.IsControl) == true)
        {
            return null;
        }

        lock (_mutationSync)
        {
            using var mutationLock = _denyListStore.AcquireMutationLock();
            var policy = _adminOptions.GetEnforcementPolicy();
            var inspection = _iisDenyListWriter.Inspect(request.SiteName, normalizedIp);
            var managedEntry = _denyListStore.GetManagedDeny(request.SiteName, normalizedIp);
            var allowListed = _ipAllowList.Contains(normalizedIp);
            var ruleState = inspection.RuleState switch
            {
                "denied" when managedEntry is { State: "active" } => "service-managed-deny",
                "denied" => "pre-existing-unmanaged-deny",
                "allow" => "administrator-allow-rule",
                _ => "missing"
            };
            var evidence = (request.Evidence ?? [])
                .Append(string.IsNullOrWhiteSpace(request.Reason) ? null : request.Reason.Trim())
                .Where(static item => !string.IsNullOrWhiteSpace(item))
                .Select(static item => item!)
                .Distinct(StringComparer.Ordinal)
                .Take(32)
                .ToArray();
            var warnings = new List<string>();
            if (allowListed)
            {
                warnings.Add("The address matches the configured allow-list and cannot be denied.");
            }

            if (ruleState == "pre-existing-unmanaged-deny")
            {
                warnings.Add("The existing deny rule is not recorded as service-owned and will not be adopted or removed.");
            }

            if (inspection.OtherSitesSharingPools.Count > 0)
            {
                warnings.Add("The target site's application pools are shared with other sites; IIS configuration changes may recycle those pools.");
            }

            var expiresAt = GetExpiryTime();
            RecordAction(actor, "preview", request.SiteName, normalizedIp, request.Reason ?? "Deny-list preview", "requested", policy, expiresAt);
            return new DenyListPreview(
                inspection.SiteName,
                normalizedIp,
                $"ipAddress={normalizedIp}; allowed=false",
                expiresAt,
                policy.Mode.ToString(),
                allowListed,
                policy.CanMutate && !allowListed && ruleState == "missing",
                ruleState,
                evidence,
                inspection.ApplicationPools,
                inspection.OtherSitesSharingPools,
                warnings);
        }
    }

    public void ReconcilePendingManagedDenies()
    {
        if (!_adminOptions.GetEnforcementPolicy().CanMutate)
        {
            return;
        }

        lock (_mutationSync)
        {
            using var mutationLock = _denyListStore.AcquireMutationLock();
            foreach (var entry in _denyListStore.GetPendingManagedDenies(250))
            {
                IisDenyListInspection inspection;
                try
                {
                    inspection = _iisDenyListWriter.Inspect(entry.SiteName, entry.ClientIp);
                }
                catch (Exception exception)
                {
                    RecordAction("system:recovery", "recover", entry.SiteName, entry.ClientIp,
                        "Reconcile pending IIS mutation", "failed", _adminOptions.GetEnforcementPolicy(), entry.ExpiresAt);
                    _logger.LogWarning(exception, "Unable to inspect pending deny-list operation {AuditId} for recovery.", entry.AuditId);
                    continue;
                }

                if (string.Equals(entry.State, "pending-remove", StringComparison.Ordinal))
                {
                    if (inspection.RuleState == "missing")
                    {
                        _denyListStore.TryRemoveManagedDeny(entry.SiteName, entry.ClientIp, entry.State, entry.AuditId);
                        RecordAction("system:recovery", "recover", entry.SiteName, entry.ClientIp,
                            "Reconciled completed deny-list removal", "reverted", _adminOptions.GetEnforcementPolicy(), entry.ExpiresAt);
                    }
                    else if (inspection.RuleState == "denied")
                    {
                        _denyListStore.CompleteManagedDeny(entry.SiteName, entry.ClientIp, entry.ExpiresAt, entry.AuditId);
                        RecordAction("system:recovery", "recover", entry.SiteName, entry.ClientIp,
                            "Restored ownership after unapplied removal", "failed", _adminOptions.GetEnforcementPolicy(), entry.ExpiresAt);
                    }
                    else
                    {
                        _denyListStore.TryRemoveManagedDeny(entry.SiteName, entry.ClientIp, entry.State, entry.AuditId);
                        RecordAction("system:recovery", "recover", entry.SiteName, entry.ClientIp,
                            "Preserved administrator allow rule", "reverted", _adminOptions.GetEnforcementPolicy(), entry.ExpiresAt);
                    }
                }
                else if (inspection.RuleState == "missing" || inspection.RuleState == "allow")
                {
                    _denyListStore.TryRemoveManagedDeny(entry.SiteName, entry.ClientIp, entry.State, entry.AuditId);
                    RecordAction("system:recovery", "recover", entry.SiteName, entry.ClientIp,
                        "Reverted unapplied or superseded deny-list addition", "reverted", _adminOptions.GetEnforcementPolicy(), entry.ExpiresAt);
                }
                else
                {
                    _denyListStore.TryTransitionManagedDeny(
                        entry.SiteName, entry.ClientIp, entry.State, entry.AuditId, "recovery-required", entry.AuditId);
                    RecordAction("system:recovery", "recover", entry.SiteName, entry.ClientIp,
                        "Ambiguous deny rule preserved for administrator review", "recovery-required", _adminOptions.GetEnforcementPolicy(), entry.ExpiresAt);
                }
            }
        }
    }

    public bool AddDeniedIp(
        string siteName,
        string clientIp,
        string actor = "manual",
        string reason = "Manual deny-list request",
        SecurityEvent? securityEvent = null,
        string? domain = null)
    {
        if (!IisDenyListWriter.IsValidSiteName(siteName) ||
            !IisIpAllowList.TryNormalizeAddress(clientIp, out var normalizedIp))
        {
            return false;
        }

        lock (_mutationSync)
        {
            using var mutationLock = _denyListStore.AcquireMutationLock();
            var policy = _adminOptions.GetEnforcementPolicy();
            var expiresAt = GetExpiryTime();
            RecordAction(actor, "add", siteName, normalizedIp, reason, "requested", policy, expiresAt);

            if (IsAllowListed(normalizedIp, actor, "add", siteName, reason, policy, securityEvent, domain))
            {
                return false;
            }

            if (!policy.WritesEnabled || policy.Mode == DenyListEnforcementMode.Observe)
            {
                RecordAction(actor, "add", siteName, normalizedIp, reason, "observed", policy, expiresAt);
                return false;
            }

            if (policy.IsSimulation)
            {
                RecordAction(actor, "add", siteName, normalizedIp, reason, "simulated", policy, expiresAt);
                LogDenyAction("add", "simulated", normalizedIp, siteName, reason, securityEvent, domain, expiresAt);
                return true;
            }

            var managedEntry = _denyListStore.GetManagedDeny(siteName, normalizedIp);
            if (managedEntry is not null && !string.Equals(managedEntry.State, "active", StringComparison.Ordinal))
            {
                RecordAction(actor, "add", siteName, normalizedIp, reason, "recovery-required", policy, expiresAt);
                return false;
            }

            var auditId = RecordAction(actor, "add", siteName, normalizedIp, reason, "attempted", policy, expiresAt);
            IisDenyListMutationResult writeResult;
            try
            {
                writeResult = RetryIisMutation(() => _iisDenyListWriter.EnsureDenied(
                    siteName,
                    normalizedIp,
                    () =>
                    {
                        if (managedEntry is null)
                        {
                            var pendingEntry = new ManagedDenyListEntry(siteName, normalizedIp, expiresAt, "pending-add", auditId);
                            if (!_denyListStore.TryPrepareManagedDeny(pendingEntry))
                            {
                                var concurrentEntry = _denyListStore.GetManagedDeny(siteName, normalizedIp);
                                if (concurrentEntry is null || concurrentEntry.State != "pending-add" || concurrentEntry.AuditId != auditId)
                                {
                                    throw new InvalidOperationException("A concurrent deny-list operation already owns this site/address.");
                                }
                            }
                        }
                        else
                        {
                            if (!_denyListStore.TryTransitionManagedDeny(
                                    siteName, normalizedIp, "active", managedEntry.AuditId, "pending-add", auditId))
                            {
                                var concurrentEntry = _denyListStore.GetManagedDeny(siteName, normalizedIp);
                                if (concurrentEntry is null || concurrentEntry.State != "pending-add" || concurrentEntry.AuditId != auditId)
                                {
                                    throw new InvalidOperationException("A concurrent deny-list operation changed ownership state.");
                                }
                            }
                        }
                    }));
            }
            catch (Exception exception)
            {
                RecordAction(actor, "add", siteName, normalizedIp, reason, "failed", policy, expiresAt);
                LogDenyAction("add", "failed", normalizedIp, siteName, reason, securityEvent, domain, expiresAt, exception);
                return false;
            }

            switch (writeResult.Status)
            {
                case IisDenyListMutationStatus.Added:
                    try
                    {
                        if (!_denyListStore.CompleteManagedDeny(siteName, normalizedIp, expiresAt, auditId))
                        {
                            throw new InvalidOperationException("The managed deny-list ownership state changed during commit.");
                        }
                    }
                    catch (Exception exception)
                    {
                        RecordAction(actor, "add", siteName, normalizedIp, reason, "recovery-required", policy, expiresAt);
                        LogDenyAction("add", "failed", normalizedIp, siteName, reason, securityEvent, domain, expiresAt, exception);
                        return false;
                    }

                    RecordAction(actor, "add", siteName, normalizedIp, reason, "succeeded", policy, expiresAt);
                    LogDenyAction("add", "succeeded", normalizedIp, siteName, reason, securityEvent, domain, expiresAt);
                    return true;
                case IisDenyListMutationStatus.AlreadyDenied:
                    var alreadyDeniedOutcome = managedEntry is null ? "pre-existing-unmanaged" : "already-managed";
                    RecordAction(actor, "add", siteName, normalizedIp, reason, alreadyDeniedOutcome, policy, managedEntry?.ExpiresAt);
                    LogDenyAction("add", alreadyDeniedOutcome, normalizedIp, siteName, reason, securityEvent, domain, managedEntry?.ExpiresAt);
                    return false;
                case IisDenyListMutationStatus.ExistingAllowRule:
                    if (managedEntry is not null)
                    {
                        _denyListStore.TryRemoveManagedDeny(siteName, normalizedIp, managedEntry.State, managedEntry.AuditId);
                    }

                    RecordAction(actor, "add", siteName, normalizedIp, reason, "existing-allow-rule", policy);
                    LogDenyAction("add", "existing-allow-rule", normalizedIp, siteName, reason, securityEvent, domain);
                    return false;
                default:
                    RecordAction(actor, "add", siteName, normalizedIp, reason, "failed", policy, expiresAt);
                    LogDenyAction("add", "failed", normalizedIp, siteName, reason, securityEvent, domain, expiresAt, writeResult.Exception);
                    return false;
            }
        }
    }

    public IReadOnlyList<string> AddDeniedIpToDomains(
        string clientIp,
        IEnumerable<string> domains,
        string actor = "manual",
        string reason = "Manual deny-list request",
        SecurityEvent? securityEvent = null)
    {
        if (!IisIpAllowList.TryNormalizeAddress(clientIp, out var normalizedIp))
        {
            return [];
        }

        lock (_mutationSync)
        {
            using var mutationLock = _denyListStore.AcquireMutationLock();
            var policy = _adminOptions.GetEnforcementPolicy();
            var targetDomains = (domains ?? [])
                .Where(static domain => !string.IsNullOrWhiteSpace(domain) && domain.Length <= 253 && !domain.Any(char.IsControl))
                .Select(IisSiteDiscoveryService.NormalizeDomain)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(64)
                .ToArray();
            var targetSiteName = SiteIdentityNormalizer.GetSiteName(securityEvent?.Properties);
            if (!IisDenyListWriter.IsValidSiteName(targetSiteName))
            {
                targetSiteName = string.Empty;
            }
            RecordAction(actor, "add", "*", normalizedIp, reason, "requested", policy, GetExpiryTime());

            if (IsAllowListed(normalizedIp, actor, "add", "*", reason, policy, securityEvent, string.Join(", ", targetDomains)))
            {
                return [];
            }

            if (!policy.WritesEnabled || policy.Mode == DenyListEnforcementMode.Observe)
            {
                RecordAction(actor, "add", "*", normalizedIp, reason, "observed", policy, GetExpiryTime());
                return [];
            }

            if (policy.IsSimulation)
            {
                RecordAction(actor, "add", "*", normalizedIp,
                    $"{reason}; target domains: {string.Join(", ", targetDomains)}", "simulated", policy, GetExpiryTime());
                LogDenyAction("add", "simulated", normalizedIp, "*", reason, securityEvent, string.Join(", ", targetDomains), GetExpiryTime());
                return [];
            }

            if (targetDomains.Length == 0 && targetSiteName.Length == 0)
            {
                RecordAction(actor, "add", "*", normalizedIp, reason, "no-target-domains", policy, GetExpiryTime());
                return [];
            }

            var targetSites = _siteDiscoveryService.GetSites()
                .Where(site =>
                    string.Equals(site.Name, targetSiteName, StringComparison.OrdinalIgnoreCase) ||
                    site.Domains.Any(siteDomain => targetDomains.Any(targetDomain =>
                        string.Equals(IisSiteDiscoveryService.NormalizeDomain(siteDomain), targetDomain, StringComparison.OrdinalIgnoreCase))))
                .Select(site => site.Name)
                .Where(IisDenyListWriter.IsValidSiteName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (targetSites.Length == 0)
            {
                RecordAction(actor, "add", "*", normalizedIp, reason, "no-matching-sites", policy, GetExpiryTime());
                LogDenyAction("add", "no-matching-sites", normalizedIp, "*", reason, securityEvent, string.Join(", ", targetDomains));
                return [];
            }

            var updatedSites = new List<string>(targetSites.Length);
            foreach (var siteName in targetSites)
            {
                if (AddDeniedIp(siteName, normalizedIp, actor, reason, securityEvent, string.Join(", ", targetDomains)))
                {
                    updatedSites.Add(siteName);
                }
            }

            return updatedSites;
        }
    }

    public bool RemoveDeniedIp(
        string siteName,
        string clientIp,
        string actor = "manual",
        string reason = "Manual deny-list removal")
        => RemoveDeniedIpWithStatus(siteName, clientIp, actor, reason) is
            DenyListRemovalStatus.Removed or DenyListRemovalStatus.Simulated;

    public DenyListRemovalStatus RemoveDeniedIpWithStatus(
        string siteName,
        string clientIp,
        string actor = "manual",
        string reason = "Manual deny-list removal")
    {
        if (!IisDenyListWriter.IsValidSiteName(siteName) ||
            !IisIpAllowList.TryNormalizeAddress(clientIp, out var normalizedIp))
        {
            return DenyListRemovalStatus.Invalid;
        }

        lock (_mutationSync)
        {
            using var mutationLock = _denyListStore.AcquireMutationLock();
            var policy = _adminOptions.GetEnforcementPolicy();
            RecordAction(actor, "remove", siteName, normalizedIp, reason, "requested", policy, expiresAt: null);
            if (!policy.WritesEnabled || policy.Mode == DenyListEnforcementMode.Observe)
            {
                RecordAction(actor, "remove", siteName, normalizedIp, reason, "observed", policy, expiresAt: null);
                return DenyListRemovalStatus.Observed;
            }

            if (policy.IsSimulation)
            {
                RecordAction(actor, "remove", siteName, normalizedIp, reason, "simulated", policy, expiresAt: null);
                return DenyListRemovalStatus.Simulated;
            }

            var managedEntry = _denyListStore.GetManagedDeny(siteName, normalizedIp);
            if (managedEntry is null)
            {
                try
                {
                    if (_iisDenyListWriter.Inspect(siteName, normalizedIp).RuleState == "missing")
                    {
                        RecordAction(actor, "remove", siteName, normalizedIp, reason, "not-found", policy);
                        return DenyListRemovalStatus.NotFound;
                    }
                }
                catch (InvalidOperationException)
                {
                    RecordAction(actor, "remove", siteName, normalizedIp, reason, "not-found", policy);
                    return DenyListRemovalStatus.NotFound;
                }
                catch (Exception exception)
                {
                    RecordAction(actor, "remove", siteName, normalizedIp, reason, "failed", policy);
                    LogDenyAction("remove", "failed", normalizedIp, siteName, reason, securityEvent: null, exception: exception);
                    return DenyListRemovalStatus.Failed;
                }

                RecordAction(actor, "remove", siteName, normalizedIp, reason, "skipped-not-service-owned", policy);
                return DenyListRemovalStatus.NotServiceOwned;
            }

            if (!string.Equals(managedEntry.State, "active", StringComparison.Ordinal))
            {
                RecordAction(actor, "remove", siteName, normalizedIp, reason, "recovery-required", policy, managedEntry.ExpiresAt);
                return DenyListRemovalStatus.RecoveryRequired;
            }

            var auditId = RecordAction(actor, "remove", siteName, normalizedIp, reason, "attempted", policy, managedEntry.ExpiresAt);
            if (!_denyListStore.TryTransitionManagedDeny(
                    siteName, normalizedIp, "active", managedEntry.AuditId, "pending-remove", auditId))
            {
                RecordAction(actor, "remove", siteName, normalizedIp, reason, "skipped-concurrent-change", policy, managedEntry.ExpiresAt);
                return DenyListRemovalStatus.ConcurrentChange;
            }

            var result = RetryIisMutation(() => _iisDenyListWriter.RemoveDenied(siteName, normalizedIp));
            if (result.Status is IisDenyListMutationStatus.Removed or IisDenyListMutationStatus.NotFound)
            {
                try
                {
                    if (!_denyListStore.TryRemoveManagedDeny(siteName, normalizedIp, "pending-remove", auditId))
                    {
                        RecordAction(actor, "remove", siteName, normalizedIp, reason, "skipped-concurrent-change", policy, managedEntry.ExpiresAt);
                        return DenyListRemovalStatus.ConcurrentChange;
                    }
                }
                catch (Exception exception)
                {
                    RecordAction(actor, "remove", siteName, normalizedIp, reason, "recovery-required", policy, managedEntry.ExpiresAt);
                    LogDenyAction("remove", "failed", normalizedIp, siteName, reason, securityEvent: null, expiresAt: managedEntry.ExpiresAt, exception: exception);
                    return DenyListRemovalStatus.Failed;
                }

                var outcome = result.Status == IisDenyListMutationStatus.NotFound ? "already-removed" : "succeeded";
                RecordAction(actor, "remove", siteName, normalizedIp, reason, outcome, policy, managedEntry.ExpiresAt);
                LogDenyAction("remove", outcome, normalizedIp, siteName, reason, securityEvent: null, expiresAt: managedEntry.ExpiresAt);
                return DenyListRemovalStatus.Removed;
            }

            RecordAction(actor, "remove", siteName, normalizedIp, reason, "failed", policy, managedEntry.ExpiresAt);
            LogDenyAction("remove", "failed", normalizedIp, siteName, reason, securityEvent: null, expiresAt: managedEntry.ExpiresAt, exception: result.Exception);
            return DenyListRemovalStatus.Failed;
        }
    }

    public bool RemoveExpiredDeniedIp(TemporaryDenyListEntry entry)
    {
        if (!IisDenyListWriter.IsValidSiteName(entry.SiteName) ||
            !IisIpAllowList.TryNormalizeAddress(entry.ClientIp, out var normalizedIp))
        {
            return false;
        }

        lock (_mutationSync)
        {
            using var mutationLock = _denyListStore.AcquireMutationLock();
            var policy = _adminOptions.GetEnforcementPolicy();
            var managedEntry = _denyListStore.GetManagedDeny(entry.SiteName, normalizedIp);
            if (managedEntry is null || managedEntry.ExpiresAt is null ||
                managedEntry.ExpiresAt.Value != entry.ExpiresAt || managedEntry.ExpiresAt.Value > DateTimeOffset.UtcNow)
            {
                return true;
            }

            RecordAction(ExpiryCleanupActor, "expire", entry.SiteName, normalizedIp, ExpiryCleanupReason, "requested", policy, entry.ExpiresAt);
            if (!policy.WritesEnabled || policy.Mode == DenyListEnforcementMode.Observe)
            {
                RecordAction(ExpiryCleanupActor, "expire", entry.SiteName, normalizedIp, ExpiryCleanupReason, "observed", policy, entry.ExpiresAt);
                return false;
            }

            if (policy.IsSimulation)
            {
                RecordAction(ExpiryCleanupActor, "expire", entry.SiteName, normalizedIp, ExpiryCleanupReason, "simulated-expiry", policy, entry.ExpiresAt);
                return false;
            }

            if (!string.Equals(managedEntry.State, "active", StringComparison.Ordinal))
            {
                RecordAction(ExpiryCleanupActor, "expire", entry.SiteName, normalizedIp, ExpiryCleanupReason, "recovery-required", policy, entry.ExpiresAt);
                return false;
            }

            var auditId = RecordAction(ExpiryCleanupActor, "expire", entry.SiteName, normalizedIp, ExpiryCleanupReason, "attempted", policy, entry.ExpiresAt);
            if (!_denyListStore.TryTransitionManagedDeny(
                    entry.SiteName, normalizedIp, "active", managedEntry.AuditId, "pending-remove", auditId))
            {
                RecordAction(ExpiryCleanupActor, "expire", entry.SiteName, normalizedIp, ExpiryCleanupReason, "skipped-concurrent-change", policy, entry.ExpiresAt);
                return false;
            }
            var result = RetryIisMutation(() => _iisDenyListWriter.RemoveDenied(entry.SiteName, normalizedIp));
            if (result.Status is not (IisDenyListMutationStatus.Removed or IisDenyListMutationStatus.NotFound))
            {
                RecordAction(ExpiryCleanupActor, "expire", entry.SiteName, normalizedIp, ExpiryCleanupReason, "failed", policy, entry.ExpiresAt);
                LogDenyAction("expire", "failed", normalizedIp, entry.SiteName, ExpiryCleanupReason, securityEvent: null, expiresAt: entry.ExpiresAt, exception: result.Exception);
                return false;
            }

            try
            {
                if (!_denyListStore.TryRemoveManagedDeny(entry.SiteName, normalizedIp, "pending-remove", auditId))
                {
                    RecordAction(ExpiryCleanupActor, "expire", entry.SiteName, normalizedIp, ExpiryCleanupReason, "skipped-concurrent-change", policy, entry.ExpiresAt);
                    return false;
                }
            }
            catch (Exception exception)
            {
                RecordAction(ExpiryCleanupActor, "expire", entry.SiteName, normalizedIp, ExpiryCleanupReason, "recovery-required", policy, entry.ExpiresAt);
                LogDenyAction("expire", "failed", normalizedIp, entry.SiteName, ExpiryCleanupReason, securityEvent: null, expiresAt: entry.ExpiresAt, exception: exception);
                return false;
            }

            var outcome = result.Status == IisDenyListMutationStatus.NotFound ? "expired-already-removed" : "expired";
            RecordAction(ExpiryCleanupActor, "expire", entry.SiteName, normalizedIp, ExpiryCleanupReason, outcome, policy, entry.ExpiresAt);
            LogDenyAction("expire", outcome, normalizedIp, entry.SiteName, ExpiryCleanupReason, securityEvent: null, expiresAt: entry.ExpiresAt);
            return true;
        }
    }

    private bool IsAllowListed(
        string clientIp,
        string actor,
        string action,
        string siteName,
        string reason,
        DenyListEnforcementPolicy policy,
        SecurityEvent? securityEvent,
        string? domain = null)
    {
        if (!_ipAllowList.Contains(clientIp))
        {
            return false;
        }

        LogDenyAction(action, "skipped-allow-list", clientIp, siteName, reason, securityEvent, domain);
        RecordAction(actor, action, siteName, clientIp, reason, "skipped-allow-list", policy, GetExpiryTime());
        return true;
    }

    private void LogDenyAction(
        string action,
        string outcome,
        string clientIp,
        string siteName,
        string reason,
        SecurityEvent? securityEvent,
        string? domain = null,
        DateTimeOffset? expiresAt = null,
        Exception? exception = null)
    {
        const string message = "IIS deny-list operation completed. Action={Action} Outcome={Outcome} FailureType={FailureType}";
        var failureType = exception?.GetType().Name;

        if (exception is not null)
        {
            _logger.LogError(message, action, outcome, failureType);
        }
        else if (outcome == "failed")
        {
            _logger.LogWarning(message, action, outcome, failureType);
        }
        else
        {
            _logger.LogInformation(message, action, outcome, failureType);
        }
    }

    private DateTimeOffset? GetExpiryTime()
        => _adminOptions.TemporaryBanMinutes > 0
            ? DateTimeOffset.UtcNow.AddMinutes(_adminOptions.TemporaryBanMinutes)
            : null;

    private long RecordAction(
        string actor,
        string action,
        string siteName,
        string clientIp,
        string reason,
        string outcome,
        DenyListEnforcementPolicy policy,
        DateTimeOffset? expiresAt = null)
    {
        var auditId = _denyListStore.RecordAudit(new DenyListAuditRecord(
            0,
            string.IsNullOrWhiteSpace(actor) ? "unknown" : actor,
            action,
            siteName,
            clientIp,
            string.IsNullOrWhiteSpace(reason) ? action : reason[..Math.Min(reason.Length, 1024)],
            DateTimeOffset.UtcNow,
            policy.Mode != DenyListEnforcementMode.Enforce,
            outcome,
            expiresAt));

        if (outcome is not ("requested" or "attempted"))
        {
            _observability?.RecordIisEnforcementOutcome(outcome, policy.IsSimulation);
            if (action == "expire")
            {
                switch (outcome)
                {
                    case "simulated-expiry":
                        _observability?.RecordExpiryCleanupSimulated();
                        break;
                    case "expired":
                    case "expired-already-removed":
                        _observability?.RecordExpiryCleanupSucceeded();
                        break;
                    case "failed":
                    case "recovery-required":
                        _observability?.RecordExpiryCleanupFailure();
                        break;
                }
            }
        }

        return auditId;
    }

    private static IisDenyListMutationResult RetryIisMutation(Func<IisDenyListMutationResult> mutation)
    {
        const int maximumAttempts = 3;
        for (var attempt = 1; attempt <= maximumAttempts; attempt++)
        {
            var result = mutation();
            if (result.Status != IisDenyListMutationStatus.Failed ||
                result.Exception is null ||
                !IsTransientIisFailure(result.Exception) ||
                attempt == maximumAttempts)
            {
                return result;
            }

            Thread.Sleep(attempt * 100);
        }

        throw new InvalidOperationException("The bounded IIS retry loop exited unexpectedly.");
    }

    private static bool IsTransientIisFailure(Exception exception)
        => exception is IOException or TimeoutException or COMException;

    private long BeginAudit(string actor, string action, string siteName, string clientIp, string reason, DateTimeOffset? expiresAt)
        => _denyListStore.BeginAudit(new DenyListAuditRecord(
            0,
            string.IsNullOrWhiteSpace(actor) ? "unknown" : actor,
            action,
            siteName,
            clientIp,
            string.IsNullOrWhiteSpace(reason) ? action : reason,
            DateTimeOffset.UtcNow,
            _adminOptions.DryRun,
            "pending",
            expiresAt));

    private void RecordCompletedAudit(
        string actor,
        string action,
        string siteName,
        string clientIp,
        string reason,
        bool dryRun,
        string outcome,
        DateTimeOffset? expiresAt)
    {
        var auditId = _denyListStore.BeginAudit(new DenyListAuditRecord(
            0,
            string.IsNullOrWhiteSpace(actor) ? "unknown" : actor,
            action,
            siteName,
            clientIp,
            string.IsNullOrWhiteSpace(reason) ? action : reason,
            DateTimeOffset.UtcNow,
            dryRun,
            "pending",
            expiresAt));
        CompleteAudit(auditId, outcome);
    }

    private void CompleteAudit(long auditId, string outcome)
    {
        _denyListStore.CompleteAudit(auditId, outcome);
        _logger.LogInformation("Deny-list audit {AuditId}: {Outcome}.", auditId, outcome);
    }

    private void RestoreExpiry(string siteName, string clientIp, DateTimeOffset? previousExpiry)
    {
        if (previousExpiry is { } expiry)
        {
            _denyListStore.SetExpiry(siteName, clientIp, expiry);
        }
        else
        {
            _denyListStore.RemoveExpiry(siteName, clientIp);
        }
    }

    private bool RemoveDeniedIpFromIis(
        string siteName,
        string clientIp,
        string reason,
        SecurityEvent? securityEvent = null,
        string? domain = null,
        bool deniedRulesOnly = false)
    {
        try
        {
            var result = _iisDenyListWriter.RemoveDenied(siteName, clientIp);
            if (result.Status == IisDenyListMutationStatus.Failed)
            {
                if (result.Exception is { } exception)
                {
                    LogMutationFailure(exception, "remove", clientIp, siteName, reason, securityEvent, domain);
                }

                return false;
            }

            return result.Status is IisDenyListMutationStatus.Removed or IisDenyListMutationStatus.NotFound;
        }
        catch (Exception ex)
        {
            LogMutationFailure(ex, "remove", clientIp, siteName, reason, securityEvent, domain);
            return false;
        }
    }

    private IisDenyListMutationResult WriteDeniedIp(
        string siteName,
        string clientIp,
        string reason,
        SecurityEvent? securityEvent,
        string? domain,
        Action prepareNewEntry)
    {
        var result = _iisDenyListWriter.EnsureDenied(siteName, clientIp, prepareNewEntry);
        if (result.Status == IisDenyListMutationStatus.Failed && result.Exception is { } exception)
        {
            LogMutationFailure(exception, "add", clientIp, siteName, reason, securityEvent, domain);
        }

        return result;
    }

    private void SetExpiry(string siteName, string clientIp, DateTimeOffset? expiresAt)
    {
        if (expiresAt is { } value)
        {
            _denyListStore.SetExpiry(siteName, clientIp, value);
        }
        else
        {
            _denyListStore.RemoveExpiry(siteName, clientIp);
        }
    }

    private void LogMutationFailure(
        Exception exception,
        string action,
        string clientIp,
        string siteName,
        string reason,
        SecurityEvent? securityEvent,
        string? domain)
    {
        _logger.LogWarning(
            exception,
            "Failed to {DenyListAction} deny-list entry for {ClientIp} on {Domain} (site {SiteName}); risk score {RiskScore}, severity {RiskSeverity}, detection reason {DetectionReason}. Reason: {Reason}",
            action,
            clientIp,
            domain ?? siteName,
            siteName,
            securityEvent?.RiskScore ?? 0,
            securityEvent?.RiskSeverity ?? "Unknown",
            securityEvent?.DetectionReason ?? "Not applicable",
            reason);
    }

    private static IisAdminOptions ValidateOptions(IisAdminOptions options)
    {
        if (options.TemporaryBanMinutes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "IisAdmin:TemporaryBanMinutes must be zero or greater.");
        }

        if (!IisAdminOptions.IsValidEnforcementMode(options.EnforcementMode) ||
            !IisIpAllowList.IsValidAllowList(options.AllowList))
        {
            throw new ArgumentException("IIS enforcement mode or IP allow-list configuration is invalid.", nameof(options));
        }

        return options;
    }
}
