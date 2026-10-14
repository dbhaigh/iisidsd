using System.Net;
using System.Xml.Linq;
using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.Extensions.Options;
using Microsoft.Web.Administration;

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
        IIisDenyListWriter iisDenyListWriter)
    {
        _appCmd = appCmdRunner;
        _siteDiscoveryService = siteDiscoveryService;
        _denyListStore = denyListStore;
        _ipAllowList = ipAllowList;
        _iisDenyListWriter = iisDenyListWriter;
        _adminOptions = ValidateOptions(adminOptions.Value);
        _logger = logger;
    }

    public IReadOnlyList<string> GetDeniedIps(string siteName)
    {
        if (string.IsNullOrWhiteSpace(siteName))
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

    public bool AddDeniedIp(
        string siteName,
        string clientIp,
        string actor = "manual",
        string reason = "Manual deny-list request",
        SecurityEvent? securityEvent = null,
        string? domain = null)
    {
        if (!CanMutate() || string.IsNullOrWhiteSpace(siteName) || !IPAddress.TryParse(clientIp, out _))
        {
            return false;
        }

        if (IsAllowListed(clientIp, actor, "add", siteName, reason, securityEvent, domain))
        {
            return false;
        }

        lock (_mutationSync)
        {
            var expiresAt = GetExpiryTime();
            var auditId = BeginAudit(actor, "add", siteName, clientIp, reason, expiresAt);
            if (_adminOptions.DryRun)
            {
                CompleteAudit(auditId, "dry-run");
                LogDenyAction("add", "dry-run", clientIp, siteName, reason, securityEvent, domain, expiresAt);
                return true;
            }

            DateTimeOffset? previousExpiry = null;
            var previousExpiryRead = false;
            IisDenyListWriteResult writeResult;
            try
            {
                previousExpiry = _denyListStore.GetExpiry(siteName, clientIp);
                previousExpiryRead = true;
                writeResult = WriteDeniedIp(
                    siteName,
                    clientIp,
                    reason,
                    securityEvent,
                    domain,
                    () => SetExpiry(siteName, clientIp, expiresAt));
            }
            catch (Exception exception)
            {
                if (previousExpiryRead)
                {
                    RestoreExpiry(siteName, clientIp, previousExpiry);
                }

                CompleteAudit(auditId, "failed");
                LogDenyAction("add", "failed", clientIp, siteName, reason, securityEvent, domain, expiresAt, exception);
                throw;
            }

            switch (writeResult.Status)
            {
                case IisDenyListWriteStatus.Added:
                    CompleteAudit(auditId, "succeeded");
                    LogDenyAction("add", "succeeded", clientIp, siteName, reason, securityEvent, domain, expiresAt);
                    return true;
                case IisDenyListWriteStatus.AlreadyDenied:
                    var existingExpiry = previousExpiry is null ? null : expiresAt;
                    if (previousExpiry is not null)
                    {
                        SetExpiry(siteName, clientIp, existingExpiry);
                    }

                    _denyListStore.SetAuditExpiry(auditId, existingExpiry);
                    var alreadyDeniedOutcome = existingExpiry is null
                        ? "already-denied-permanent"
                        : "already-denied-temporary";
                    CompleteAudit(auditId, alreadyDeniedOutcome);
                    LogDenyAction("add", alreadyDeniedOutcome, clientIp, siteName, reason, securityEvent, domain, existingExpiry);
                    return true;
                case IisDenyListWriteStatus.ExistingAllowRule:
                    _denyListStore.RemoveExpiry(siteName, clientIp);
                    _denyListStore.SetAuditExpiry(auditId, null);
                    CompleteAudit(auditId, "existing-allow-rule");
                    LogDenyAction("add", "existing-allow-rule", clientIp, siteName, reason, securityEvent, domain);
                    return false;
                default:
                    RestoreExpiry(siteName, clientIp, previousExpiry);
                    CompleteAudit(auditId, "failed");
                    LogDenyAction("add", "failed", clientIp, siteName, reason, securityEvent, domain, expiresAt, writeResult.Exception);
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
        if (!CanMutate() || !IPAddress.TryParse(clientIp, out _))
        {
            return [];
        }

        if (IsAllowListed(clientIp, actor, "add", "*", reason, securityEvent))
        {
            return [];
        }

        var targetDomains = (domains ?? [])
            .Where(static domain => !string.IsNullOrWhiteSpace(domain))
            .Select(NormalizeDomain)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (targetDomains.Length == 0)
        {
            RecordCompletedAudit(actor, "add", "*", clientIp, reason, _adminOptions.DryRun, "no-target-domains", GetExpiryTime());
            LogDenyAction("add", "no-target-domains", clientIp, "*", reason, securityEvent);
            return [];
        }

        if (_adminOptions.DryRun)
        {
            var dryRunReason = $"{reason}; target domains: {string.Join(", ", targetDomains)}";
            RecordCompletedAudit(actor, "add", "*", clientIp, dryRunReason, dryRun: true, "dry-run", GetExpiryTime());
            LogDenyAction("add", "dry-run", clientIp, "*", reason, securityEvent, string.Join(", ", targetDomains), GetExpiryTime());
            return [];
        }

        var targetSites = _siteDiscoveryService.GetSites()
            .Where(site => site.Domains.Any(siteDomain => targetDomains.Any(targetDomain =>
                string.Equals(NormalizeDomain(siteDomain), targetDomain, StringComparison.OrdinalIgnoreCase))))
            .Select(site => site.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (targetSites.Length == 0)
        {
            RecordCompletedAudit(actor, "add", "*", clientIp, reason, _adminOptions.DryRun, "no-matching-sites", GetExpiryTime());
            LogDenyAction("add", "no-matching-sites", clientIp, "*", reason, securityEvent, string.Join(", ", targetDomains));
            return [];
        }

        var updatedSites = new List<string>(targetSites.Length);
        foreach (var siteName in targetSites)
        {
            if (AddDeniedIp(siteName, clientIp, actor, reason, securityEvent, string.Join(", ", targetDomains)))
            {
                updatedSites.Add(siteName);
            }
        }

        return updatedSites;
    }

    public bool RemoveDeniedIp(
        string siteName,
        string clientIp,
        string actor = "manual",
        string reason = "Manual deny-list removal")
    {
        if (!CanMutate() || string.IsNullOrWhiteSpace(siteName) || !IPAddress.TryParse(clientIp, out _))
        {
            return false;
        }

        lock (_mutationSync)
        {
            var auditId = BeginAudit(actor, "remove", siteName, clientIp, reason, expiresAt: null);
            if (_adminOptions.DryRun)
            {
                CompleteAudit(auditId, "dry-run");
                LogDenyAction("remove", "dry-run", clientIp, siteName, reason, securityEvent: null);
                return true;
            }

            var succeeded = RemoveDeniedIpFromIis(siteName, clientIp, reason);
            if (succeeded)
            {
                _denyListStore.RemoveExpiry(siteName, clientIp);
            }

            CompleteAudit(auditId, succeeded ? "succeeded" : "failed");
            LogDenyAction("remove", succeeded ? "succeeded" : "failed", clientIp, siteName, reason, securityEvent: null);
            return succeeded;
        }
    }

    public bool RemoveExpiredDeniedIp(TemporaryDenyListEntry entry)
    {
        if (!CanMutate())
        {
            return false;
        }

        lock (_mutationSync)
        {
            var currentExpiry = _denyListStore.GetExpiry(entry.SiteName, entry.ClientIp);
            if (currentExpiry is null || currentExpiry.Value != entry.ExpiresAt || currentExpiry.Value > DateTimeOffset.UtcNow)
            {
                return true;
            }

            var auditId = BeginAudit(
                ExpiryCleanupActor,
                "expire",
                entry.SiteName,
                entry.ClientIp,
                ExpiryCleanupReason,
                entry.ExpiresAt);
            if (_adminOptions.DryRun)
            {
                CompleteAudit(auditId, "dry-run");
                LogDenyAction("expire", "dry-run", entry.ClientIp, entry.SiteName, ExpiryCleanupReason, securityEvent: null, expiresAt: entry.ExpiresAt);
                return false;
            }

            (bool Success, string Output, string Error) result;
            try
            {
                result = _appCmd.Run(
                    "set",
                    "config",
                    entry.SiteName,
                    "/section:system.webServer/security/ipSecurity",
                    $"/-[ipAddress='{entry.ClientIp}',allowed='false']",
                    "/commit:apphost");
            }
            catch (Exception exception)
            {
                CompleteAudit(auditId, "failed");
                LogDenyAction("expire", "failed", entry.ClientIp, entry.SiteName, ExpiryCleanupReason, securityEvent: null, expiresAt: entry.ExpiresAt, exception: exception);
                return false;
            }

            if (!result.Success)
            {
                CompleteAudit(auditId, "failed");
                LogDenyAction("expire", "failed", entry.ClientIp, entry.SiteName, ExpiryCleanupReason, securityEvent: null, expiresAt: entry.ExpiresAt);
                return false;
            }

            _denyListStore.RemoveExpiry(entry.SiteName, entry.ClientIp);
            CompleteAudit(auditId, "succeeded");
            LogDenyAction("expire", "succeeded", entry.ClientIp, entry.SiteName, ExpiryCleanupReason, securityEvent: null, expiresAt: entry.ExpiresAt);
            return true;
        }
    }

    private bool CanMutate()
    {
        if (_adminOptions.EnableDenyListChanges)
        {
            return true;
        }

        _logger.LogWarning("Deny-list mutation was skipped because IisAdmin:EnableDenyListChanges is disabled.");
        return false;
    }

    private bool IsAllowListed(
        string clientIp,
        string actor,
        string action,
        string siteName,
        string reason,
        SecurityEvent? securityEvent,
        string? domain = null)
    {
        if (!_ipAllowList.Contains(clientIp))
        {
            return false;
        }

        LogDenyAction(action, "skipped-allow-list", clientIp, siteName, reason, securityEvent, domain);
        RecordCompletedAudit(actor, action, siteName, clientIp, reason, _adminOptions.DryRun, "skipped-allow-list", GetExpiryTime());
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
        const string message = "IIS deny-list {Action} {Outcome}. ClientIp={ClientIp} Domain={Domain} RiskScore={RiskScore} RiskSeverity={RiskSeverity} DetectionReason={DetectionReason} SiteName={SiteName} ExpiresAt={ExpiresAt} Reason={Reason}";
        var logDomain = securityEvent?.Domain ?? domain;
        var riskScore = securityEvent?.RiskScore;
        var riskSeverity = securityEvent?.RiskSeverity;
        var detectionReason = securityEvent?.DetectionReason ?? reason;

        if (exception is not null)
        {
            _logger.LogError(exception, message, action, outcome, clientIp, logDomain, riskScore, riskSeverity, detectionReason, siteName, expiresAt, reason);
        }
        else if (outcome == "failed")
        {
            _logger.LogWarning(message, action, outcome, clientIp, logDomain, riskScore, riskSeverity, detectionReason, siteName, expiresAt, reason);
        }
        else
        {
            _logger.LogInformation(message, action, outcome, clientIp, logDomain, riskScore, riskSeverity, detectionReason, siteName, expiresAt, reason);
        }
    }

    private DateTimeOffset? GetExpiryTime()
        => _adminOptions.TemporaryBanMinutes > 0
            ? DateTimeOffset.UtcNow.AddMinutes(_adminOptions.TemporaryBanMinutes)
            : null;

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
        string? domain = null)
    {
        try
        {
            using var manager = new ServerManager();
            var section = manager.GetApplicationHostConfiguration().GetSection("system.webServer/security/ipSecurity", siteName);
            var collection = section.GetCollection();
            var entry = collection.Cast<ConfigurationElement>().FirstOrDefault(element =>
                string.Equals((string?)element["ipAddress"], clientIp, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
            {
                return true;
            }

            collection.Remove(entry);
            manager.CommitChanges();
            return true;
        }
        catch (Exception ex)
        {
            LogMutationFailure(ex, "remove", clientIp, siteName, reason, securityEvent, domain);
            return false;
        }
    }

    private IisDenyListWriteResult WriteDeniedIp(
        string siteName,
        string clientIp,
        string reason,
        SecurityEvent? securityEvent,
        string? domain,
        Action prepareNewEntry)
    {
        var result = _iisDenyListWriter.EnsureDenied(siteName, clientIp, prepareNewEntry);
        if (result.Status == IisDenyListWriteStatus.Failed && result.Exception is { } exception)
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

    private static string NormalizeDomain(string domain)
    {
        var value = domain.Trim().TrimEnd('.');
        var colonIndex = value.LastIndexOf(':');
        return colonIndex > -1 && value.IndexOf(':') == colonIndex ? value[..colonIndex] : value;
    }

    private static IisAdminOptions ValidateOptions(IisAdminOptions options)
    {
        if (options.TemporaryBanMinutes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "IisAdmin:TemporaryBanMinutes must be zero or greater.");
        }

        return options;
    }
}
