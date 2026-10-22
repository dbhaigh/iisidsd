using System.Linq;
using Microsoft.Web.Administration;

namespace iisidsd.Iis;

public sealed class IisDenyListWriter : IIisDenyListWriter
{
    public IisDenyListInspection Inspect(string siteName, string clientIp)
    {
        var normalizedIp = ValidateInputs(siteName, clientIp);
        using var manager = new ServerManager();
        var site = FindSite(manager, siteName);
        var section = manager.GetApplicationHostConfiguration()
            .GetSection("system.webServer/security/ipSecurity", site.Name);
        var existing = FindRule(section.GetCollection(), normalizedIp);
        var pools = site.Applications
            .Cast<Microsoft.Web.Administration.Application>()
            .Select(application => application.ApplicationPoolName)
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var otherSites = manager.Sites
            .Cast<Site>()
            .Where(otherSite => !string.Equals(otherSite.Name, site.Name, StringComparison.OrdinalIgnoreCase))
            .Where(otherSite => otherSite.Applications.Cast<Microsoft.Web.Administration.Application>()
                .Any(application => pools.Contains(application.ApplicationPoolName, StringComparer.OrdinalIgnoreCase)))
            .Select(otherSite => otherSite.Name)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new IisDenyListInspection(
            site.Name,
            normalizedIp,
            existing is null ? "missing" : Equals(existing["allowed"], false) ? "denied" : "allow",
            pools,
            otherSites);
    }

    public IisDenyListMutationResult EnsureDenied(string siteName, string clientIp, Action prepareNewEntry)
    {
        ArgumentNullException.ThrowIfNull(prepareNewEntry);
        var normalizedIp = ValidateInputs(siteName, clientIp);

        ServerManager? manager = null;
        ConfigurationElementCollection collection;
        ConfigurationElement? existing;
        try
        {
            manager = new ServerManager();
            var site = FindSite(manager, siteName);
            var section = manager.GetApplicationHostConfiguration()
                .GetSection("system.webServer/security/ipSecurity", site.Name);
            collection = section.GetCollection();
            existing = FindRule(collection, normalizedIp);
        }
        catch (Exception exception)
        {
            manager?.Dispose();
            return new IisDenyListMutationResult(IisDenyListMutationStatus.Failed, exception);
        }

        using (manager!)
        {
            if (existing is not null)
            {
                return new IisDenyListMutationResult(
                    Equals(existing["allowed"], false)
                        ? IisDenyListMutationStatus.AlreadyDenied
                        : IisDenyListMutationStatus.ExistingAllowRule);
            }

            prepareNewEntry();
            try
            {
                var entry = collection.CreateElement("add");
                entry["ipAddress"] = normalizedIp;
                entry["allowed"] = false;
                collection.Add(entry);
                manager.CommitChanges();
                return new IisDenyListMutationResult(IisDenyListMutationStatus.Added);
            }
            catch (Exception exception)
            {
                return new IisDenyListMutationResult(IisDenyListMutationStatus.Failed, exception);
            }
        }
    }

    public IisDenyListMutationResult RemoveDenied(string siteName, string clientIp)
    {
        try
        {
            var normalizedIp = ValidateInputs(siteName, clientIp);
            using var manager = new ServerManager();
            var site = FindSite(manager, siteName);
            var section = manager.GetApplicationHostConfiguration()
                .GetSection("system.webServer/security/ipSecurity", site.Name);
            var collection = section.GetCollection();
            var entry = collection.Cast<ConfigurationElement>().FirstOrDefault(element =>
                IsExactAddress((string?)element["ipAddress"], normalizedIp) &&
                Equals(element["allowed"], false));
            if (entry is null)
            {
                return new IisDenyListMutationResult(IisDenyListMutationStatus.NotFound);
            }

            collection.Remove(entry);
            manager.CommitChanges();
            return new IisDenyListMutationResult(IisDenyListMutationStatus.Removed);
        }
        catch (Exception exception)
        {
            return new IisDenyListMutationResult(IisDenyListMutationStatus.Failed, exception);
        }
    }

    public static bool IsValidSiteName(string? siteName)
        => !string.IsNullOrWhiteSpace(siteName) &&
            siteName.Length <= 128 &&
            string.Equals(siteName, siteName.Trim(), StringComparison.Ordinal) &&
            !siteName.Any(char.IsControl) &&
            siteName.IndexOfAny(['/', '\\', '?', '#', ':', ';']) < 0;

    private static string ValidateInputs(string siteName, string clientIp)
    {
        if (!IsValidSiteName(siteName))
        {
            throw new ArgumentException("The IIS site name is invalid.", nameof(siteName));
        }

        if (!IisIpAllowList.TryNormalizeAddress(clientIp, out var normalizedIp))
        {
            throw new ArgumentException("The client address must be a canonical IPv4 or IPv6 address.", nameof(clientIp));
        }

        return normalizedIp;
    }

    private static Site FindSite(ServerManager manager, string siteName)
        => manager.Sites.Cast<Site>().FirstOrDefault(site =>
            string.Equals(site.Name, siteName, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("The requested IIS site does not exist.");

    private static ConfigurationElement? FindRule(ConfigurationElementCollection collection, string clientIp)
        => collection.Cast<ConfigurationElement>().FirstOrDefault(element =>
            IsExactAddress((string?)element["ipAddress"], clientIp));

    private static bool IsExactAddress(string? configuredAddress, string clientIp)
        => IisIpAllowList.TryNormalizeAddress(configuredAddress, out var normalizedConfiguredAddress) &&
            string.Equals(normalizedConfiguredAddress, clientIp, StringComparison.OrdinalIgnoreCase);
}
