using System.Linq;
using Microsoft.Web.Administration;

namespace iisidsd.Iis;

public sealed class IisDenyListWriter : IIisDenyListWriter
{
    public IisDenyListMutationResult EnsureDenied(string siteName, string clientIp, Action prepareNewEntry)
    {
        ArgumentNullException.ThrowIfNull(prepareNewEntry);

        ServerManager? manager = null;
        ConfigurationElementCollection collection;
        ConfigurationElement? existing;
        try
        {
            manager = new ServerManager();
            var section = manager.GetApplicationHostConfiguration()
                .GetSection("system.webServer/security/ipSecurity", siteName);
            collection = section.GetCollection();
            existing = collection.Cast<ConfigurationElement>().FirstOrDefault(element =>
                string.Equals((string?)element["ipAddress"], clientIp, StringComparison.OrdinalIgnoreCase));
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
                entry["ipAddress"] = clientIp;
                entry["allowed"] = false;
                collection.Add(entry);
                SuppressConfigChangeRotation(manager, siteName);
                manager.CommitChanges();
                return new IisDenyListMutationResult(IisDenyListMutationStatus.Added);
            }
            catch (Exception exception)
            {
                return new IisDenyListMutationResult(IisDenyListMutationStatus.Failed, exception);
            }
        }
    }

    public IisDenyListMutationResult RemoveDenied(string siteName, string clientIp, bool deniedRulesOnly = false)
    {
        try
        {
            using var manager = new ServerManager();
            var section = manager.GetApplicationHostConfiguration()
                .GetSection("system.webServer/security/ipSecurity", siteName);
            var collection = section.GetCollection();
            var entry = collection.Cast<ConfigurationElement>().FirstOrDefault(element =>
                string.Equals((string?)element["ipAddress"], clientIp, StringComparison.OrdinalIgnoreCase) &&
                (!deniedRulesOnly || Equals(element["allowed"], false)));
            if (entry is null)
            {
                return new IisDenyListMutationResult(IisDenyListMutationStatus.NotFound);
            }

            collection.Remove(entry);
            SuppressConfigChangeRotation(manager, siteName);
            manager.CommitChanges();
            return new IisDenyListMutationResult(IisDenyListMutationStatus.Removed);
        }
        catch (Exception exception)
        {
            return new IisDenyListMutationResult(IisDenyListMutationStatus.Failed, exception);
        }
    }

    private static void SuppressConfigChangeRotation(ServerManager manager, string siteName)
    {
        var site = manager.Sites[siteName]
            ?? throw new InvalidOperationException($"IIS site '{siteName}' was not found.");
        var applicationPoolNames = site.Applications
            .Cast<Microsoft.Web.Administration.Application>()
            .Select(application => application.ApplicationPoolName)
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (applicationPoolNames.Length == 0)
        {
            throw new InvalidOperationException($"IIS site '{siteName}' has no application pools.");
        }

        foreach (var applicationPoolName in applicationPoolNames)
        {
            var applicationPool = manager.ApplicationPools[applicationPoolName]
                ?? throw new InvalidOperationException($"IIS application pool '{applicationPoolName}' was not found.");
            applicationPool.Recycling.DisallowRotationOnConfigChange = true;
        }
    }
}
