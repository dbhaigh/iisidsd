using System.Linq;
using Microsoft.Web.Administration;

namespace iisidsd.Iis;

public sealed class IisDenyListWriter : IIisDenyListWriter
{
    public IisDenyListWriteResult EnsureDenied(string siteName, string clientIp, Action prepareNewEntry)
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
            return new IisDenyListWriteResult(IisDenyListWriteStatus.Failed, exception);
        }

        using (manager!)
        {
            if (existing is not null)
            {
                return new IisDenyListWriteResult(
                    Equals(existing["allowed"], false)
                        ? IisDenyListWriteStatus.AlreadyDenied
                        : IisDenyListWriteStatus.ExistingAllowRule);
            }

            prepareNewEntry();
            try
            {
                var entry = collection.CreateElement("add");
                entry["ipAddress"] = clientIp;
                entry["allowed"] = false;
                collection.Add(entry);
                manager.CommitChanges();
                return new IisDenyListWriteResult(IisDenyListWriteStatus.Added);
            }
            catch (Exception exception)
            {
                return new IisDenyListWriteResult(IisDenyListWriteStatus.Failed, exception);
            }
        }
    }
}
