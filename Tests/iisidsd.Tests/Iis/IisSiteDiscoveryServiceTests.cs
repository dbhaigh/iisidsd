using iisidsd.Iis;
using Microsoft.Extensions.Logging.Abstractions;

namespace iisidsd.Tests.Iis;

public sealed class IisSiteDiscoveryServiceTests
{
    [Fact]
    public void GetSites_ParsesAppCmdSiteMetadataAndBindings()
    {
        var appCmd = new FakeAppCmdRunner(
            true,
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <appcmd>
              <SITE SITE.NAME="Example Site" SITE.ID="7" bindings="https/*:443:example.test,http/*:80:example.test" state="Started" />
            </appcmd>
            """,
            string.Empty);
        var service = new IisSiteDiscoveryService(NullLogger<IisSiteDiscoveryService>.Instance, appCmd);

        var site = Assert.Single(service.GetSites());

        Assert.Equal(7, site.SiteId);
        Assert.Equal("Example Site", site.Name);
        Assert.Equal("Started", site.State);
        Assert.Equal(["https/*:443:example.test", "http/*:80:example.test"], site.Bindings);
        Assert.Equal(["example.test"], site.Domains);
        Assert.Equal(["list", "site", "/xml"], appCmd.Arguments);
    }

    [Fact]
    public void GetSites_ReturnsEmptyWhenAppCmdFails()
    {
        var appCmd = new FakeAppCmdRunner(false, string.Empty, "appcmd.exe is unavailable.");
        var service = new IisSiteDiscoveryService(NullLogger<IisSiteDiscoveryService>.Instance, appCmd);

        Assert.Empty(service.GetSites());
    }

    private sealed class FakeAppCmdRunner(bool success, string output, string error) : IAppCmdRunner
    {
        public string[] Arguments { get; private set; } = [];

        public (bool Success, string Output, string Error) Run(params string[] arguments)
        {
            Arguments = arguments;
            return (success, output, error);
        }
    }
}
