using iisidsd.Configuration;
using iisidsd.Iis;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Iis;

public sealed class IisIpAllowListTests
{
    [Fact]
    public void Contains_MatchesExactAddressesAndCidrRanges()
    {
        var allowList = new IisIpAllowList(Options.Create(new IisAdminOptions
        {
            AllowList = ["192.0.2.10", "198.51.100.0/24", "2001:db8::/32"]
        }));

        Assert.True(allowList.Contains("192.0.2.10"));
        Assert.True(allowList.Contains("198.51.100.254"));
        Assert.True(allowList.Contains("2001:db8:abcd::1"));
        Assert.False(allowList.Contains("198.51.101.1"));
        Assert.False(allowList.Contains("203.0.113.1"));
    }

    [Fact]
    public void Contains_NormalizesIpv4MappedIpv6AddressesAndRanges()
    {
        var allowList = new IisIpAllowList(Options.Create(new IisAdminOptions
        {
            AllowList = ["192.0.2.0/24", "::ffff:198.51.100.0/120"]
        }));

        Assert.True(allowList.Contains("::ffff:192.0.2.10"));
        Assert.True(allowList.Contains("198.51.100.25"));
        Assert.False(allowList.Contains("::ffff:198.51.101.25"));
    }

    [Fact]
    public void Contains_RejectsNonCanonicalIpv4AndScopedIpv6Inputs()
    {
        var allowList = new IisIpAllowList(Options.Create(new IisAdminOptions
        {
            AllowList = ["192.0.2.0/24", "fe80::/10"]
        }));

        Assert.False(allowList.Contains("192.0.2.010"));
        Assert.False(allowList.Contains("fe80::1%3"));
    }

    [Fact]
    public void Constructor_RejectsInvalidAllowListEntries()
    {
        var options = Options.Create(new IisAdminOptions { AllowList = ["192.0.2.1/99"] });

        Assert.Throws<ArgumentException>(() => new IisIpAllowList(options));
    }

    [Fact]
    public void Constructor_RejectsAmbiguousMappedIpv6Prefixes()
    {
        var options = Options.Create(new IisAdminOptions { AllowList = ["::ffff:0:0/80"] });

        Assert.Throws<ArgumentException>(() => new IisIpAllowList(options));
    }
}
