using System.Net;
using iisidsd.Configuration;
using iisidsd.Networking;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Configuration;

public sealed class TrustedProxyOptionsTests
{
    [Fact]
    public async Task ForwardedHeaders_AreIgnoredWhenProxyTrustIsDisabled()
    {
        var remoteAddress = await ApplyForwardedHeader(new TrustedProxyOptions(), IPAddress.Loopback);

        Assert.Equal(IPAddress.Loopback, remoteAddress);
    }

    [Fact]
    public async Task ForwardedHeaders_AreAcceptedOnlyFromConfiguredExactProxy()
    {
        var remoteAddress = await ApplyForwardedHeader(new TrustedProxyOptions
        {
            Enabled = true,
            TrustedProxyIps = ["127.0.0.1", "::1"]
        }, IPAddress.Loopback);

        Assert.Equal(IPAddress.Parse("198.51.100.7"), remoteAddress);
    }

    [Fact]
    public async Task ForwardedHeaders_AreIgnoredWhenImmediateProxyIsNotTrusted()
    {
        var remoteAddress = await ApplyForwardedHeader(new TrustedProxyOptions
        {
            Enabled = true,
            TrustedProxyIps = ["192.0.2.10"]
        }, IPAddress.Loopback);

        Assert.Equal(IPAddress.Loopback, remoteAddress);
    }

    [Fact]
    public void TryGetCanonicalProxies_NormalizesMappedIpv4AndRejectsInvalidValues()
    {
        var validOptions = new TrustedProxyOptions
        {
            Enabled = true,
            TrustedProxyIps = ["::ffff:127.0.0.1"]
        };
        var invalidOptions = new TrustedProxyOptions
        {
            Enabled = true,
            TrustedProxyIps = ["127.0.0.1/8"]
        };

        Assert.True(validOptions.TryGetCanonicalProxies(out var proxies));
        Assert.Equal(IPAddress.Loopback, Assert.Single(proxies));
        Assert.False(invalidOptions.TryGetCanonicalProxies(out _));
    }

    [Theory]
    [InlineData("127.1")]
    [InlineData("2130706433")]
    [InlineData("192.168.001.001")]
    [InlineData("192.0.2.1/24")]
    public void IpAddressNormalizer_RejectsAmbiguousOrNonAddressInputs(string value)
    {
        Assert.False(IpAddressNormalizer.TryNormalize(value, out _));
    }

    [Fact]
    public void IpAddressNormalizer_CanonicalizesExpandedIpv6()
    {
        Assert.True(IpAddressNormalizer.TryNormalize("2001:0db8:0:0:0:0:0:1", out var canonical));
        Assert.Equal("2001:db8::1", canonical);
    }

    private static async Task<IPAddress?> ApplyForwardedHeader(TrustedProxyOptions options, IPAddress remoteAddress)
    {
        var forwardedHeadersOptions = new ForwardedHeadersOptions();
        options.ConfigureForwardedHeaders(forwardedHeadersOptions);
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = remoteAddress;
        context.Request.Headers["X-Forwarded-For"] = "198.51.100.7";
        var middleware = new ForwardedHeadersMiddleware(_ => Task.CompletedTask,
            NullLoggerFactory.Instance, Options.Create(forwardedHeadersOptions));

        await middleware.Invoke(context);
        return context.Connection.RemoteIpAddress;
    }
}
