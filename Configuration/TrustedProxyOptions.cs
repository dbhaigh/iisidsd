using System.ComponentModel.DataAnnotations;
using System.Net;
using iisidsd.Networking;
using Microsoft.AspNetCore.HttpOverrides;

namespace iisidsd.Configuration;

public sealed class TrustedProxyOptions
{
    public const string SectionName = "TrustedProxies";

    public bool Enabled { get; set; }

    [Range(1, 10)]
    public int ForwardLimit { get; set; } = 1;

    [MaxLength(64)]
    public string[] TrustedProxyIps { get; set; } = [];

    public bool TryGetCanonicalProxies(out IPAddress[] proxies)
    {
        if (TrustedProxyIps is null || TrustedProxyIps.Length > 64)
        {
            proxies = [];
            return false;
        }

        var canonicalProxies = new List<IPAddress>(TrustedProxyIps.Length);
        foreach (var value in TrustedProxyIps)
        {
            if (!IpAddressNormalizer.TryNormalize(value, out var canonical) || !IPAddress.TryParse(canonical, out var address))
            {
                proxies = [];
                return false;
            }

            canonicalProxies.Add(address);
        }

        proxies = canonicalProxies.Distinct().ToArray();
        return !Enabled || proxies.Length > 0;
    }

    public void ConfigureForwardedHeaders(ForwardedHeadersOptions options)
    {
        options.ForwardedHeaders = Enabled
            ? ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            : ForwardedHeaders.None;
        options.ForwardLimit = ForwardLimit;
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        if (!TryGetCanonicalProxies(out var proxies))
        {
            throw new InvalidOperationException("TrustedProxies:TrustedProxyIps must contain valid exact IP addresses.");
        }

        foreach (var proxy in proxies)
        {
            options.KnownProxies.Add(proxy);
        }
    }
}
