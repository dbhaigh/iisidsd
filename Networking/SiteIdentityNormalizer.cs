using System.Globalization;
using System.Net;
using iisidsd.Models;

namespace iisidsd.Networking;

internal readonly record struct SiteIdentityKey(string Server, string Host, string SiteName);

internal static class SiteIdentityNormalizer
{
    private const int MaximumHostLength = 253;
    private const int MaximumSiteNameLength = 128;

    public static bool TryCreate(SecurityEvent webEvent, out SiteIdentityKey identity)
    {
        identity = default;
        if (!TryNormalizeServer(webEvent.Server, out var server))
        {
            return false;
        }

        var siteName = GetSiteName(webEvent.Properties);
        if (!TryNormalizeOpaqueSiteName(siteName, out var normalizedSiteName))
        {
            return false;
        }

        if (!TryNormalizeHost(webEvent.Domain, out var host))
        {
            if (normalizedSiteName.Length == 0)
            {
                return false;
            }

            identity = new SiteIdentityKey(server, $"site:{normalizedSiteName}", string.Empty);
            return true;
        }

        identity = new SiteIdentityKey(server, host, normalizedSiteName);
        return true;
    }

    public static bool TryNormalizeHost(string? value, out string normalizedHost)
    {
        normalizedHost = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var candidate = value.Trim();
        if (candidate.Length > MaximumHostLength + 16 || candidate.Any(char.IsControl))
        {
            return false;
        }

        if (IpAddressNormalizer.TryNormalize(candidate, out var canonicalAddress))
        {
            normalizedHost = canonicalAddress;
            return true;
        }

        if (!TrySplitHostAndPort(candidate, out var host, out var port))
        {
            return false;
        }

        if (IpAddressNormalizer.TryNormalize(host, out canonicalAddress) && IPAddress.TryParse(canonicalAddress, out var address))
        {
            var addressText = address.ToString();
            normalizedHost = port.HasValue && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? $"[{addressText}]:{port.Value.ToString(CultureInfo.InvariantCulture)}"
                : port.HasValue ? $"{addressText}:{port.Value.ToString(CultureInfo.InvariantCulture)}" : addressText;
            return true;
        }

        if (!TryNormalizeDnsName(host, out var normalizedDnsName))
        {
            return false;
        }

        normalizedHost = port.HasValue
            ? $"{normalizedDnsName}:{port.Value.ToString(CultureInfo.InvariantCulture)}"
            : normalizedDnsName;
        return true;
    }

    private static bool TryNormalizeServer(string? value, out string normalizedServer)
    {
        normalizedServer = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var candidate = value.Trim();
        if (candidate.Length > 255 || candidate.Any(char.IsControl) || candidate.IndexOfAny(['/', '\\', '?', '#']) >= 0)
        {
            return false;
        }

        normalizedServer = candidate.TrimEnd('.').ToLowerInvariant();
        return normalizedServer.Length > 0;
    }

    internal static string GetSiteName(IReadOnlyDictionary<string, string>? properties)
    {
        if (properties is null)
        {
            return string.Empty;
        }

        foreach (var name in new[] { "ssitename", "s-sitename", "SiteName" })
        {
            if (properties.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static bool TryNormalizeOpaqueSiteName(string? value, out string normalizedSiteName)
    {
        normalizedSiteName = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        var candidate = value.Trim();
        if (candidate.Length > MaximumSiteNameLength || candidate.Any(char.IsControl) ||
            candidate.IndexOfAny(['/', '\\', '?', '#', '@']) >= 0)
        {
            return false;
        }

        normalizedSiteName = candidate.ToLowerInvariant();
        return true;
    }

    private static bool TrySplitHostAndPort(string value, out string host, out int? port)
    {
        host = value;
        port = null;
        if (value[0] == '[')
        {
            var closingBracket = value.IndexOf(']');
            if (closingBracket <= 1 || !IPAddress.TryParse(value[1..closingBracket], out var ipv6Address) ||
                ipv6Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return false;
            }

            var suffix = value[(closingBracket + 1)..];
            int? parsedPort = null;
            if (suffix.Length > 0 && (!suffix.StartsWith(':') || !TryParsePort(suffix[1..], out _)))
            {
                return false;
            }

            if (suffix.Length > 0)
            {
                _ = TryParsePort(suffix[1..], out var portValue);
                parsedPort = portValue;
            }

            host = ipv6Address.ToString();
            port = parsedPort;
            return true;
        }

        var separator = value.LastIndexOf(':');
        if (separator >= 0 && value.IndexOf(':') == separator)
        {
            if (!TryParsePort(value[(separator + 1)..], out var parsedPort))
            {
                return false;
            }

            host = value[..separator];
            port = parsedPort;
        }

        return host.Length > 0;
    }

    private static bool TryParsePort(string value, out int port)
        => int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is > 0 and <= 65535;

    private static bool TryNormalizeDnsName(string value, out string normalizedDnsName)
    {
        normalizedDnsName = string.Empty;
        var host = value.TrimEnd('.');
        if (host.Length == 0 || host.All(static character => char.IsAsciiDigit(character) || character == '.'))
        {
            return false;
        }

        try
        {
            host = new IdnMapping().GetAscii(host).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return false;
        }

        if (host.Length > MaximumHostLength || host.Split('.').Any(static label =>
                label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-' ||
                label.Any(static character => !char.IsAsciiLetterOrDigit(character) && character != '-')))
        {
            return false;
        }

        normalizedDnsName = host;
        return true;
    }

}
