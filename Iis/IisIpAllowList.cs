using System.Net;
using iisidsd.Configuration;
using Microsoft.Extensions.Options;

namespace iisidsd.Iis;

public sealed class IisIpAllowList : IIpAllowList
{
    private readonly AddressRange[] _ranges;

    public IisIpAllowList(IOptions<IisAdminOptions> options)
    {
        _ranges = options.Value.AllowList.Select(ParseRange).ToArray();
    }

    public bool Contains(string? clientIp)
    {
        if (!IPAddress.TryParse(clientIp, out var address))
        {
            return false;
        }

        address = NormalizeAddress(address);
        return _ranges.Any(range => range.Contains(address));
    }

    public static bool IsValidAllowList(IEnumerable<string>? allowList)
    {
        if (allowList is null)
        {
            return false;
        }

        try
        {
            foreach (var configuredRange in allowList)
            {
                _ = ParseRange(configuredRange);
            }

            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static AddressRange ParseRange(string configuredRange)
    {
        if (string.IsNullOrWhiteSpace(configuredRange))
        {
            throw new ArgumentException("Allow-list entries cannot be empty.");
        }

        var value = configuredRange.Trim();
        var separator = value.LastIndexOf('/');
        var hasPrefix = separator >= 0;
        var addressText = hasPrefix ? value[..separator] : value;
        if (!IPAddress.TryParse(addressText, out var address))
        {
            throw new ArgumentException($"Invalid IP address or CIDR in IisAdmin:AllowList: '{configuredRange}'.");
        }

        var prefixLength = address.GetAddressBytes().Length * 8;
        if (hasPrefix)
        {
            if (!int.TryParse(value[(separator + 1)..], out prefixLength) ||
                prefixLength < 0 ||
                prefixLength > address.GetAddressBytes().Length * 8)
            {
                throw new ArgumentException($"Invalid CIDR prefix in IisAdmin:AllowList: '{configuredRange}'.");
            }
        }

        if (address.IsIPv4MappedToIPv6 && (!hasPrefix || prefixLength >= 96))
        {
            address = address.MapToIPv4();
            if (hasPrefix)
            {
                prefixLength -= 96;
            }
        }

        return new AddressRange(address.GetAddressBytes(), prefixLength);
    }

    private static IPAddress NormalizeAddress(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private sealed class AddressRange(byte[] addressBytes, int prefixLength)
    {
        public bool Contains(IPAddress address)
        {
            var candidateBytes = address.GetAddressBytes();
            if (candidateBytes.Length != addressBytes.Length)
            {
                return false;
            }

            var fullBytes = prefixLength / 8;
            for (var index = 0; index < fullBytes; index++)
            {
                if (candidateBytes[index] != addressBytes[index])
                {
                    return false;
                }
            }

            var remainingBits = prefixLength % 8;
            if (remainingBits == 0)
            {
                return true;
            }

            var mask = (byte)(0xff << (8 - remainingBits));
            return (candidateBytes[fullBytes] & mask) == (addressBytes[fullBytes] & mask);
        }
    }
}
