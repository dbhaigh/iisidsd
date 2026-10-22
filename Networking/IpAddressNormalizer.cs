using System.Net;
using System.Net.Sockets;

namespace iisidsd.Networking;

public static class IpAddressNormalizer
{
    public static bool TryNormalize(string? value, out string canonicalAddress)
    {
        canonicalAddress = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var input = value.Trim();
        if (input.Contains(':'))
        {
            if (!IPAddress.TryParse(input, out var ipv6Address) || ipv6Address.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return false;
            }

            canonicalAddress = Normalize(ipv6Address).ToString();
            return true;
        }

        var octets = input.Split('.');
        if (octets.Length != 4)
        {
            return false;
        }

        var addressBytes = new byte[4];
        for (var index = 0; index < octets.Length; index++)
        {
            if (octets[index].Length is 0 or > 3 ||
                octets[index].Length > 1 && octets[index][0] == '0' ||
                !byte.TryParse(octets[index], out addressBytes[index]))
            {
                return false;
            }
        }

        var address = new IPAddress(addressBytes);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        canonicalAddress = address.ToString();
        return true;
    }

    public static IPAddress Normalize(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
