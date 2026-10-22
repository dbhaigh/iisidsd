using System.Globalization;
using iisidsd.Models;
using iisidsd.Networking;

namespace iisidsd.Etw;

public sealed record EtwEventPayload(
    DateTimeOffset Timestamp,
    string Id,
    long ReceivedTimestamp,
    IReadOnlyDictionary<string, string> Properties);

public static class EtwEventNormalizer
{
    private static readonly string[] ServerNamePropertyNames = ["scomputername", "ServerName", "ComputerName", "MachineName"];
    private static readonly string[] DomainPropertyNames = ["cshost", "Host", "HostName", "ssitename", "s-sitename", "SiteName"];
    private static readonly string[] MethodPropertyNames = ["csmethod", "Method", "HttpMethod", "Verb"];
    private static readonly string[] PathPropertyNames = ["csuristem", "UriStem", "Path", "RequestPath", "Url"];
    private static readonly string[] ClientIpPropertyNames = ["cip", "ClientIP", "ClientIp", "RemoteAddress", "RemoteIp"];
    private static readonly string[] StatusCodePropertyNames = ["scstatus", "HttpStatus", "StatusCode", "Status"];
    private static readonly string[] UserAgentPropertyNames = ["csUserAgent", "UserAgent", "User-Agent"];

    public static bool TryNormalize(EtwEventPayload payload, out SecurityEvent? webEvent, out string failureCode)
    {
        webEvent = null;
        failureCode = "invalid-payload";
        try
        {
            if (payload.Properties is null || payload.Properties.Count is 0 or > 256)
            {
                failureCode = "invalid-property-count";
                return false;
            }

            var totalCharacters = 0;
            foreach (var property in payload.Properties)
            {
                if (string.IsNullOrWhiteSpace(property.Key) || property.Key.Length > 128 || property.Value is null || property.Value.Length > 16_384)
                {
                    failureCode = "invalid-property-shape";
                    return false;
                }

                totalCharacters += property.Key.Length + property.Value.Length;
                if (totalCharacters > 65_536)
                {
                    failureCode = "payload-too-large";
                    return false;
                }
            }

            var rawPath = Get(payload.Properties, PathPropertyNames);
            var rawStatus = Get(payload.Properties, StatusCodePropertyNames);
            var rawClientIp = Get(payload.Properties, ClientIpPropertyNames);
            var rawMethod = Get(payload.Properties, MethodPropertyNames);
            if (rawPath is null && rawStatus is null && rawClientIp is null && rawMethod is null)
            {
                failureCode = "unrecognized-event-shape";
                return false;
            }

            var server = Get(payload.Properties, ServerNamePropertyNames) ?? Environment.MachineName;
            var rawDomain = Get(payload.Properties, DomainPropertyNames) ?? string.Empty;
            var method = rawMethod ?? string.Empty;
            var path = rawPath ?? string.Empty;
            var userAgent = Get(payload.Properties, UserAgentPropertyNames) ?? string.Empty;
            if (server.Length > 255 || rawDomain.Length > 512 || method.Length > 32 || path.Length > 8_192 || userAgent.Length > 4_096 ||
                server.Any(char.IsControl) || rawDomain.Any(char.IsControl) || method.Any(char.IsControl) || path.Any(char.IsControl))
            {
                failureCode = "invalid-field-length-or-control-character";
                return false;
            }

            var domain = SiteIdentityNormalizer.TryNormalizeHost(rawDomain, out var normalizedDomain)
                ? normalizedDomain
                : rawDomain.Trim();
            var clientIp = IpAddressNormalizer.TryNormalize(rawClientIp, out var normalizedIp)
                ? normalizedIp
                : string.Empty;
            var statusCode = int.TryParse(rawStatus, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedStatus)
                ? parsedStatus
                : 0;

            webEvent = new SecurityEvent(
                payload.Timestamp,
                server,
                domain,
                method,
                path,
                clientIp,
                statusCode,
                userAgent,
                payload.Properties)
            {
                Id = payload.Id
            };
            failureCode = string.Empty;
            return true;
        }
        catch (Exception)
        {
            failureCode = "normalization-failed";
            return false;
        }
    }

    private static string? Get(IReadOnlyDictionary<string, string> properties, string[] names)
    {
        foreach (var name in names)
        {
            if (properties.TryGetValue(name, out var value))
            {
                return value;
            }
        }

        return null;
    }
}