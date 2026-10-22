using System.ComponentModel.DataAnnotations;
using iisidsd.Networking;

namespace iisidsd.Configuration;

public sealed class DashboardOptions
{
    public const string SectionName = "Dashboard";

    public bool RemoteAccessEnabled { get; set; }

    [Required]
    [MinLength(1)]
    [MaxLength(64)]
    public string[] AllowedHosts { get; set; } = ["localhost", "127.0.0.1", "::1"];

    [Range(1, 256)]
    public int MaximumEventStreamSubscribers { get; set; } = 64;

    [Range(1, 120)]
    public int EventStreamHeartbeatSeconds { get; set; } = 15;

    [Range(1, 120)]
    public int EventStreamWriteTimeoutSeconds { get; set; } = 30;

    public bool TryGetCanonicalAllowedHosts(out string[] hosts)
    {
        if (AllowedHosts is null || AllowedHosts.Length is 0 or > 64)
        {
            hosts = [];
            return false;
        }

        var normalizedHosts = new List<string>(AllowedHosts.Length);
        foreach (var host in AllowedHosts)
        {
            if (IpAddressNormalizer.TryNormalize(host, out var canonicalIp))
            {
                normalizedHosts.Add(canonicalIp);
                continue;
            }

            if (!SiteIdentityNormalizer.TryNormalizeHost(host, out var canonicalHost) || canonicalHost.Contains(':'))
            {
                hosts = [];
                return false;
            }

            normalizedHosts.Add(canonicalHost);
        }

        hosts = normalizedHosts.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return hosts.Length > 0;
    }
}
