using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.Extensions.Options;

namespace iisidsd.Services;

public sealed class IpAggregationService(
    IEventStore eventStore,
    IBanCountService banCountService,
    IOptions<StorageOptions> storageOptions) : IIpAggregationService
{
    private readonly IEventStore _eventStore = eventStore;
    private readonly IBanCountService _banCountService = banCountService;
    private readonly int _eventRetentionLimit = Math.Max(1, storageOptions.Value.EventRetentionLimit);

    public IReadOnlyList<IpFinding> GetFindings(int limit, string? domain = null)
    {
        limit = Math.Max(1, limit);
        var eventGroups = _eventStore.GetRecent(_eventRetentionLimit, clientIp: null, domain: domain)
            .Where(static webEvent => !string.IsNullOrWhiteSpace(webEvent.ClientIp))
            .GroupBy(static webEvent => webEvent.ClientIp, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var banCounts = _banCountService.GetBanCounts(eventGroups.Select(static group => group.Key));

        return eventGroups
            .Select(group => BuildFinding(group, banCounts.TryGetValue(group.Key, out var banCount) ? banCount : null))
            .Where(static finding => finding.SuspiciousRequestCount > 0 || finding.HighestRiskScore > 0)
            .OrderByDescending(static finding => finding.HighestRiskScore)
            .ThenByDescending(static finding => finding.SuspiciousRequestCount)
            .ThenByDescending(static finding => finding.LastSeen)
            .Take(limit)
            .ToArray();
    }

    public IpFinding? GetFinding(string clientIp, string? domain = null)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
        {
            return null;
        }

        var events = _eventStore.GetRecent(_eventRetentionLimit, clientIp: clientIp, domain: domain);
        return events.Count == 0 ? null : BuildFinding(events, _banCountService.GetBanCount(clientIp));
    }

    private static IpFinding BuildFinding(IEnumerable<SecurityEvent> events, BanCountRecord? banCount)
    {
        var eventList = events.ToArray();
        var suspiciousEvents = eventList.Where(static webEvent => webEvent.IsSuspicious || webEvent.RiskScore >= 20).ToArray();
        var highestRiskEvent = eventList
            .OrderByDescending(static webEvent => webEvent.RiskScore)
            .ThenByDescending(static webEvent => webEvent.Timestamp)
            .First();

        return new IpFinding(
            eventList[0].ClientIp,
            eventList.Length,
            suspiciousEvents.Length,
            highestRiskEvent.RiskScore,
            highestRiskEvent.RiskSeverity,
            eventList.Min(static webEvent => webEvent.Timestamp),
            eventList.Max(static webEvent => webEvent.Timestamp),
            eventList.Select(static webEvent => webEvent.Domain)
                .Where(static domain => !string.IsNullOrWhiteSpace(domain))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            suspiciousEvents.Select(static webEvent => webEvent.DetectionReason)
                .Where(static reason => !string.IsNullOrWhiteSpace(reason))
                .Distinct(StringComparer.Ordinal)
                .Cast<string>()
                .ToArray(),
            suspiciousEvents.SelectMany(static webEvent => webEvent.RiskIndicators ?? [])
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray(),
            BanCount: banCount?.BanCount ?? 0);
    }
}
