using System.Threading.Channels;
using iisidsd.Models;

namespace iisidsd.Storage;

public interface IReplayableEventStore
{
    EventPage<StoredSecurityEvent> GetLatestPage(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false);
    EventPage<StoredSecurityEvent> GetPageAfter(long afterSequence, int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false);
    EventPage<StoredSecurityEvent> GetPageBefore(long beforeSequence, int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false);
    EventStreamSubscription SubscribeWithCursor(CancellationToken cancellationToken);
}

public sealed record EventStreamSubscription(ChannelReader<SecurityEvent> Reader, long InitialCursor);

public sealed class EventStreamSubscriberLimitException : Exception
{
    public EventStreamSubscriberLimitException()
        : base("The maximum number of concurrent event streams has been reached.")
    {
    }
}

public sealed class EventStreamSlowConsumerException()
    : Exception("The event stream consumer exceeded its bounded buffer; reconnect and resume from the last cursor.");