using System.Collections.Concurrent;
using System.Threading.Channels;
using iisidsd.Configuration;
using iisidsd.Models;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class InMemoryEventStore(
    IOptions<IisEtwOptions> etwOptions,
    IOptions<StorageOptions> storageOptions,
    IOptions<DashboardOptions>? dashboardOptions = null) : IEventStore, IEventRetentionStore, IReplayableEventStore
{
    private const int MaximumQueryLimit = 10_000;
    private readonly int _retentionLimit = Math.Max(1, storageOptions.Value.EventRetentionLimit);
    private readonly int _retentionDays = storageOptions.Value.EventRetentionDays;
    private readonly int _subscriptionBufferSize = Math.Clamp(etwOptions.Value.SubscriptionBufferSize, 1, 4_096);
    private readonly int _maximumStreamSubscribers = Math.Clamp(dashboardOptions?.Value.MaximumEventStreamSubscribers ?? 64, 1, 256);
    private readonly LinkedList<StoredSecurityEvent> _events = [];
    private readonly Lock _sync = new();
    private readonly ConcurrentDictionary<Guid, Channel<SecurityEvent>> _subscribers = [];
    private readonly object _subscriberSync = new();
    private long _nextSequenceId = 1;
    private long _prunedThroughSequence;

    public IReadOnlyList<SecurityEvent> GetRecent(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
    {
        limit = Math.Clamp(limit, 1, Math.Min(_retentionLimit, MaximumQueryLimit));
        lock (_sync)
        {
            return _events
                .Reverse()
                .Where(webEvent => clientIp is null || string.Equals(webEvent.ClientIp, clientIp, StringComparison.OrdinalIgnoreCase))
                .Where(webEvent => domain is null || string.Equals(webEvent.Domain, domain, StringComparison.OrdinalIgnoreCase))
                .Where(webEvent => !suspiciousOnly || webEvent.IsSuspicious)
                .Take(limit)
                .Select(webEvent => webEvent.ToSecurityEvent())
                .ToArray();
        }
    }

    public EventPage<StoredSecurityEvent> GetLatestPage(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
    {
        limit = Math.Clamp(limit, 1, MaximumQueryLimit);
        lock (_sync)
        {
            var matchingEvents = FilterEvents(clientIp, domain, suspiciousOnly).ToArray();
            var items = matchingEvents.TakeLast(limit).ToArray();
            return new EventPage<StoredSecurityEvent>(
                items,
                items.Length == 0 ? null : items[0].SequenceId,
                items.Length == 0 ? null : items[^1].SequenceId,
                _nextSequenceId - 1,
                matchingEvents.Length > limit,
                false,
                _events.First?.Value.SequenceId,
                _prunedThroughSequence);
        }
    }

    public EventPage<StoredSecurityEvent> GetPageAfter(
        long afterSequence,
        int limit,
        string? clientIp = null,
        string? domain = null,
        bool suspiciousOnly = false)
    {
        limit = Math.Clamp(limit, 1, MaximumQueryLimit);
        lock (_sync)
        {
            var items = FilterEvents(clientIp, domain, suspiciousOnly)
                .Where(webEvent => webEvent.SequenceId > afterSequence)
                .Take(limit + 1)
                .ToArray();
            var hasMore = items.Length > limit;
            if (hasMore) items = items[..limit];
            return new EventPage<StoredSecurityEvent>(
                items,
                items.Length == 0 ? null : items[0].SequenceId,
                items.Length == 0 ? null : items[^1].SequenceId,
                _nextSequenceId - 1,
                hasMore,
                afterSequence < _prunedThroughSequence,
                _events.First?.Value.SequenceId,
                _prunedThroughSequence);
        }
    }

    public EventPage<StoredSecurityEvent> GetPageBefore(
        long beforeSequence,
        int limit,
        string? clientIp = null,
        string? domain = null,
        bool suspiciousOnly = false)
    {
        limit = Math.Clamp(limit, 1, MaximumQueryLimit);
        lock (_sync)
        {
            var items = FilterEvents(clientIp, domain, suspiciousOnly)
                .Where(webEvent => webEvent.SequenceId < beforeSequence)
                .TakeLast(limit + 1)
                .ToArray();
            var hasMore = items.Length > limit;
            if (hasMore) items = items[1..];
            return new EventPage<StoredSecurityEvent>(
                items,
                items.Length == 0 ? null : items[0].SequenceId,
                items.Length == 0 ? null : items[^1].SequenceId,
                _nextSequenceId - 1,
                hasMore,
                false,
                _events.First?.Value.SequenceId,
                _prunedThroughSequence);
        }
    }

    public void Publish(SecurityEvent webEvent)
    {
        lock (_sync)
        {
            var storedEvent = new StoredSecurityEvent(
                _nextSequenceId++,
                webEvent.Id,
                webEvent.Timestamp,
                webEvent.Server,
                webEvent.Domain,
                webEvent.Method,
                webEvent.Path,
                webEvent.ClientIp,
                webEvent.StatusCode,
                webEvent.UserAgent,
                webEvent.Properties,
                webEvent.IsSuspicious,
                webEvent.DetectionReason,
                webEvent.RiskScore,
                webEvent.RiskSeverity,
                webEvent.RiskIndicators ?? []);
            _events.AddLast(storedEvent);
            PruneExpiredEventsCore(DateTimeOffset.UtcNow.AddDays(-_retentionDays));
            while (_events.Count > _retentionLimit)
            {
                _prunedThroughSequence = Math.Max(_prunedThroughSequence, _events.First!.Value.SequenceId);
                _events.RemoveFirst();
            }

            var sequencedEvent = storedEvent.ToSecurityEvent();
            foreach (var subscriber in _subscribers)
            {
                if (!subscriber.Value.Writer.TryWrite(sequencedEvent))
                {
                    RemoveSubscriber(subscriber.Key, new EventStreamSlowConsumerException());
                }
            }
        }
    }

    public int PruneExpiredEvents(DateTimeOffset olderThan)
    {
        lock (_sync)
        {
            return PruneExpiredEventsCore(olderThan);
        }
    }

    public ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken)
        => SubscribeWithCursor(cancellationToken).Reader;

    public EventStreamSubscription SubscribeWithCursor(CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            var reader = SubscribeCore(cancellationToken);
            return new EventStreamSubscription(reader, _nextSequenceId - 1);
        }
    }

    private ChannelReader<SecurityEvent> SubscribeCore(CancellationToken cancellationToken)
    {
        var channel = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(_subscriptionBufferSize)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
        var id = Guid.NewGuid();
        lock (_subscriberSync)
        {
            if (_subscribers.Count >= _maximumStreamSubscribers)
            {
                throw new EventStreamSubscriberLimitException();
            }

            _subscribers[id] = channel;
        }

        cancellationToken.Register(() => RemoveSubscriber(id));
        return channel.Reader;
    }

    private IEnumerable<StoredSecurityEvent> FilterEvents(string? clientIp, string? domain, bool suspiciousOnly)
        => _events
            .Where(webEvent => clientIp is null || string.Equals(webEvent.ClientIp, clientIp, StringComparison.OrdinalIgnoreCase))
            .Where(webEvent => domain is null || string.Equals(webEvent.Domain, domain, StringComparison.OrdinalIgnoreCase))
            .Where(webEvent => !suspiciousOnly || webEvent.IsSuspicious);

    private void RemoveSubscriber(Guid id, Exception? completionError = null)
    {
        lock (_subscriberSync)
        {
            if (_subscribers.TryRemove(id, out var channel))
            {
                channel.Writer.TryComplete(completionError);
            }
        }
    }

    private int PruneExpiredEventsCore(DateTimeOffset olderThan)
    {
        var prunedCount = 0;
        var node = _events.First;
        while (node is not null)
        {
            var next = node.Next;
            if (node.Value.Timestamp < olderThan)
            {
                _prunedThroughSequence = Math.Max(_prunedThroughSequence, node.Value.SequenceId);
                _events.Remove(node);
                prunedCount++;
            }

            node = next;
        }

        return prunedCount;
    }
}
