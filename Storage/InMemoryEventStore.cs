using System.Collections.Concurrent;
using System.Threading.Channels;
using iisidsd.Configuration;
using iisidsd.Models;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class InMemoryEventStore(IOptions<IisEtwOptions> etwOptions, IOptions<StorageOptions> storageOptions) : IEventStore, IEventRetentionStore
{
    private readonly int _retentionLimit = Math.Max(1, storageOptions.Value.EventRetentionLimit);
    private readonly int _retentionDays = storageOptions.Value.EventRetentionDays;
    private readonly int _subscriptionBufferSize = Math.Max(1, etwOptions.Value.SubscriptionBufferSize);
    private readonly LinkedList<SecurityEvent> _events = [];
    private readonly Lock _sync = new();
    private readonly ConcurrentDictionary<Guid, Channel<SecurityEvent>> _subscribers = [];

    public IReadOnlyList<SecurityEvent> GetRecent(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
    {
        limit = Math.Clamp(limit, 1, _retentionLimit);
        lock (_sync)
        {
            return _events
                .Reverse()
                .Where(webEvent => clientIp is null || string.Equals(webEvent.ClientIp, clientIp, StringComparison.OrdinalIgnoreCase))
                .Where(webEvent => domain is null || string.Equals(webEvent.Domain, domain, StringComparison.OrdinalIgnoreCase))
                .Where(webEvent => !suspiciousOnly || webEvent.IsSuspicious)
                .Take(limit)
                .ToArray();
        }
    }

    public void Publish(SecurityEvent webEvent)
    {
        lock (_sync)
        {
            _events.AddLast(webEvent);
            PruneExpiredEventsCore(DateTimeOffset.UtcNow.AddDays(-_retentionDays));
            while (_events.Count > _retentionLimit)
            {
                _events.RemoveFirst();
            }
        }

        foreach (var subscriber in _subscribers.Values)
        {
            subscriber.Writer.TryWrite(webEvent);
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
    {
        var channel = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(_subscriptionBufferSize)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false
        });
        var id = Guid.NewGuid();
        _subscribers[id] = channel;
        cancellationToken.Register(() =>
        {
            if (_subscribers.TryRemove(id, out var removed))
            {
                removed.Writer.TryComplete();
            }
        });
        return channel.Reader;
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
                _events.Remove(node);
                prunedCount++;
            }

            node = next;
        }

        return prunedCount;
    }
}
