using System.Collections.Concurrent;
using System.Threading.Channels;
using iisidsd.Configuration;
using iisidsd.Models;
using Microsoft.Extensions.Options;

namespace iisidsd.Storage;

public sealed class InMemoryEventStore(IOptions<IisEtwOptions> options) : IEventStore
{
    private readonly IisEtwOptions _options = options.Value;
    private readonly LinkedList<SecurityEvent> _events = [];
    private readonly Lock _sync = new();
    private readonly ConcurrentDictionary<Guid, Channel<SecurityEvent>> _subscribers = [];

    public IReadOnlyList<SecurityEvent> GetRecent(int limit)
    {
        limit = Math.Clamp(limit, 1, _options.RetentionLimit);
        lock (_sync)
        {
            return _events.Reverse().Take(limit).ToArray();
        }
    }

    public void Publish(SecurityEvent webEvent)
    {
        lock (_sync)
        {
            _events.AddLast(webEvent);
            while (_events.Count > _options.RetentionLimit)
            {
                _events.RemoveFirst();
            }
        }

        foreach (var subscriber in _subscribers.Values)
        {
            subscriber.Writer.TryWrite(webEvent);
        }
    }

    public ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken)
    {
        var channel = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(_options.SubscriptionBufferSize)
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
}
