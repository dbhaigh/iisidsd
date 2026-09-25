using System.Threading.Channels;
using iisidsd.Models;

namespace iisidsd.Storage;

public interface IEventStore
{
    IReadOnlyList<SecurityEvent> GetRecent(int limit);
    void Publish(SecurityEvent webEvent);
    ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken);
}
