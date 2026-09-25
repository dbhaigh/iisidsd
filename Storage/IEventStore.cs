using System.Threading.Channels;
using iisidsd.Models;

namespace iisidsd.Storage;

public interface IEventStore
{
    IReadOnlyList<SecurityEvent> GetRecent(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false);
    void Publish(SecurityEvent webEvent);
    ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken);
}
