using System.Threading.Channels;
using iisidsd.Models;

namespace iisidsd.Storage;

public interface IEventStore
{
    IReadOnlyList<SecurityEvent> GetRecent(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false);
    void Publish(SecurityEvent webEvent);
    IReadOnlyList<SecurityEvent> PublishBatch(IReadOnlyList<SecurityEvent> webEvents)
    {
        foreach (var webEvent in webEvents)
        {
            Publish(webEvent);
        }

        return webEvents;
    }
    IngestionDiagnosticsSnapshot GetIngestionDiagnostics() => new(0, 0, 0, 0, 0, 0, 0, 0);
    void SaveIngestionDiagnosticsSidecar(IngestionDiagnosticsSnapshot snapshot) { }
    void SaveIngestionDiagnostics(IngestionDiagnosticsSnapshot snapshot) { }
    ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken);
}
