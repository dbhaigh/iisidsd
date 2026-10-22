using iisidsd.Models;
using Microsoft.Data.Sqlite;

namespace iisidsd.Storage;

public interface IFindingStore
{
    void Upsert(SecurityEvent webEvent);
    void Upsert(SecurityEvent webEvent, SqliteConnection connection, SqliteTransaction transaction);
    void UpsertBatch(IReadOnlyList<SecurityEvent> webEvents, SqliteConnection connection, SqliteTransaction transaction)
    {
        foreach (var webEvent in webEvents)
        {
            Upsert(webEvent, connection, transaction);
        }
    }
    int BackfillFromExistingEvents();
    IpFinding? Get(string clientIp, string? domain = null);
    IReadOnlyList<IpFinding> List(int limit, string? domain = null);
    int Prune(DateTimeOffset olderThan);
}
