using iisidsd.Models;
using Microsoft.Data.Sqlite;

namespace iisidsd.Storage;

public interface INotificationQueue
{
    NotificationEnqueueResult Enqueue(SecurityEvent webEvent, SqliteConnection connection, SqliteTransaction transaction);
    IReadOnlyList<NotificationIncident> List(int limit = 250);
    IReadOnlyList<NotificationIncident> GetDue(DateTimeOffset now, int limit = 25);
    NotificationQueueStatus GetStatus();
    int PruneExpired(DateTimeOffset olderThanUtc);
    void RecordDelivered(string id, DateTimeOffset attemptedAtUtc);
    void RecordFailure(string id, DateTimeOffset attemptedAtUtc, string failureType);
    NotificationIncident? Acknowledge(string id, DateTimeOffset acknowledgedAtUtc, string acknowledgedBy);
}