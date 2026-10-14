namespace iisidsd.Storage;

public interface IEventRetentionStore
{
    int PruneExpiredEvents(DateTimeOffset olderThan);
}
