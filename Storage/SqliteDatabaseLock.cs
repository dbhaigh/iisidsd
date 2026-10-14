using System.Collections.Concurrent;

namespace iisidsd.Storage;

internal static class SqliteDatabaseLock
{
    private static readonly ConcurrentDictionary<string, Lock> WriteLocks = new(StringComparer.OrdinalIgnoreCase);

    public static Lock For(string databasePath)
        => WriteLocks.GetOrAdd(Path.GetFullPath(databasePath), static _ => new Lock());
}
