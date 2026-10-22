namespace iisidsd.Models;

public sealed record EventEnvelope<T>(
    string EventId,
    DateTimeOffset Timestamp,
    string Type,
    int PayloadVersion,
    long Cursor,
    T Payload);

public sealed record EventPage<T>(
    IReadOnlyList<T> Items,
    long? FirstCursor,
    long? LastCursor,
    long? LatestCursor,
    bool HasMore,
    bool GapDetected,
    long? OldestAvailableCursor,
    long? PrunedThroughCursor = null);