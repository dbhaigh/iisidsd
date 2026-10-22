namespace iisidsd.Storage;

public sealed record IngestionDiagnosticsSnapshot(
    long EventsReceived,
    long EventsAccepted,
    long EventsDropped,
    long EventsMalformed,
    long EventsProcessed,
    long ProcessingFailures,
    long AutoDenyFailures,
    long ProcessingRetries);