using System.Diagnostics;
using System.Threading.Channels;
using iisidsd.Configuration;
using iisidsd.Detection;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Storage;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace iisidsd.Etw;

public sealed class EtwIngestionPipeline
{
    private readonly IEventStore _eventStore;
    private readonly ISuspiciousActivityDetector _detector;
    private readonly IIisAutoDenyService _autoDenyService;
    private readonly IisObservability _observability;
    private readonly ILogger _logger;
    private readonly int _batchSize;
    private readonly Func<Exception, bool> _isTransientStoreFailure;
    private readonly Channel<EtwEventPayload> _queue;
    private long _lastMalformedWarning;
    private long _lastProcessingWarning;
    private long _lastRetryWarning;
    private long _lastReportedDropCount;

    public EtwIngestionPipeline(
        IEventStore eventStore,
        ISuspiciousActivityDetector detector,
        IIisAutoDenyService autoDenyService,
        IisObservability observability,
        IOptions<IisEtwOptions> options,
        ILogger logger,
        Func<Exception, bool>? isTransientStoreFailure = null)
    {
        _eventStore = eventStore;
        _detector = detector;
        _autoDenyService = autoDenyService;
        _observability = observability;
        _logger = logger;
        _batchSize = options.Value.ProcessingBatchSize;
        _isTransientStoreFailure = isTransientStoreFailure ?? IsTransientSqliteFailure;
        _observability.SetQueueCapacity(options.Value.IngestionBufferSize);
        _queue = Channel.CreateBounded<EtwEventPayload>(new BoundedChannelOptions(options.Value.IngestionBufferSize)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
    }

    public bool TryEnqueue(EtwEventPayload payload)
    {
        _observability.RecordEtwEventReceived();
        var reservedDepth = _observability.ReserveQueueItem();
        if (!_queue.Writer.TryWrite(payload))
        {
            _observability.RecordQueueItemDequeued();
            _observability.RecordEtwEventDropped();
            return false;
        }

        _observability.RecordQueueItemAccepted(reservedDepth);
        return true;
    }

    public void RecordMalformed(string failureCode)
    {
        _observability.RecordEtwEventReceived();
        _observability.RecordEtwEventMalformed();
    }

    public void Complete() => _queue.Writer.TryComplete();

    public async Task ProcessAsync()
    {
        try
        {
            _observability.InitializeIngestionDiagnostics(_eventStore.GetIngestionDiagnostics());
        }
        catch (Exception exception)
        {
            _logger.LogWarning(
                "Unable to restore ETW ingestion diagnostics. FailureType={FailureType}",
                exception.GetType().Name);
        }

        using var checkpointCancellation = new CancellationTokenSource();
        var checkpointTask = PersistDiagnosticsPeriodicallyAsync(checkpointCancellation.Token);
        try
        {
            while (await _queue.Reader.WaitToReadAsync())
            {
                var batch = new List<EtwEventPayload>(_batchSize);
                while (batch.Count < _batchSize && _queue.Reader.TryRead(out var next))
                {
                    batch.Add(next);
                    _observability.RecordQueueItemDequeued();
                }

                if (batch.Count > 0)
                {
                    await ProcessBatchAsync(batch);
                    ReportQueueLoss();
                }
            }
        }
        finally
        {
            checkpointCancellation.Cancel();
            try
            {
                await checkpointTask;
            }
            catch (OperationCanceledException)
            {
            }
        }

        ReportQueueLoss();
        await PersistIngestionDiagnosticsAsync();
    }

    private async Task ProcessBatchAsync(IReadOnlyList<EtwEventPayload> payloads)
    {
        var analyzedEvents = new List<(EtwEventPayload Payload, SecurityEvent Event)>(payloads.Count);
        foreach (var payload in payloads)
        {
            if (!EtwEventNormalizer.TryNormalize(payload, out var webEvent, out var failureCode))
            {
                _observability.RecordEtwEventMalformed();
                LogRateLimited(ref _lastMalformedWarning, LogLevel.Warning,
                    "Rejecting malformed IIS ETW payload. EventId={EventId} FailureCode={FailureCode}",
                    payload.Id,
                    failureCode);
                continue;
            }

            try
            {
                var assessment = _detector.AnalyzeDetailed(webEvent!);
                var analyzedEvent = assessment.Event ?? (webEvent! with { DetectionEvidence = assessment.Evidence });
                _observability.RecordDetectionAnalyzed(analyzedEvent);
                analyzedEvents.Add((payload, analyzedEvent));
            }
            catch (Exception exception)
            {
                _observability.RecordEventProcessingFailure();
                LogRateLimited(ref _lastProcessingWarning, LogLevel.Error,
                    "IIS ETW detection failed. EventId={EventId} FailureType={FailureType}",
                    payload.Id,
                    exception.GetType().Name);
            }
        }

        if (analyzedEvents.Count == 0)
        {
            await PersistIngestionDiagnosticsAsync();
            return;
        }

        var events = analyzedEvents.Select(static item => item.Event).ToArray();
        var retryDelay = TimeSpan.FromMilliseconds(100);
        IReadOnlyList<SecurityEvent> persistedEvents;
        while (true)
        {
            try
            {
                persistedEvents = _eventStore.PublishBatch(events);
                break;
            }
            catch (Exception exception) when (_isTransientStoreFailure(exception))
            {
                _observability.RecordEventProcessingRetry();
                _observability.RecordRecoveryAttempt("sqlite", exception.GetType().Name);
                LogRateLimited(ref _lastRetryWarning, LogLevel.Warning,
                    "SQLite is temporarily unavailable; retaining {BatchSize} accepted event(s) for retry. FailureType={FailureType}",
                    events.Length,
                    exception.GetType().Name);
                await Task.Delay(retryDelay);
                retryDelay = TimeSpan.FromMilliseconds(Math.Min(retryDelay.TotalMilliseconds * 2, 5_000));
            }
            catch (Exception exception)
            {
                _observability.RecordEventProcessingFailure(events.Length);
                _logger.LogError(
                    "Unable to persist IIS ETW batch. BatchSize={BatchSize} FirstEventId={FirstEventId} FailureType={FailureType}",
                    events.Length,
                    events[0].Id,
                    exception.GetType().Name);
                return;
            }
        }

        foreach (var (payload, webEvent) in analyzedEvents)
        {
            _observability.RecordEventProcessed(webEvent, Stopwatch.GetElapsedTime(payload.ReceivedTimestamp));
        }

        foreach (var webEvent in persistedEvents)
        {
            if (!webEvent.IsSuspicious)
            {
                continue;
            }

            try
            {
                _autoDenyService.Apply(webEvent);
            }
            catch (Exception exception)
            {
                _observability.RecordAutoDenyFailure();
                LogRateLimited(ref _lastProcessingWarning, LogLevel.Error,
                    "Automatic IIS action failed after event persistence. EventId={EventId} FailureType={FailureType}",
                    webEvent.Id,
                    exception.GetType().Name);
            }
        }

        await PersistIngestionDiagnosticsAsync();
    }

    private async Task PersistIngestionDiagnosticsAsync()
    {
        var retryDelay = TimeSpan.FromMilliseconds(100);
        while (true)
        {
            try
            {
                _eventStore.SaveIngestionDiagnostics(_observability.GetIngestionDiagnosticsSnapshot());
                return;
            }
            catch (Exception exception) when (_isTransientStoreFailure(exception))
            {
                _observability.RecordEventProcessingRetry();
                _observability.RecordRecoveryAttempt("sqlite", exception.GetType().Name);
                LogRateLimited(ref _lastRetryWarning, LogLevel.Warning,
                    "SQLite is temporarily unavailable while saving ETW diagnostics. FailureType={FailureType}",
                    exception.GetType().Name);
                await Task.Delay(retryDelay);
                retryDelay = TimeSpan.FromMilliseconds(Math.Min(retryDelay.TotalMilliseconds * 2, 5_000));
            }
            catch (Exception exception)
            {
                _logger.LogError(
                    "Unable to persist ETW ingestion diagnostics. FailureType={FailureType}",
                    exception.GetType().Name);
                return;
            }
        }
    }

    private async Task PersistDiagnosticsPeriodicallyAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            try
            {
                _eventStore.SaveIngestionDiagnosticsSidecar(_observability.GetIngestionDiagnosticsSnapshot());
            }
            catch (Exception exception)
            {
                _logger.LogWarning(
                    "Unable to checkpoint ETW ingestion diagnostics. FailureType={FailureType}",
                    exception.GetType().Name);
            }

            ReportQueueLoss();
        }
    }

    private void ReportQueueLoss()
    {
        var droppedCount = _observability.EtwEventsDropped;
        var previousCount = Interlocked.Read(ref _lastReportedDropCount);
        if (droppedCount == 0 || (previousCount > 0 && droppedCount - previousCount < 100))
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _lastReportedDropCount, droppedCount, previousCount) == previousCount)
        {
            _logger.LogWarning(
                "ETW queue rejected events. DroppedCount={DroppedCount} AcceptedCount={AcceptedCount} QueueDepth={QueueDepth}",
                droppedCount,
                _observability.EtwEventsAccepted,
                _observability.QueueDepth);
        }
    }

    private void LogRateLimited(ref long lastTimestamp, LogLevel level, string message, params object?[] args)
    {
        var now = Stopwatch.GetTimestamp();
        var previous = Interlocked.Read(ref lastTimestamp);
        if (previous != 0 && Stopwatch.GetElapsedTime(previous, now) < TimeSpan.FromSeconds(10))
        {
            return;
        }

        if (Interlocked.CompareExchange(ref lastTimestamp, now, previous) == previous)
        {
            _logger.Log(level, message, args);
        }
    }

    private static bool IsTransientSqliteFailure(Exception exception)
        => exception is SqliteException sqliteException && sqliteException.SqliteErrorCode is 5 or 6 or 8 or 10 or 13 or 14;
}