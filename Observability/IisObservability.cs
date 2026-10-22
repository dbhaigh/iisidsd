using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text;
using iisidsd.Models;
using iisidsd.Storage;

namespace iisidsd.Observability;

public sealed class IisObservability : IDisposable
{
    public const string MeterName = "iisidsd";

    private static readonly double[] DurationBucketBounds =
    [
        0.001,
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1,
        2.5,
        5,
        10
    ];

    private static readonly double[] PipelineLatencyBucketBounds =
    [
        0.001,
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1,
        2.5,
        5,
        10,
        30,
        60
    ];

    private readonly Meter _meter = new(MeterName, "1.0.0");
    private readonly Counter<long> _etwEventsReceived;
    private readonly Counter<long> _etwEventsAccepted;
    private readonly Counter<long> _etwEventsDropped;
    private readonly Counter<long> _etwEventsMalformed;
    private readonly Counter<long> _eventsProcessed;
    private readonly Counter<long> _eventProcessingFailures;
    private readonly Counter<long> _eventProcessingRetries;
    private readonly Counter<long> _sqliteWriteFailures;
    private readonly Counter<long> _sqliteBusyFailures;
    private readonly Counter<long> _sqliteCorruptionFailures;
    private readonly Counter<long> _sqliteDiskFullFailures;
    private readonly Counter<long> _autoDenyFailures;
    private readonly Counter<long> _suspiciousEvents;
    private readonly Counter<long> _autoDenies;
    private readonly Counter<long> _detectionHistoryPruned;
    private readonly Counter<long> _detectionHistoryCapacityRejections;
    private readonly Counter<long> _detectionPathCapacityRejections;
    private readonly Counter<long> _outOfOrderDetectionEvents;
    private readonly Counter<long> _detectionClockResets;
    private readonly Counter<long> _extensionCacheCapacityRejections;
    private readonly Histogram<double> _sqliteWriteDuration;
    private readonly Histogram<double> _eventPipelineLatency;
    private readonly long[] _durationBucketCounts = new long[DurationBucketBounds.Length];
    private readonly long[] _pipelineLatencyBucketCounts = new long[PipelineLatencyBucketBounds.Length];
    private long _etwEventsReceivedCount;
    private long _etwEventsAcceptedCount;
    private long _etwEventsDroppedCount;
    private long _etwEventsMalformedCount;
    private long _eventsProcessedCount;
    private long _eventProcessingFailureCount;
    private long _eventProcessingRetryCount;
    private long _sqliteWriteFailureCount;
    private long _sqliteBusyFailureCount;
    private long _sqliteCorruptionFailureCount;
    private long _sqliteDiskFullFailureCount;
    private long _autoDenyFailureCount;
    private long _suspiciousEventsCount;
    private long _autoDeniesCount;
    private long _detectionHistoryPrunedCount;
    private long _detectionHistoryCapacityRejectionCount;
    private long _detectionPathCapacityRejectionCount;
    private long _outOfOrderDetectionEventCount;
    private long _detectionClockResetCount;
    private long _extensionCacheCapacityRejectionCount;
    private long _trackedDetectionHistories;
    private long _trackedHistoryBuckets;
    private long _trackedExtensionSites;
    private long _trackedPathTokens;
    private long _queueDepth;
    private long _queueHighWaterMark;
    private long _lastEventTimestampTicks;
    private long _sqliteWriteDurationCount;
    private long _sqliteWriteDurationTicks;
    private long _pipelineLatencyCount;
    private long _pipelineLatencyTicks;

    public IisObservability()
    {
        _etwEventsReceived = _meter.CreateCounter<long>("etw_events_received", "{event}", "ETW events received.");
        _etwEventsAccepted = _meter.CreateCounter<long>("etw_events_accepted", "{event}", "ETW events accepted into the bounded ingestion queue.");
        _etwEventsDropped = _meter.CreateCounter<long>("etw_events_dropped", "{event}", "ETW events dropped from the ingestion queue.");
        _etwEventsMalformed = _meter.CreateCounter<long>("etw_events_malformed", "{event}", "Malformed ETW events rejected before queueing.");
        _eventsProcessed = _meter.CreateCounter<long>("events_processed", "{event}", "ETW events successfully persisted.");
        _eventProcessingFailures = _meter.CreateCounter<long>("event_processing_failures", "{event}", "ETW events that could not be processed.");
        _eventProcessingRetries = _meter.CreateCounter<long>("event_processing_retries", "{retry}", "Retries while persisting queued ETW events.");
        _sqliteWriteFailures = _meter.CreateCounter<long>("sqlite_write_failures", "{failure}", "SQLite write failures.");
        _sqliteBusyFailures = _meter.CreateCounter<long>("sqlite_busy_failures", "{failure}", "SQLite busy or locked failures.");
        _sqliteCorruptionFailures = _meter.CreateCounter<long>("sqlite_corruption_failures", "{failure}", "SQLite corruption or invalid-database failures.");
        _sqliteDiskFullFailures = _meter.CreateCounter<long>("sqlite_disk_full_failures", "{failure}", "SQLite disk-full failures.");
        _autoDenyFailures = _meter.CreateCounter<long>("auto_deny_failures", "{event}", "Automatic IIS actions that failed after event persistence.");
        _suspiciousEvents = _meter.CreateCounter<long>("suspicious_events", "{event}", "Suspicious events successfully persisted.");
        _autoDenies = _meter.CreateCounter<long>("auto_denies", "{action}", "Automatic deny-list actions successfully applied.");
        _detectionHistoryPruned = _meter.CreateCounter<long>("detection_history_pruned", "{history}", "Inactive in-memory detector histories pruned.");
        _detectionHistoryCapacityRejections = _meter.CreateCounter<long>("detection_history_capacity_rejections", "{history}", "New detector histories rejected at configured capacity.");
        _detectionPathCapacityRejections = _meter.CreateCounter<long>("detection_path_capacity_rejections", "{path}", "New unique path tokens rejected at configured capacity.");
        _outOfOrderDetectionEvents = _meter.CreateCounter<long>("detection_events_out_of_order", "{event}", "Events skipped because they exceeded the allowed lateness.");
        _detectionClockResets = _meter.CreateCounter<long>("detection_clock_resets", "{reset}", "In-memory detector windows reset after a system clock rollback.");
        _extensionCacheCapacityRejections = _meter.CreateCounter<long>("detection_extension_cache_capacity_rejections", "{entry}", "Site extension-cache admission or learning rejected at configured capacity.");
        _sqliteWriteDuration = _meter.CreateHistogram<double>("sqlite_write_duration", "s", "Duration of SQLite event writes.");
        _eventPipelineLatency = _meter.CreateHistogram<double>("etw_pipeline_latency", "s", "Time from callback reception to successful event persistence.");
        _meter.CreateObservableGauge("queue_depth", () => QueueDepth, "{event}", "Current ETW ingestion queue depth.");
        _meter.CreateObservableGauge("queue_high_water_mark", () => QueueHighWaterMark, "{event}", "Maximum ETW ingestion queue depth in this process.");
        _meter.CreateObservableGauge("detection_client_histories", () => Interlocked.Read(ref _trackedDetectionHistories), "{history}", "Current in-memory detector client/site histories.");
        _meter.CreateObservableGauge("detection_history_buckets", () => Interlocked.Read(ref _trackedHistoryBuckets), "{bucket}", "Current in-memory detector event-time buckets.");
        _meter.CreateObservableGauge("detection_extension_sites", () => Interlocked.Read(ref _trackedExtensionSites), "{site}", "Current in-memory detector site extension caches.");
        _meter.CreateObservableGauge("detection_path_tokens", () => Interlocked.Read(ref _trackedPathTokens), "{path}", "Current hashed unique paths retained by detector windows.");
        _meter.CreateObservableGauge(
            "last_event_timestamp_seconds",
            () => LastEventTimestamp?.ToUnixTimeMilliseconds() / 1000d ?? 0,
            "s",
            "Unix timestamp of the last successfully processed event.");
    }

    public long EtwEventsDropped => Interlocked.Read(ref _etwEventsDroppedCount);
    public long QueueDepth => Interlocked.Read(ref _queueDepth);
    public long QueueHighWaterMark => Interlocked.Read(ref _queueHighWaterMark);
    public long EtwEventsAccepted => Interlocked.Read(ref _etwEventsAcceptedCount);
    public long EtwEventsMalformed => Interlocked.Read(ref _etwEventsMalformedCount);
    public long EventsProcessed => Interlocked.Read(ref _eventsProcessedCount);
    public long EventProcessingFailures => Interlocked.Read(ref _eventProcessingFailureCount);
    public long EventProcessingRetries => Interlocked.Read(ref _eventProcessingRetryCount);
    public long AutoDenyFailures => Interlocked.Read(ref _autoDenyFailureCount);

    public IngestionDiagnosticsSnapshot GetIngestionDiagnosticsSnapshot()
        => new(
            Interlocked.Read(ref _etwEventsReceivedCount),
            Interlocked.Read(ref _etwEventsAcceptedCount),
            Interlocked.Read(ref _etwEventsDroppedCount),
            Interlocked.Read(ref _etwEventsMalformedCount),
            Interlocked.Read(ref _eventsProcessedCount),
            Interlocked.Read(ref _eventProcessingFailureCount),
            Interlocked.Read(ref _autoDenyFailureCount),
            Interlocked.Read(ref _eventProcessingRetryCount));

    public void InitializeIngestionDiagnostics(IngestionDiagnosticsSnapshot snapshot)
    {
        Interlocked.Exchange(ref _etwEventsReceivedCount, snapshot.EventsReceived);
        Interlocked.Exchange(ref _etwEventsAcceptedCount, snapshot.EventsAccepted);
        Interlocked.Exchange(ref _etwEventsDroppedCount, snapshot.EventsDropped);
        Interlocked.Exchange(ref _etwEventsMalformedCount, snapshot.EventsMalformed);
        Interlocked.Exchange(ref _eventsProcessedCount, snapshot.EventsProcessed);
        Interlocked.Exchange(ref _eventProcessingFailureCount, snapshot.ProcessingFailures);
        Interlocked.Exchange(ref _autoDenyFailureCount, snapshot.AutoDenyFailures);
        _etwEventsReceived.Add(snapshot.EventsReceived);
        _etwEventsAccepted.Add(snapshot.EventsAccepted);
        _etwEventsDropped.Add(snapshot.EventsDropped);
        _etwEventsMalformed.Add(snapshot.EventsMalformed);
        _eventsProcessed.Add(snapshot.EventsProcessed);
        _eventProcessingFailures.Add(snapshot.ProcessingFailures);
        _autoDenyFailures.Add(snapshot.AutoDenyFailures);
        Interlocked.Exchange(ref _eventProcessingRetryCount, snapshot.ProcessingRetries);
        _eventProcessingRetries.Add(snapshot.ProcessingRetries);
    }

    public DateTimeOffset? LastEventTimestamp
    {
        get
        {
            var ticks = Interlocked.Read(ref _lastEventTimestampTicks);
            return ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
        }
    }

    public void RecordEtwEventReceived()
    {
        Interlocked.Increment(ref _etwEventsReceivedCount);
        _etwEventsReceived.Add(1);
    }

    public void RecordEtwEventDropped()
    {
        Interlocked.Increment(ref _etwEventsDroppedCount);
        _etwEventsDropped.Add(1);
    }

    public long ReserveQueueItem() => Interlocked.Increment(ref _queueDepth);

    public void RecordQueueItemAccepted(long reservedDepth)
    {
        Interlocked.Increment(ref _etwEventsAcceptedCount);
        _etwEventsAccepted.Add(1);
        UpdateMaximum(ref _queueHighWaterMark, reservedDepth);
    }

    public void RecordQueueItemEnqueued()
    {
        var depth = ReserveQueueItem();
        RecordQueueItemAccepted(depth);
    }

    public void RecordQueueItemDequeued()
    {
        var depth = Interlocked.Decrement(ref _queueDepth);
        if (depth < 0)
        {
            Interlocked.Exchange(ref _queueDepth, 0);
        }
    }

    public void RecordEtwEventMalformed()
    {
        Interlocked.Increment(ref _etwEventsMalformedCount);
        _etwEventsMalformed.Add(1);
    }

    public void RecordEventProcessingFailure()
        => RecordEventProcessingFailure(1);

    public void RecordEventProcessingFailure(long count)
    {
        if (count <= 0)
        {
            return;
        }

        Interlocked.Add(ref _eventProcessingFailureCount, count);
        _eventProcessingFailures.Add(count);
    }

    public void RecordEventProcessingRetry()
    {
        Interlocked.Increment(ref _eventProcessingRetryCount);
        _eventProcessingRetries.Add(1);
    }

    public void RecordAutoDenyFailure()
    {
        Interlocked.Increment(ref _autoDenyFailureCount);
        _autoDenyFailures.Add(1);
    }

    public void RecordEventProcessed(SecurityEvent webEvent)
        => RecordEventProcessed(webEvent, null);

    public void RecordEventProcessed(SecurityEvent webEvent, TimeSpan? pipelineLatency)
    {
        Interlocked.Increment(ref _eventsProcessedCount);
        _eventsProcessed.Add(1);
        UpdateMaximum(ref _lastEventTimestampTicks, webEvent.Timestamp.UtcDateTime.Ticks);
        if (pipelineLatency is { } latency)
        {
            var seconds = Math.Max(0, latency.TotalSeconds);
            _eventPipelineLatency.Record(seconds);
            Interlocked.Increment(ref _pipelineLatencyCount);
            Interlocked.Add(ref _pipelineLatencyTicks, Math.Max(0, latency.Ticks));
            for (var index = 0; index < PipelineLatencyBucketBounds.Length; index++)
            {
                if (seconds <= PipelineLatencyBucketBounds[index])
                {
                    Interlocked.Increment(ref _pipelineLatencyBucketCounts[index]);
                }
            }
        }

        if (webEvent.IsSuspicious)
        {
            Interlocked.Increment(ref _suspiciousEventsCount);
            _suspiciousEvents.Add(1);
        }
    }

    public void RecordAutoDeny()
    {
        Interlocked.Increment(ref _autoDeniesCount);
        _autoDenies.Add(1);
    }

    public void RecordDetectionHistoryPruned()
    {
        Interlocked.Increment(ref _detectionHistoryPrunedCount);
        _detectionHistoryPruned.Add(1);
    }

    public void RecordDetectionHistoryCapacityRejection()
    {
        Interlocked.Increment(ref _detectionHistoryCapacityRejectionCount);
        _detectionHistoryCapacityRejections.Add(1);
    }

    public void RecordDetectionPathCapacityRejection()
    {
        Interlocked.Increment(ref _detectionPathCapacityRejectionCount);
        _detectionPathCapacityRejections.Add(1);
    }

    public void RecordOutOfOrderDetectionEvent()
    {
        Interlocked.Increment(ref _outOfOrderDetectionEventCount);
        _outOfOrderDetectionEvents.Add(1);
    }

    public void RecordDetectionClockReset()
    {
        Interlocked.Increment(ref _detectionClockResetCount);
        _detectionClockResets.Add(1);
    }

    public void RecordExtensionCacheCapacityRejection()
    {
        Interlocked.Increment(ref _extensionCacheCapacityRejectionCount);
        _extensionCacheCapacityRejections.Add(1);
    }

    public void SetDetectionRequestHistorySnapshot(int histories, int historyBuckets, int pathTokens)
    {
        Interlocked.Exchange(ref _trackedDetectionHistories, histories);
        Interlocked.Exchange(ref _trackedHistoryBuckets, historyBuckets);
        Interlocked.Exchange(ref _trackedPathTokens, pathTokens);
    }

    public void SetDetectionExtensionSiteCount(int extensionSites)
        => Interlocked.Exchange(ref _trackedExtensionSites, extensionSites);

    public void RecordSqliteWrite(TimeSpan duration)
    {
        var elapsed = Math.Max(0, duration.TotalSeconds);
        _sqliteWriteDuration.Record(elapsed);
        Interlocked.Increment(ref _sqliteWriteDurationCount);
        Interlocked.Add(ref _sqliteWriteDurationTicks, Math.Max(0, duration.Ticks));

        for (var index = 0; index < DurationBucketBounds.Length; index++)
        {
            if (elapsed <= DurationBucketBounds[index])
            {
                Interlocked.Increment(ref _durationBucketCounts[index]);
            }
        }
    }

    public void RecordSqliteFailure(int errorCode)
    {
        _sqliteWriteFailures.Add(1);
        Interlocked.Increment(ref _sqliteWriteFailureCount);
        switch (errorCode)
        {
            case 5 or 6:
                _sqliteBusyFailures.Add(1);
                Interlocked.Increment(ref _sqliteBusyFailureCount);
                break;
            case 11 or 26:
                _sqliteCorruptionFailures.Add(1);
                Interlocked.Increment(ref _sqliteCorruptionFailureCount);
                break;
            case 13:
                _sqliteDiskFullFailures.Add(1);
                Interlocked.Increment(ref _sqliteDiskFullFailureCount);
                break;
        }
    }

    public string RenderPrometheus()
    {
        var output = new StringBuilder();
        AppendCounter(output, "etw_events_received", "ETW events received.", Interlocked.Read(ref _etwEventsReceivedCount));
        AppendCounter(output, "etw_events_accepted", "ETW events accepted into the bounded ingestion queue.", Interlocked.Read(ref _etwEventsAcceptedCount));
        AppendCounter(output, "etw_events_dropped", "ETW events dropped from the ingestion queue.", Interlocked.Read(ref _etwEventsDroppedCount));
        AppendCounter(output, "etw_events_malformed", "Malformed ETW events rejected before queueing.", Interlocked.Read(ref _etwEventsMalformedCount));
        AppendCounter(output, "events_processed", "ETW events successfully persisted.", Interlocked.Read(ref _eventsProcessedCount));
        AppendCounter(output, "event_processing_failures", "ETW events that could not be processed.", Interlocked.Read(ref _eventProcessingFailureCount));
        AppendCounter(output, "event_processing_retries", "Retries while persisting queued ETW events.", Interlocked.Read(ref _eventProcessingRetryCount));
        AppendCounter(output, "sqlite_write_failures", "SQLite write failures.", Interlocked.Read(ref _sqliteWriteFailureCount));
        AppendCounter(output, "sqlite_busy_failures", "SQLite busy or locked failures.", Interlocked.Read(ref _sqliteBusyFailureCount));
        AppendCounter(output, "sqlite_corruption_failures", "SQLite corruption or invalid-database failures.", Interlocked.Read(ref _sqliteCorruptionFailureCount));
        AppendCounter(output, "sqlite_disk_full_failures", "SQLite disk-full failures.", Interlocked.Read(ref _sqliteDiskFullFailureCount));
        AppendCounter(output, "auto_deny_failures", "Automatic IIS actions that failed after event persistence.", Interlocked.Read(ref _autoDenyFailureCount));
        AppendCounter(output, "suspicious_events", "Suspicious events successfully persisted.", Interlocked.Read(ref _suspiciousEventsCount));
        AppendCounter(output, "auto_denies", "Automatic deny-list actions successfully applied.", Interlocked.Read(ref _autoDeniesCount));
        AppendCounter(output, "detection_history_pruned", "Inactive in-memory detector histories pruned.", Interlocked.Read(ref _detectionHistoryPrunedCount));
        AppendCounter(output, "detection_history_capacity_rejections", "New detector histories rejected at configured capacity.", Interlocked.Read(ref _detectionHistoryCapacityRejectionCount));
        AppendCounter(output, "detection_path_capacity_rejections", "New unique path tokens rejected at configured capacity.", Interlocked.Read(ref _detectionPathCapacityRejectionCount));
        AppendCounter(output, "detection_events_out_of_order", "Events skipped because they exceeded the allowed lateness.", Interlocked.Read(ref _outOfOrderDetectionEventCount));
        AppendCounter(output, "detection_clock_resets", "In-memory detector windows reset after a system clock rollback.", Interlocked.Read(ref _detectionClockResetCount));
        AppendCounter(output, "detection_extension_cache_capacity_rejections", "Site extension-cache admission or learning rejected at configured capacity.", Interlocked.Read(ref _extensionCacheCapacityRejectionCount));

        output.AppendLine("# HELP queue_depth Current ETW ingestion queue depth.");
        output.AppendLine("# TYPE queue_depth gauge");
        output.Append("queue_depth ").AppendLine(QueueDepth.ToString(CultureInfo.InvariantCulture));
        AppendGauge(output, "queue_high_water_mark", "Maximum ETW ingestion queue depth in this process.", QueueHighWaterMark);

        AppendGauge(output, "detection_client_histories", "Current in-memory detector client/site histories.", Interlocked.Read(ref _trackedDetectionHistories));
        AppendGauge(output, "detection_history_buckets", "Current in-memory detector event-time buckets.", Interlocked.Read(ref _trackedHistoryBuckets));
        AppendGauge(output, "detection_extension_sites", "Current in-memory detector site extension caches.", Interlocked.Read(ref _trackedExtensionSites));
        AppendGauge(output, "detection_path_tokens", "Current hashed unique paths retained by detector windows.", Interlocked.Read(ref _trackedPathTokens));

        output.AppendLine("# HELP last_event_timestamp_seconds Unix timestamp of the last successfully processed event.");
        output.AppendLine("# TYPE last_event_timestamp_seconds gauge");
        output.Append("last_event_timestamp_seconds ")
            .AppendLine((LastEventTimestamp?.ToUnixTimeMilliseconds() / 1000d ?? 0).ToString("0.######", CultureInfo.InvariantCulture));

        output.AppendLine("# HELP sqlite_write_duration_seconds Duration of SQLite event writes.");
        output.AppendLine("# TYPE sqlite_write_duration_seconds histogram");
        for (var index = 0; index < DurationBucketBounds.Length; index++)
        {
            output.Append("sqlite_write_duration_seconds_bucket{le=\"")
                .Append(DurationBucketBounds[index].ToString("0.###", CultureInfo.InvariantCulture))
                .Append("\"} ")
                .AppendLine(Interlocked.Read(ref _durationBucketCounts[index]).ToString(CultureInfo.InvariantCulture));
        }

        var count = Interlocked.Read(ref _sqliteWriteDurationCount);
        output.Append("sqlite_write_duration_seconds_bucket{le=\"+Inf\"} ").AppendLine(count.ToString(CultureInfo.InvariantCulture));
        output.Append("sqlite_write_duration_seconds_sum ")
            .AppendLine((Interlocked.Read(ref _sqliteWriteDurationTicks) / (double)TimeSpan.TicksPerSecond).ToString("0.######", CultureInfo.InvariantCulture));
        output.Append("sqlite_write_duration_seconds_count ").AppendLine(count.ToString(CultureInfo.InvariantCulture));

        output.AppendLine("# HELP etw_pipeline_latency_seconds Time from callback reception to successful event persistence.");
        output.AppendLine("# TYPE etw_pipeline_latency_seconds histogram");
        for (var index = 0; index < PipelineLatencyBucketBounds.Length; index++)
        {
            output.Append("etw_pipeline_latency_seconds_bucket{le=\"")
                .Append(PipelineLatencyBucketBounds[index].ToString("0.###", CultureInfo.InvariantCulture))
                .Append("\"} ")
                .AppendLine(Interlocked.Read(ref _pipelineLatencyBucketCounts[index]).ToString(CultureInfo.InvariantCulture));
        }

        var pipelineLatencyCount = Interlocked.Read(ref _pipelineLatencyCount);
        output.Append("etw_pipeline_latency_seconds_bucket{le=\"+Inf\"} ").AppendLine(pipelineLatencyCount.ToString(CultureInfo.InvariantCulture));
        output.Append("etw_pipeline_latency_seconds_sum ")
            .AppendLine((Interlocked.Read(ref _pipelineLatencyTicks) / (double)TimeSpan.TicksPerSecond).ToString("0.######", CultureInfo.InvariantCulture));
        output.Append("etw_pipeline_latency_seconds_count ").AppendLine(pipelineLatencyCount.ToString(CultureInfo.InvariantCulture));
        return output.ToString();
    }

    public void Dispose() => _meter.Dispose();

    private static void AppendCounter(StringBuilder output, string name, string description, long value)
    {
        output.Append("# HELP ").Append(name).Append(' ').AppendLine(description);
        output.Append("# TYPE ").Append(name).AppendLine(" counter");
        output.Append(name).Append(' ').AppendLine(value.ToString(CultureInfo.InvariantCulture));
    }

    private static void AppendGauge(StringBuilder output, string name, string description, long value)
    {
        output.Append("# HELP ").Append(name).Append(' ').AppendLine(description);
        output.Append("# TYPE ").Append(name).AppendLine(" gauge");
        output.Append(name).Append(' ').AppendLine(value.ToString(CultureInfo.InvariantCulture));
    }

    private static void UpdateMaximum(ref long target, long value)
    {
        var current = Interlocked.Read(ref target);
        while (value > current)
        {
            var observed = Interlocked.CompareExchange(ref target, value, current);
            if (observed == current)
            {
                return;
            }

            current = observed;
        }
    }
}
