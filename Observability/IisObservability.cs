using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text;
using iisidsd.Models;

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

    private readonly Meter _meter = new(MeterName, "1.0.0");
    private readonly Counter<long> _etwEventsReceived;
    private readonly Counter<long> _etwEventsDropped;
    private readonly Counter<long> _eventsProcessed;
    private readonly Counter<long> _suspiciousEvents;
    private readonly Counter<long> _autoDenies;
    private readonly Histogram<double> _sqliteWriteDuration;
    private readonly long[] _durationBucketCounts = new long[DurationBucketBounds.Length];
    private long _etwEventsReceivedCount;
    private long _etwEventsDroppedCount;
    private long _eventsProcessedCount;
    private long _suspiciousEventsCount;
    private long _autoDeniesCount;
    private long _queueDepth;
    private long _lastEventTimestampTicks;
    private long _sqliteWriteDurationCount;
    private long _sqliteWriteDurationTicks;

    public IisObservability()
    {
        _etwEventsReceived = _meter.CreateCounter<long>("etw_events_received", "{event}", "ETW events received.");
        _etwEventsDropped = _meter.CreateCounter<long>("etw_events_dropped", "{event}", "ETW events dropped from the ingestion queue.");
        _eventsProcessed = _meter.CreateCounter<long>("events_processed", "{event}", "ETW events successfully persisted.");
        _suspiciousEvents = _meter.CreateCounter<long>("suspicious_events", "{event}", "Suspicious events successfully persisted.");
        _autoDenies = _meter.CreateCounter<long>("auto_denies", "{action}", "Automatic deny-list actions successfully applied.");
        _sqliteWriteDuration = _meter.CreateHistogram<double>("sqlite_write_duration", "s", "Duration of SQLite event writes.");
        _meter.CreateObservableGauge("queue_depth", () => QueueDepth, "{event}", "Current ETW ingestion queue depth.");
        _meter.CreateObservableGauge(
            "last_event_timestamp_seconds",
            () => LastEventTimestamp?.ToUnixTimeMilliseconds() / 1000d ?? 0,
            "s",
            "Unix timestamp of the last successfully processed event.");
    }

    public long EtwEventsDropped => Interlocked.Read(ref _etwEventsDroppedCount);
    public long QueueDepth => Interlocked.Read(ref _queueDepth);

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

    public void RecordQueueItemEnqueued() => Interlocked.Increment(ref _queueDepth);

    public void RecordQueueItemDequeued()
    {
        var depth = Interlocked.Decrement(ref _queueDepth);
        if (depth < 0)
        {
            Interlocked.Exchange(ref _queueDepth, 0);
        }
    }

    public void RecordEventProcessed(SecurityEvent webEvent)
    {
        Interlocked.Increment(ref _eventsProcessedCount);
        _eventsProcessed.Add(1);
        Interlocked.Exchange(ref _lastEventTimestampTicks, webEvent.Timestamp.UtcDateTime.Ticks);

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

    public string RenderPrometheus()
    {
        var output = new StringBuilder();
        AppendCounter(output, "etw_events_received", "ETW events received.", Interlocked.Read(ref _etwEventsReceivedCount));
        AppendCounter(output, "etw_events_dropped", "ETW events dropped from the ingestion queue.", Interlocked.Read(ref _etwEventsDroppedCount));
        AppendCounter(output, "events_processed", "ETW events successfully persisted.", Interlocked.Read(ref _eventsProcessedCount));
        AppendCounter(output, "suspicious_events", "Suspicious events successfully persisted.", Interlocked.Read(ref _suspiciousEventsCount));
        AppendCounter(output, "auto_denies", "Automatic deny-list actions successfully applied.", Interlocked.Read(ref _autoDeniesCount));

        output.AppendLine("# HELP queue_depth Current ETW ingestion queue depth.");
        output.AppendLine("# TYPE queue_depth gauge");
        output.Append("queue_depth ").AppendLine(QueueDepth.ToString(CultureInfo.InvariantCulture));

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
        return output.ToString();
    }

    public void Dispose() => _meter.Dispose();

    private static void AppendCounter(StringBuilder output, string name, string description, long value)
    {
        output.Append("# HELP ").Append(name).Append(' ').AppendLine(description);
        output.Append("# TYPE ").Append(name).AppendLine(" counter");
        output.Append(name).Append(' ').AppendLine(value.ToString(CultureInfo.InvariantCulture));
    }
}
