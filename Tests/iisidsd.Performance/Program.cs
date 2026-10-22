using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using iisidsd.Api;
using iisidsd.Configuration;
using iisidsd.Detection;
using iisidsd.Etw;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Services;
using iisidsd.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

const int DefaultSeed = 424242;
const int DefaultEventCount = 50_000;
var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web)
{
    WriteIndented = true
};
var arguments = BenchmarkArguments.Parse(args);
var repositoryRoot = FindRepositoryRoot();
var releaseVersion = typeof(SqliteEventStore).Assembly.GetName().Version?.ToString(3) ?? "unknown";
var reportPath = arguments.OutputPath is null
    ? Path.Combine(repositoryRoot, "docs", "reports", $"performance-baseline-{releaseVersion}.json")
    : Path.GetFullPath(arguments.OutputPath, repositoryRoot);
var comparePath = arguments.ComparePath is null ? null : Path.GetFullPath(arguments.ComparePath, repositoryRoot);
var eventCount = arguments.EventCount ?? ReadEventCount();
if (eventCount is < 1_000 or > 500_000)
{
    throw new ArgumentOutOfRangeException(nameof(eventCount), "Event count must be between 1,000 and 500,000.");
}

var report = await new BenchmarkRunner(repositoryRoot, eventCount, DefaultSeed).RunAsync();
if (comparePath is not null)
{
    var previous = JsonSerializer.Deserialize<BenchmarkReport>(await File.ReadAllTextAsync(comparePath), jsonOptions)
        ?? throw new InvalidDataException($"Could not read benchmark report '{comparePath}'.");
    report = report with { Comparison = Compare(previous, report) };
}

Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
await File.WriteAllTextAsync(reportPath, JsonSerializer.Serialize(report, jsonOptions));
var markdownPath = Path.ChangeExtension(reportPath, ".md");
await File.WriteAllTextAsync(markdownPath, FormatMarkdown(report));
Console.WriteLine($"Benchmark JSON: {reportPath}");
Console.WriteLine($"Benchmark report: {markdownPath}");
Console.WriteLine(FormatMarkdown(report));

return 0;

static int ReadEventCount()
    => int.TryParse(Environment.GetEnvironmentVariable("IISIDSD_BENCHMARK_EVENTS"), out var value)
        ? value
        : DefaultEventCount;

static string FindRepositoryRoot()
{
    for (var directory = new DirectoryInfo(Environment.CurrentDirectory); directory is not null; directory = directory.Parent)
    {
        if (File.Exists(Path.Combine(directory.FullName, "iisidsd.slnx")))
        {
            return directory.FullName;
        }
    }

    return Environment.CurrentDirectory;
}

static BenchmarkComparison Compare(BenchmarkReport previous, BenchmarkReport current)
{
    static double PercentChange(double previousValue, double currentValue)
        => previousValue == 0 ? 0 : (currentValue - previousValue) / previousValue * 100;

    var previousMetrics = new Dictionary<string, double>
    {
        ["Sustained throughput (events/s)"] = previous.SustainedIngestion.EventsPerSecond,
        ["Sustained detection latency p95 (ms)"] = previous.SustainedIngestion.EndToEndLatency.P95Milliseconds,
        ["Sustained detection latency p99 (ms)"] = previous.SustainedIngestion.EndToEndLatency.P99Milliseconds,
        ["Database growth (bytes/event)"] = previous.Database.GrowthBytesPerEvent,
        ["Dashboard query latency p95 (ms)"] = previous.Dashboard.ConcurrentQueries.Latency.P95Milliseconds,
        ["Event export latency (ms)"] = previous.Dashboard.EventJsonExport.LatencyMilliseconds
    };
    var currentMetrics = new Dictionary<string, double>
    {
        ["Sustained throughput (events/s)"] = current.SustainedIngestion.EventsPerSecond,
        ["Sustained detection latency p95 (ms)"] = current.SustainedIngestion.EndToEndLatency.P95Milliseconds,
        ["Sustained detection latency p99 (ms)"] = current.SustainedIngestion.EndToEndLatency.P99Milliseconds,
        ["Database growth (bytes/event)"] = current.Database.GrowthBytesPerEvent,
        ["Dashboard query latency p95 (ms)"] = current.Dashboard.ConcurrentQueries.Latency.P95Milliseconds,
        ["Event export latency (ms)"] = current.Dashboard.EventJsonExport.LatencyMilliseconds
    };
    var metrics = previousMetrics.Select(pair => new ComparisonMetric(
        pair.Key,
        pair.Value,
        currentMetrics[pair.Key],
        PercentChange(pair.Value, currentMetrics[pair.Key]))).ToArray();
    var hardwareComparable = string.Equals(previous.Environment.ProcessorIdentifier, current.Environment.ProcessorIdentifier, StringComparison.Ordinal) &&
        previous.Environment.LogicalProcessorCount == current.Environment.LogicalProcessorCount &&
            string.Equals(previous.Environment.OperatingSystem, current.Environment.OperatingSystem, StringComparison.Ordinal) &&
            string.Equals(previous.Environment.ProcessArchitecture, current.Environment.ProcessArchitecture, StringComparison.Ordinal);
        var runtimeComparable = string.Equals(previous.Environment.Runtime, current.Environment.Runtime, StringComparison.Ordinal) &&
            string.Equals(previous.Environment.DotnetVersion, current.Environment.DotnetVersion, StringComparison.Ordinal);
    var configurationComparable = previous.Configuration == current.Configuration;
    return new BenchmarkComparison(
        previous.ApplicationVersion,
        previous.SourceRevision,
        hardwareComparable,
            runtimeComparable,
        configurationComparable,
        metrics);
}

static string FormatMarkdown(BenchmarkReport report)
{
    static string Metric(double value, string unit) => $"{value:N2} {unit}";
    static string Percentiles(LatencyDistribution value)
        => $"n={value.SampleCount}; p50={Metric(value.P50Milliseconds, "ms")}; p95={Metric(value.P95Milliseconds, "ms")}; p99={Metric(value.P99Milliseconds, "ms")}";

    var output = new System.Text.StringBuilder();
    output.AppendLine($"# iisidsd Performance Baseline {report.ApplicationVersion}");
    output.AppendLine();
    output.AppendLine($"Run: {report.GeneratedAtUtc:O} | source: `{report.SourceRevision}` | working tree dirty: {report.WorkingTreeDirty}");
    output.AppendLine($"Host: {report.Environment.ProcessorIdentifier}, {report.Environment.LogicalProcessorCount} logical CPUs, {report.Environment.AvailableMemoryBytes / (1024d * 1024 * 1024):N1} GiB available; {report.Environment.OperatingSystem}; {report.Environment.Runtime}");
    output.AppendLine($"Dataset: seed {report.Configuration.Seed}; {report.Configuration.RequestedEvents:N0} sustained requests; {report.Dataset.UniqueClientIps:N0} client IPs, {report.Dataset.UniquePaths:N0} paths, {report.Dataset.UniqueDomains:N0} domains/sites; repeated-404 detections {report.Dataset.Repeated404Detected:N0}/{report.Dataset.Repeated404Requests:N0}.");
    output.AppendLine();
    output.AppendLine("## Release Comparison");
    if (report.Comparison is null)
    {
        output.AppendLine("No previous report was supplied. This is the first baseline; no release comparison or performance target is asserted.");
    }
    else
    {
        output.AppendLine($"Compared with {report.Comparison.PreviousVersion} (`{report.Comparison.PreviousRevision}`). Same hardware: {report.Comparison.HardwareComparable}; same benchmark configuration: {report.Comparison.ConfigurationComparable}.");
        output.AppendLine("Changes are directional percentages; positive latency/storage change is slower/larger, while positive throughput change is faster.");
        foreach (var metric in report.Comparison.Metrics)
        {
            output.AppendLine($"- {metric.Name}: {metric.PreviousValue:N2} -> {metric.CurrentValue:N2} ({metric.ChangePercent:+0.0;-0.0;0.0}%).");
        }
    }

    output.AppendLine();
    output.AppendLine("## Measurements");
    output.AppendLine($"- Sustained ingestion: {report.SustainedIngestion.ProcessedEvents:N0} processed at {Metric(report.SustainedIngestion.EventsPerSecond, "events/s")}; received {report.SustainedIngestion.ReceivedEvents:N0}, dropped {report.SustainedIngestion.DroppedEvents:N0}, queue high-water {report.SustainedIngestion.QueueHighWaterMark:N0}; end-to-end detection latency {Percentiles(report.SustainedIngestion.EndToEndLatency)}.");
    output.AppendLine($"- Burst ingestion: {report.BurstIngestion.ProcessedEvents:N0} processed at {Metric(report.BurstIngestion.EventsPerSecond, "events/s")}; dropped {report.BurstIngestion.DroppedEvents:N0}, queue high-water {report.BurstIngestion.QueueHighWaterMark:N0}; end-to-end latency {Percentiles(report.BurstIngestion.EndToEndLatency)}.");
    output.AppendLine($"- Resource use during sustained ingestion: CPU {report.Resources.CpuSeconds:N2}s ({report.Resources.CpuPercentOfOneCore:N1}% of one logical core); managed allocation {report.Resources.ManagedAllocatedBytes / (1024d * 1024):N1} MiB; working set {report.Resources.WorkingSetBeforeBytes / (1024d * 1024):N1} -> {report.Resources.WorkingSetAfterBytes / (1024d * 1024):N1} MiB, peak {report.Resources.PeakWorkingSetBytes / (1024d * 1024):N1} MiB.");
    output.AppendLine($"- SQLite: {report.Database.FinalBytes:N0} bytes final size; retained {report.Database.RetainedEvents:N0} rows; growth {report.Database.GrowthBytes:N0} bytes ({report.Database.GrowthBytesPerEvent:N1} bytes/event, {report.Database.GrowthBytesPerSecond:N0} bytes/s).");
    output.AppendLine($"- Dashboard concurrent filtered queries: {report.Dashboard.ConcurrentQueries.RequestCount:N0} requests at {Metric(report.Dashboard.ConcurrentQueries.RequestsPerSecond, "requests/s")}; {Percentiles(report.Dashboard.ConcurrentQueries.Latency)}.");
    output.AppendLine($"- Dashboard concurrent SSE clients: {report.Dashboard.SseClientCount}; event delivery {Percentiles(report.Dashboard.SseDeliveryLatency)}.");
    output.AppendLine($"- Event JSON export: {Metric(report.Dashboard.EventJsonExport.LatencyMilliseconds, "ms")}, {report.Dashboard.EventJsonExport.ResponseBytes:N0} bytes; event CSV export: {Metric(report.Dashboard.EventCsvExport.LatencyMilliseconds, "ms")}, {report.Dashboard.EventCsvExport.ResponseBytes:N0} bytes; findings export: {Metric(report.Dashboard.FindingsExport.LatencyMilliseconds, "ms")}, {report.Dashboard.FindingsExport.ResponseBytes:N0} bytes.");
    output.AppendLine($"- Queue saturation: offered {report.QueueSaturation.ReceivedEvents:N0}, accepted {report.QueueSaturation.AcceptedEvents:N0}, dropped {report.QueueSaturation.DroppedEvents:N0}, high-water {report.QueueSaturation.QueueHighWaterMark:N0}; drain recovery {Metric(report.QueueSaturation.RecoveryMilliseconds, "ms")}.");
    output.AppendLine($"- SQLite lock contention: held writer lock {Metric(report.SqliteContention.LockHoldMilliseconds, "ms")}; persisted {report.SqliteContention.ProcessedEvents:N0}/{report.SqliteContention.ReceivedEvents:N0}; lock-release recovery {Metric(report.SqliteContention.RecoveryMilliseconds, "ms")}; batch-write p95 {Metric(report.SqliteContention.BatchWriteLatency.P95Milliseconds, "ms")}.");
    output.AppendLine();
    output.AppendLine("## Method and Limits");
    output.AppendLine("Synthetic IIS-shaped ETW payloads use a fixed seed and pass through the production normalizer, detector, bounded ingestion queue, SQLite event/finding stores, and mapped dashboard endpoints. TestServer API timings are in-process and exclude network/TLS/Windows Authentication. SSE clients are in-process streams; no live IIS ETW provider or production traffic is used. CPU and memory are process-wide snapshots around sustained ingestion. SQLite lock contention is injected with a held write transaction. The first run establishes a baseline only: no regression thresholds are configured; compare only runs with matched hardware, runtime, dataset, and settings.");
    return output.ToString();
}

sealed class BenchmarkRunner(string repositoryRoot, int eventCount, int seed)
{
    private const int SiteCount = 32;
    private const int QueueCapacity = 10_000;
    private const int SaturationQueueCapacity = 256;
    private const int SaturationBatchSize = 16;
    private const int BatchSize = 64;
    private const int SustainedRateEventsPerSecond = 1_000;
    private const int ApiWorkerCount = 8;
    private const int ApiRequestsPerWorker = 25;
    private const int SseClientCount = 8;
    private readonly string _rootPath = Path.Combine(Path.GetTempPath(), "iisidsd-performance", Guid.NewGuid().ToString("N"));

    public async Task<BenchmarkReport> RunAsync()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new BenchmarkHostEnvironment(_rootPath);
        var storageSettings = new StorageOptions
        {
            DatabasePath = "data/performance.sqlite3",
            EventRetentionLimit = eventCount + Math.Max(10_000, eventCount / 5) + 2_000,
            EventRetentionDays = 60,
            FindingRetentionDays = 60,
            BusyTimeoutSeconds = 2,
            JournalMode = "WAL",
            SynchronousMode = "FULL"
        };
        var storageOptions = Options.Create(storageSettings);
        var findingStore = new SqliteFindingStore(storageOptions, environment);
        using var databaseObservability = new IisObservability();
        var initializer = new EventDbInitializer(storageOptions, environment, findingStore, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);
        var eventOptions = Options.Create(new IisEtwOptions
        {
            IngestionBufferSize = QueueCapacity,
            ProcessingBatchSize = BatchSize,
            SubscriptionBufferSize = 20_000
        });
        var eventStore = new SqliteEventStore(eventOptions, storageOptions, environment, findingStore, databaseObservability);
        var banCountService = new BanCountService(storageOptions, environment);
        var aggregationService = new IpAggregationService(findingStore, banCountService);
        var databasePath = Path.Combine(_rootPath, "data", "performance.sqlite3");
        var initialDatabaseBytes = GetDatabaseBytes(databasePath);
        var requests = SyntheticTraffic.CreateRequests(eventCount, seed, SiteCount);
        var dataset = DatasetSummary.From(requests);
        var sustainedQueueCapacity = QueueCapacity;
        var sustained = await RunIngestionAsync(eventStore, requests, sustainedQueueCapacity, BatchSize, new DetectionOptions(), null,
            targetEventsPerSecond: SustainedRateEventsPerSecond,
            captureResources: true);
        var sustainedDatabaseBytes = GetDatabaseBytes(databasePath);
        var burstCount = Math.Clamp(eventCount / 5, 500, 10_000);
        var burstRequests = SyntheticTraffic.CreateRequests(burstCount, seed, SiteCount, "burst");
        var bursts = await RunIngestionAsync(eventStore, burstRequests, QueueCapacity, BatchSize, new DetectionOptions(), 500);
        var saturation = await RunQueueSaturationAsync(eventStore, seed, SiteCount);
        var contention = await RunSqliteContentionAsync(eventStore, databasePath, seed, SiteCount);
        var dashboard = await RunDashboardBenchmarksAsync(eventStore, findingStore, aggregationService, banCountService, storageOptions, environment, databasePath, seed, SiteCount);
        CheckpointWal(databasePath);
        var finalDatabaseBytes = GetDatabaseBytes(databasePath);
        var retainedEvents = GetRetainedEventCount(databasePath);
        var growthBytes = Math.Max(0, sustainedDatabaseBytes - initialDatabaseBytes);
        var sustainedSeconds = Math.Max(0.001, sustained.DurationSeconds);
        var currentAssembly = typeof(SqliteEventStore).Assembly;
        var version = currentAssembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? currentAssembly.GetName().Version?.ToString()
            ?? "unknown";
        var availableMemory = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        var report = new BenchmarkReport(
            DateTimeOffset.UtcNow,
            version,
            await GetGitValueAsync(repositoryRoot, "rev-parse", "--short", "HEAD"),
            await IsWorkingTreeDirtyAsync(repositoryRoot),
            new BenchmarkEnvironment(
                Environment.MachineName,
                Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "not reported by host",
                Environment.ProcessorCount,
                availableMemory,
                RuntimeInformation.OSDescription,
                RuntimeInformation.ProcessArchitecture.ToString(),
                RuntimeInformation.FrameworkDescription,
                Environment.Version.ToString()),
            new BenchmarkConfiguration(
                seed,
                eventCount,
                SiteCount,
                dataset.UniqueClientIps,
                dataset.UniquePaths,
                sustainedQueueCapacity,
                SaturationQueueCapacity,
                SaturationBatchSize,
                SustainedRateEventsPerSecond,
                500,
                BatchSize,
                storageSettings.JournalMode,
                storageSettings.SynchronousMode,
                storageSettings.BusyTimeoutSeconds,
                storageSettings.EventRetentionLimit),
            dataset with { Repeated404Detected = sustained.Repeated404Detections },
            sustained,
            bursts,
            sustained.Resources ?? new ResourceResult(0, 0, 0, 0, 0, 0, 0),
            new DatabaseResult(
                initialDatabaseBytes,
                sustainedDatabaseBytes,
                finalDatabaseBytes,
                growthBytes,
                eventCount == 0 ? 0 : growthBytes / (double)eventCount,
                growthBytes / sustainedSeconds,
                retainedEvents),
            dashboard,
            saturation,
            contention,
            null);

        SqliteConnection.ClearAllPools();
        Directory.Delete(_rootPath, recursive: true);
        return report;
    }

    private static async Task<IngestionResult> RunIngestionAsync(
        SqliteEventStore eventStore,
        IReadOnlyList<SyntheticRequest> requests,
        int queueCapacity,
        int batchSize,
        DetectionOptions detectionOptions,
        int? burstSize,
        string idSuffix = "",
        int? targetEventsPerSecond = null,
        bool captureResources = false)
    {
        using var observability = new IisObservability();
        var measuredStore = new MeasuringEventStore(eventStore);
        var pipeline = CreatePipeline(measuredStore, observability, detectionOptions, queueCapacity, batchSize);
        var before = eventStore.GetIngestionDiagnostics();
        var process = captureResources ? Process.GetCurrentProcess() : null;
        process?.Refresh();
        var cpuBefore = process?.TotalProcessorTime ?? TimeSpan.Zero;
        var allocationBefore = captureResources ? GC.GetTotalAllocatedBytes(true) : 0;
        var workingSetBefore = process?.WorkingSet64 ?? 0;
        var processing = pipeline.ProcessAsync();
        var timer = Stopwatch.StartNew();
        var acceptedLocally = 0;
        for (var index = 0; index < requests.Count; index++)
        {
            var payload = requests[index].ToPayload(idSuffix);
            measuredStore.Track(payload.Id, payload.ReceivedTimestamp);
            if (pipeline.TryEnqueue(payload))
            {
                acceptedLocally++;
            }
            else
            {
                measuredStore.Forget(payload.Id);
            }

            if (burstSize is { } size && (index + 1) % size == 0 && index + 1 < requests.Count)
            {
                await Task.Delay(100);
            }
            else if (targetEventsPerSecond is { } rate && (index + 1) % 100 == 0 && index + 1 < requests.Count)
            {
                await Task.Delay(TimeSpan.FromSeconds(100d / rate));
            }
            else if (index % 512 == 0)
            {
                await Task.Yield();
            }
        }

        pipeline.Complete();
        await processing.WaitAsync(TimeSpan.FromMinutes(5));
        timer.Stop();
        process?.Refresh();
        var cpuSeconds = process is null ? 0 : (process.TotalProcessorTime - cpuBefore).TotalSeconds;
        var resources = process is null
            ? null
            : new ResourceResult(
                cpuSeconds,
                cpuSeconds / Math.Max(0.001, timer.Elapsed.TotalSeconds) * 100,
                allocationBefore,
                Math.Max(0, GC.GetTotalAllocatedBytes(false) - allocationBefore),
                workingSetBefore,
                process.WorkingSet64,
                process.PeakWorkingSet64);
        var after = observability.GetIngestionDiagnosticsSnapshot();
        var processed = Math.Max(0, after.EventsProcessed - before.EventsProcessed);
        var dropped = Math.Max(0, after.EventsDropped - before.EventsDropped);
        var received = Math.Max(0, after.EventsReceived - before.EventsReceived);
        return new IngestionResult(
            received,
            acceptedLocally,
            processed,
            dropped,
            Math.Max(0, received - processed),
            observability.QueueHighWaterMark,
            timer.Elapsed.TotalSeconds,
            processed / Math.Max(0.001, timer.Elapsed.TotalSeconds),
            LatencyDistribution.From(measuredStore.EventLatencyMilliseconds),
            measuredStore.Repeated404Detections,
            resources);
    }

    private static async Task<QueueSaturationResult> RunQueueSaturationAsync(SqliteEventStore eventStore, int seed, int siteCount)
    {
        var offeredCount = 4_000;
        using var observability = new IisObservability();
        var measuredStore = new MeasuringEventStore(eventStore, blockFirstBatch: true);
        var pipeline = CreatePipeline(measuredStore, observability, new DetectionOptions(), SaturationQueueCapacity, SaturationBatchSize);
        var before = eventStore.GetIngestionDiagnostics();
        var processing = pipeline.ProcessAsync();
        var timer = Stopwatch.StartNew();
        var firstPayload = SyntheticTraffic.CreateRequests(1, seed + 1, siteCount, "queue")[0].ToPayload("queue-first");
        measuredStore.Track(firstPayload.Id, firstPayload.ReceivedTimestamp);
        _ = pipeline.TryEnqueue(firstPayload);
        if (!measuredStore.FirstBatchEntered.Wait(TimeSpan.FromSeconds(15)))
        {
            throw new TimeoutException("The queue saturation benchmark did not enter its delayed batch.");
        }

        var requests = SyntheticTraffic.CreateRequests(offeredCount - 1, seed + 2, siteCount, "queue");
        foreach (var request in requests)
        {
            var payload = request.ToPayload("queue");
            measuredStore.Track(payload.Id, payload.ReceivedTimestamp);
            if (!pipeline.TryEnqueue(payload))
            {
                measuredStore.Forget(payload.Id);
            }
        }

        pipeline.Complete();
        var recovery = Stopwatch.StartNew();
        measuredStore.ReleaseFirstBatch.Set();
        await processing.WaitAsync(TimeSpan.FromMinutes(2));
        recovery.Stop();
        timer.Stop();
        var after = observability.GetIngestionDiagnosticsSnapshot();
        return new QueueSaturationResult(
            Math.Max(0, after.EventsReceived - before.EventsReceived),
            Math.Max(0, after.EventsAccepted - before.EventsAccepted),
            Math.Max(0, after.EventsProcessed - before.EventsProcessed),
            Math.Max(0, after.EventsDropped - before.EventsDropped),
            observability.QueueHighWaterMark,
            timer.Elapsed.TotalSeconds,
            recovery.Elapsed.TotalMilliseconds);
    }

    private static async Task<SqliteContentionResult> RunSqliteContentionAsync(SqliteEventStore eventStore, string databasePath, int seed, int siteCount)
    {
        const double lockHoldMilliseconds = 250;
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWrite,
            DefaultTimeout = 2
        }.ToString());
        connection.Open();
        ExecuteSql(connection, "BEGIN IMMEDIATE;");

        using var observability = new IisObservability();
        var measuredStore = new MeasuringEventStore(eventStore);
        var pipeline = CreatePipeline(measuredStore, observability, new DetectionOptions(), 512, 64);
        var before = eventStore.GetIngestionDiagnostics();
        var processing = pipeline.ProcessAsync();
        var requests = SyntheticTraffic.CreateRequests(256, seed + 3, siteCount, "contention");
        foreach (var request in requests)
        {
            var payload = request.ToPayload("contention");
            measuredStore.Track(payload.Id, payload.ReceivedTimestamp);
            _ = pipeline.TryEnqueue(payload);
        }

        pipeline.Complete();
        if (!measuredStore.BatchWriteAttempted.Wait(TimeSpan.FromSeconds(15)))
        {
            ExecuteSql(connection, "ROLLBACK;");
            throw new TimeoutException("The SQLite contention benchmark did not reach the write attempt.");
        }

        await Task.Delay(TimeSpan.FromMilliseconds(lockHoldMilliseconds));
        var recovery = Stopwatch.StartNew();
        ExecuteSql(connection, "COMMIT;");
        await processing.WaitAsync(TimeSpan.FromMinutes(2));
        recovery.Stop();
        var after = observability.GetIngestionDiagnosticsSnapshot();
        return new SqliteContentionResult(
            lockHoldMilliseconds,
            Math.Max(0, after.EventsReceived - before.EventsReceived),
            Math.Max(0, after.EventsProcessed - before.EventsProcessed),
            Math.Max(0, after.EventsDropped - before.EventsDropped),
            recovery.Elapsed.TotalMilliseconds,
            LatencyDistribution.From(measuredStore.BatchWriteLatencyMilliseconds));
    }

    private static async Task<DashboardResult> RunDashboardBenchmarksAsync(
        SqliteEventStore eventStore,
        SqliteFindingStore findingStore,
        IIpAggregationService aggregationService,
        IBanCountService banCountService,
        IOptions<StorageOptions> storageOptions,
        IHostEnvironment environment,
        string databasePath,
        int seed,
        int siteCount)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Production",
            ContentRootPath = environment.ContentRootPath
        });
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.WebHost.UseTestServer();
        builder.Services.AddAuthorization(options =>
            options.AddPolicy("DashboardAdministrator", policy => policy.RequireAssertion(static _ => true)));
        using var dashboardObservability = new IisObservability();
        builder.Services.AddSingleton(dashboardObservability);
        builder.Services.AddSingleton<IEventStore>(eventStore);
        builder.Services.AddSingleton<IAnalystIncidentStore>(_ => null!);
        builder.Services.AddSingleton<IIpAggregationService>(aggregationService);
        builder.Services.AddSingleton<IBanCountService>(banCountService);
        builder.Services.AddSingleton<IDenyListStore>(_ => null!);
        builder.Services.AddSingleton<IIisDenyListService>(_ => null!);
        builder.Services.AddSingleton<IIisSiteDiscoveryService>(_ => null!);
        builder.Services.AddSingleton<IIpAllowList>(_ => null!);
        builder.Services.AddSingleton<SqliteHealthProbe>(_ => null!);
        builder.Services.AddOptions<IisAdminOptions>();
        builder.Services.AddSingleton(findingStore);
        builder.Services.AddSingleton(storageOptions);
        builder.Services.AddSingleton(environment);
        await using var app = builder.Build();
        app.MapDashboardEndpoints(new JsonSerializerOptions(JsonSerializerDefaults.Web));
        await app.StartAsync();
        using var client = app.GetTestClient();
        var latencySamples = new ConcurrentBag<double>();
        var queryTimer = Stopwatch.StartNew();
        await Task.WhenAll(Enumerable.Range(0, ApiWorkerCount).Select(async worker =>
        {
            for (var index = 0; index < ApiRequestsPerWorker; index++)
            {
                var query = (index % 3) switch
                {
                    0 => $"/api/events?limit=100&domain=site-{worker % siteCount:D2}.example.test",
                    1 => $"/api/events?limit=100&clientIp=198.18.0.{worker + 1}",
                    _ => "/api/events?limit=100&suspiciousOnly=true"
                };
                var timer = Stopwatch.StartNew();
                using var response = await client.GetAsync(query);
                _ = await response.Content.ReadAsByteArrayAsync();
                response.EnsureSuccessStatusCode();
                timer.Stop();
                latencySamples.Add(timer.Elapsed.TotalMilliseconds);
            }
        }));
        queryTimer.Stop();
        var queryLatency = LatencyDistribution.From(latencySamples);
        var queryResult = new ApiOperationResult(
            ApiWorkerCount * ApiRequestsPerWorker,
            queryTimer.Elapsed.TotalSeconds,
            ApiWorkerCount * ApiRequestsPerWorker / queryTimer.Elapsed.TotalSeconds,
            queryLatency,
            0,
            queryLatency.P95Milliseconds);
        var eventJsonExport = await MeasureEndpointAsync(client, "/api/export/events?limit=5000&format=json");
        var eventCsvExport = await MeasureEndpointAsync(client, "/api/export/events?limit=5000&format=csv");
        var findingsExport = await MeasureEndpointAsync(client, "/api/export/findings?limit=500&domain=site-00.example.test");

        using var sseCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var connections = new List<SseConnection>(SseClientCount);
        try
        {
            for (var clientIndex = 0; clientIndex < SseClientCount; clientIndex++)
            {
                var response = await client.SendAsync(
                    new HttpRequestMessage(HttpMethod.Get, "/api/events/stream"),
                    HttpCompletionOption.ResponseHeadersRead,
                    sseCancellation.Token);
                response.EnsureSuccessStatusCode();
                var reader = new StreamReader(await response.Content.ReadAsStreamAsync(sseCancellation.Token));
                while (await reader.ReadLineAsync(sseCancellation.Token) is { Length: > 0 })
                {
                }

                connections.Add(new SseConnection(response, reader));
            }

            var sseStart = Stopwatch.GetTimestamp();
            eventStore.Publish(CreateSseEvent(seed));
            var sseLatencies = await Task.WhenAll(connections.Select(async connection =>
            {
                while (await connection.Reader.ReadLineAsync(sseCancellation.Token) is { } line)
                {
                    if (line == "event: etw")
                    {
                        _ = await connection.Reader.ReadLineAsync(sseCancellation.Token);
                        return Stopwatch.GetElapsedTime(sseStart).TotalMilliseconds;
                    }
                }

                throw new EndOfStreamException("An SSE client disconnected before receiving its event.");
            })).WaitAsync(TimeSpan.FromSeconds(20));
            return new DashboardResult(
                queryResult,
                eventJsonExport,
                eventCsvExport,
                findingsExport,
                SseClientCount,
                LatencyDistribution.From(sseLatencies));
        }
        finally
        {
            sseCancellation.Cancel();
            foreach (var connection in connections)
            {
                connection.Reader.Dispose();
                connection.Response.Dispose();
            }
        }
    }

    private static async Task<ApiOperationResult> MeasureEndpointAsync(HttpClient client, string path)
    {
        var timer = Stopwatch.StartNew();
        using var response = await client.GetAsync(path);
        var bytes = await response.Content.ReadAsByteArrayAsync();
        response.EnsureSuccessStatusCode();
        timer.Stop();
        return new ApiOperationResult(1, timer.Elapsed.TotalSeconds, 1 / timer.Elapsed.TotalSeconds,
            LatencyDistribution.From([timer.Elapsed.TotalMilliseconds]), bytes.Length, timer.Elapsed.TotalMilliseconds);
    }

    private static EtwIngestionPipeline CreatePipeline(
        IEventStore store,
        IisObservability observability,
        DetectionOptions detectionOptions,
        int queueCapacity,
        int batchSize)
    {
        var detector = new SuspiciousActivityDetector(Options.Create(detectionOptions), store, observability);
        return new EtwIngestionPipeline(
            store,
            detector,
            new NullAutoDenyService(),
            observability,
            Options.Create(new IisEtwOptions
            {
                IngestionBufferSize = queueCapacity,
                ProcessingBatchSize = batchSize,
                SubscriptionBufferSize = queueCapacity
            }),
            NullLogger<EtwIngestionPipeline>.Instance);
    }

    private static SecurityEvent CreateSseEvent(int seed)
        => new(DateTimeOffset.UtcNow, "benchmark-server", "site-00.example.test", "GET", $"/sse/{seed}", "198.18.0.1", 200, "synthetic-browser", new Dictionary<string, string>())
        {
            Id = $"sse-{seed:D8}"
        };

    private static long GetDatabaseBytes(string databasePath)
        => new[] { databasePath, databasePath + "-wal", databasePath + "-shm" }
            .Where(File.Exists)
            .Sum(path => new FileInfo(path).Length);

    private static long GetRetainedEventCount(string databasePath)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            DefaultTimeout = 5
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM events;";
        return (long)(command.ExecuteScalar() ?? 0L);
    }

    private static void CheckpointWal(string databasePath)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWrite,
            DefaultTimeout = 5
        }.ToString());
        connection.Open();
        ExecuteSql(connection, "PRAGMA wal_checkpoint(TRUNCATE);");
    }

    private static void ExecuteSql(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static async Task<string> GetGitValueAsync(string workingDirectory, params string[] arguments)
    {
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo("git")
            {
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            foreach (var argument in arguments)
            {
                process.StartInfo.ArgumentList.Add(argument);
            }

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return process.ExitCode == 0 ? output.Trim() : "unavailable";
        }
        catch (Exception)
        {
            return "unavailable";
        }
    }

    private static async Task<bool> IsWorkingTreeDirtyAsync(string workingDirectory)
        => !string.IsNullOrWhiteSpace(await GetGitValueAsync(workingDirectory, "status", "--porcelain"));

    private sealed record SseConnection(HttpResponseMessage Response, StreamReader Reader);
}

sealed class MeasuringEventStore(IEventStore inner, bool blockFirstBatch = false) : IEventStore
{
    private readonly ConcurrentDictionary<string, long> _enqueueTimestamps = new(StringComparer.Ordinal);
    private readonly ConcurrentBag<double> _eventLatencies = [];
    private readonly ConcurrentBag<double> _batchWriteLatencies = [];
    private int _firstBatchPending = blockFirstBatch ? 1 : 0;
    private long _repeated404Detections;
    public ManualResetEventSlim FirstBatchEntered { get; } = new(false);
    public ManualResetEventSlim BatchWriteAttempted { get; } = new(false);
    public ManualResetEventSlim ReleaseFirstBatch { get; } = new(false);
    public long Repeated404Detections => Interlocked.Read(ref _repeated404Detections);
    public ConcurrentBag<double> EventLatencyMilliseconds => _eventLatencies;
    public ConcurrentBag<double> BatchWriteLatencyMilliseconds => _batchWriteLatencies;

    public void Track(string eventId, long timestamp) => _enqueueTimestamps[eventId] = timestamp;
    public void Forget(string eventId) => _enqueueTimestamps.TryRemove(eventId, out _);

    public IReadOnlyList<SecurityEvent> GetRecent(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
        => inner.GetRecent(limit, clientIp, domain, suspiciousOnly);

    public void Publish(SecurityEvent webEvent) => PublishBatch([webEvent]);

    public IReadOnlyList<SecurityEvent> PublishBatch(IReadOnlyList<SecurityEvent> webEvents)
    {
        if (Interlocked.Exchange(ref _firstBatchPending, 0) == 1)
        {
            FirstBatchEntered.Set();
            if (!ReleaseFirstBatch.Wait(TimeSpan.FromSeconds(30)))
            {
                throw new TimeoutException("The benchmark did not release the delayed persistence batch.");
            }
        }

        BatchWriteAttempted.Set();
        var timer = Stopwatch.StartNew();
        var inserted = inner.PublishBatch(webEvents);
        timer.Stop();
        _batchWriteLatencies.Add(timer.Elapsed.TotalMilliseconds);
        var publishedAt = Stopwatch.GetTimestamp();
        foreach (var webEvent in webEvents)
        {
            if (_enqueueTimestamps.TryRemove(webEvent.Id, out var enqueuedAt))
            {
                _eventLatencies.Add(Stopwatch.GetElapsedTime(enqueuedAt, publishedAt).TotalMilliseconds);
            }

            if (webEvent.RiskIndicators?.Any(static indicator => indicator.Contains("multiple 404 responses", StringComparison.OrdinalIgnoreCase)) == true)
            {
                Interlocked.Increment(ref _repeated404Detections);
            }
        }

        return inserted;
    }

    public IngestionDiagnosticsSnapshot GetIngestionDiagnostics() => inner.GetIngestionDiagnostics();
    public void SaveIngestionDiagnosticsSidecar(IngestionDiagnosticsSnapshot snapshot) => inner.SaveIngestionDiagnosticsSidecar(snapshot);
    public void SaveIngestionDiagnostics(IngestionDiagnosticsSnapshot snapshot) => inner.SaveIngestionDiagnostics(snapshot);
    public System.Threading.Channels.ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken)
        => inner.Subscribe(cancellationToken);
}

static class SyntheticTraffic
{
    public static IReadOnlyList<SyntheticRequest> CreateRequests(int count, int seed, int siteCount, string idPrefix = "sustained")
    {
        var random = new Random(seed);
        var attackCount = Math.Max(4, count / 10);
        var ipCardinality = Math.Max(100, Math.Min(40_000, count * 3 / 4));
        var pathCardinality = Math.Max(100, Math.Min(12_000, count * 4 / 5));
        var requests = new SyntheticRequest[count];
        for (var index = 0; index < count; index++)
        {
            var isRepeated404 = index < attackCount;
            var site = isRepeated404 ? 0 : index % siteCount;
            var ipIndex = isRepeated404 ? 77 : random.Next(ipCardinality);
            var pathIndex = isRepeated404 ? index : random.Next(pathCardinality);
            var status = isRepeated404 ? 404 : random.Next(100) switch
            {
                < 2 => 404,
                < 3 => 500,
                _ => 200
            };
            var path = isRepeated404 ? $"/missing/resource-{index:D6}" : $"/catalog/item-{pathIndex:D6}";
            requests[index] = new SyntheticRequest(
                $"{idPrefix}-{index:D8}",
                site,
                $"site-{site:D2}.example.test",
                $"198.18.{ipIndex / 254}.{ipIndex % 254 + 1}",
                index % 13 == 0 ? "POST" : "GET",
                path,
                status,
                random.Next(200) == 0 ? "synthetic-vulnerability-scanner" : "synthetic-browser/1.0");
        }

        return requests;
    }
}

sealed record SyntheticRequest(
    string Id,
    int SiteIndex,
    string Domain,
    string ClientIp,
    string Method,
    string Path,
    int StatusCode,
    string UserAgent)
{
    public EtwEventPayload ToPayload(string idSuffix)
        => new(DateTimeOffset.UtcNow, Id + idSuffix, Stopwatch.GetTimestamp(), new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ServerName"] = "synthetic-iis-01",
            ["SiteName"] = $"site-{SiteIndex:D2}",
            ["Host"] = Domain,
            ["Method"] = Method,
            ["Path"] = Path,
            ["ClientIP"] = ClientIp,
            ["StatusCode"] = StatusCode.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["UserAgent"] = UserAgent
        });
}

sealed class BenchmarkHostEnvironment(string contentRootPath) : IHostEnvironment
{
    public string EnvironmentName { get; set; } = "Production";
    public string ApplicationName { get; set; } = "iisidsd.Performance";
    public string ContentRootPath { get; set; } = contentRootPath;
    public IFileProvider ContentRootFileProvider { get; set; } = new PhysicalFileProvider(contentRootPath);
}

sealed class NullAutoDenyService : IIisAutoDenyService
{
    public void Apply(SecurityEvent securityEvent) { }
}

static class DatasetSummary
{
    public static DatasetResult From(IReadOnlyList<SyntheticRequest> requests)
    {
        var attackRequests = Math.Max(4, requests.Count / 10);
        return new DatasetResult(
            requests.Count,
            requests.Select(static request => request.ClientIp).Distinct(StringComparer.Ordinal).Count(),
            requests.Select(static request => request.Path).Distinct(StringComparer.Ordinal).Count(),
            requests.Select(static request => request.Domain).Distinct(StringComparer.Ordinal).Count(),
            attackRequests,
            0);
    }
}

sealed record BenchmarkArguments(int? EventCount, string? OutputPath, string? ComparePath)
{
    public static BenchmarkArguments Parse(string[] args)
    {
        int? eventCount = null;
        string? outputPath = null;
        string? comparePath = null;
        for (var index = 0; index < args.Length; index++)
        {
            var value = args[index];
            switch (value)
            {
                case "--events" when index + 1 < args.Length && int.TryParse(args[++index], out var parsedEvents):
                    eventCount = parsedEvents;
                    break;
                case "--output" when index + 1 < args.Length:
                    outputPath = args[++index];
                    break;
                case "--compare" when index + 1 < args.Length:
                    comparePath = args[++index];
                    break;
                default:
                    throw new ArgumentException($"Unknown or incomplete benchmark argument '{value}'.");
            }
        }

        return new BenchmarkArguments(eventCount, outputPath, comparePath);
    }
}

sealed record LatencyDistribution(int SampleCount, double P50Milliseconds, double P95Milliseconds, double P99Milliseconds)
{
    public static LatencyDistribution From(IEnumerable<double> values)
    {
        var sorted = values.Order().ToArray();
        return new LatencyDistribution(sorted.Length, Percentile(sorted, 0.50), Percentile(sorted, 0.95), Percentile(sorted, 0.99));
    }

    private static double Percentile(double[] sorted, double percentile)
    {
        if (sorted.Length == 0)
        {
            return 0;
        }

        var index = Math.Clamp((int)Math.Ceiling(percentile * sorted.Length) - 1, 0, sorted.Length - 1);
        return sorted[index];
    }
}

sealed record BenchmarkEnvironment(
    string MachineName,
    string ProcessorIdentifier,
    int LogicalProcessorCount,
    long AvailableMemoryBytes,
    string OperatingSystem,
    string ProcessArchitecture,
    string Runtime,
    string DotnetVersion);

sealed record BenchmarkConfiguration(
    int Seed,
    int RequestedEvents,
    int SiteCount,
    int ClientIpCardinality,
    int PathCardinality,
    int SustainedQueueCapacity,
    int SaturationQueueCapacity,
    int SaturationBatchSize,
    int SustainedRateEventsPerSecond,
    int BurstSize,
    int BatchSize,
    string JournalMode,
    string SynchronousMode,
    int BusyTimeoutSeconds,
    int EventRetentionLimit);

sealed record DatasetResult(
    int EventCount,
    int UniqueClientIps,
    int UniquePaths,
    int UniqueDomains,
    int Repeated404Requests,
    long Repeated404Detected);

sealed record IngestionResult(
    long ReceivedEvents,
    long AcceptedEvents,
    long ProcessedEvents,
    long DroppedEvents,
    long LostEvents,
    long QueueHighWaterMark,
    double DurationSeconds,
    double EventsPerSecond,
    LatencyDistribution EndToEndLatency,
    long Repeated404Detections,
    ResourceResult? Resources);

sealed record ResourceResult(
    double CpuSeconds,
    double CpuPercentOfOneCore,
    long AllocatedBytesBefore,
    long ManagedAllocatedBytes,
    long WorkingSetBeforeBytes,
    long WorkingSetAfterBytes,
    long PeakWorkingSetBytes);

sealed record DatabaseResult(
    long InitialBytes,
    long AfterSustainedIngestionBytes,
    long FinalBytes,
    long GrowthBytes,
    double GrowthBytesPerEvent,
    double GrowthBytesPerSecond,
    long RetainedEvents);

sealed record ApiOperationResult(
    int RequestCount,
    double DurationSeconds,
    double RequestsPerSecond,
    LatencyDistribution Latency,
    long ResponseBytes,
    double LatencyMilliseconds);

sealed record DashboardResult(
    ApiOperationResult ConcurrentQueries,
    ApiOperationResult EventJsonExport,
    ApiOperationResult EventCsvExport,
    ApiOperationResult FindingsExport,
    int SseClientCount,
    LatencyDistribution SseDeliveryLatency);

sealed record QueueSaturationResult(
    long ReceivedEvents,
    long AcceptedEvents,
    long ProcessedEvents,
    long DroppedEvents,
    long QueueHighWaterMark,
    double DurationSeconds,
    double RecoveryMilliseconds);

sealed record SqliteContentionResult(
    double LockHoldMilliseconds,
    long ReceivedEvents,
    long ProcessedEvents,
    long DroppedEvents,
    double RecoveryMilliseconds,
    LatencyDistribution BatchWriteLatency);

sealed record ComparisonMetric(string Name, double PreviousValue, double CurrentValue, double ChangePercent);
sealed record BenchmarkComparison(string PreviousVersion, string PreviousRevision, bool HardwareComparable, bool RuntimeComparable, bool ConfigurationComparable, IReadOnlyList<ComparisonMetric> Metrics);

sealed record BenchmarkReport(
    DateTimeOffset GeneratedAtUtc,
    string ApplicationVersion,
    string SourceRevision,
    bool WorkingTreeDirty,
    BenchmarkEnvironment Environment,
    BenchmarkConfiguration Configuration,
    DatasetResult Dataset,
    IngestionResult SustainedIngestion,
    IngestionResult BurstIngestion,
    ResourceResult Resources,
    DatabaseResult Database,
    DashboardResult Dashboard,
    QueueSaturationResult QueueSaturation,
    SqliteContentionResult SqliteContention,
    BenchmarkComparison? Comparison);