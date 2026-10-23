using System.Diagnostics;
using System.Threading.Channels;
using iisidsd.Configuration;
using iisidsd.Detection;
using iisidsd.Etw;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Etw;

public sealed class EtwIngestionPipelineTests
{
    [Fact]
    public async Task FullQueue_DropsNewestAndReportsDepthAndHighWater()
    {
        using var observability = new IisObservability();
        var store = new FakeEventStore();
        var pipeline = CreatePipeline(store, observability, capacity: 2, batchSize: 1);

        Assert.True(pipeline.TryEnqueue(CreatePayload("one")));
        Assert.True(pipeline.TryEnqueue(CreatePayload("two")));
        Assert.False(pipeline.TryEnqueue(CreatePayload("three")));
        Assert.Equal(2, observability.QueueDepth);
        Assert.Equal(2, observability.QueueHighWaterMark);
        Assert.Equal(2, observability.EtwEventsAccepted);
        Assert.Equal(1, observability.EtwEventsDropped);

        pipeline.Complete();
        await pipeline.ProcessAsync();

        Assert.Equal(2, store.Events.Count);
        Assert.Equal(0, observability.QueueDepth);
    }

    [Fact]
    public async Task MalformedAndPoisonEvents_AreIsolatedAndFollowingEventsContinue()
    {
        using var observability = new IisObservability();
        var store = new FakeEventStore();
        var detector = new FakeDetector
        {
            AnalyzeEvent = webEvent => webEvent.Path == "/poison"
                ? throw new InvalidOperationException("synthetic detector fault")
                : webEvent
        };
        var pipeline = CreatePipeline(store, observability, detector: detector, batchSize: 4);
        var malformed = CreatePayload("malformed") with { Properties = new Dictionary<string, string>() };

        Assert.True(pipeline.TryEnqueue(malformed));
        Assert.True(pipeline.TryEnqueue(CreatePayload("poison", "/poison")));
        Assert.True(pipeline.TryEnqueue(CreatePayload("healthy")));
        pipeline.Complete();
        await pipeline.ProcessAsync();

        Assert.Equal(new[] { "healthy" }, store.Events.Select(static item => item.Id));
        Assert.Equal(1, observability.EtwEventsMalformed);
        Assert.Equal(1, observability.EventProcessingFailures);
        Assert.Equal(1, observability.EventsProcessed);
    }

    [Fact]
    public async Task ObservationOnlyEvidence_IsPersistedWithoutMarkingEventSuspicious()
    {
        using var observability = new IisObservability();
        var store = new FakeEventStore();
        var evidence = new DetectionEvidence(
            DetectionSignalCode.Custom,
            DetectionEvidenceFamily.PathContent,
            "observed indicator",
            8,
            0,
            false,
            DetectorId: "optional-detector",
            SignalKey: "optional.signal",
            Explanation: "The optional detector saw a pattern.",
            ObserveOnly: true);
        var detector = new FakeDetector
        {
            AnalyzeEvent = static _ => null,
            Assessment = new(null, DetectionEvidenceScope.None, DetectionEvidenceStrength.None, 0, [evidence])
        };
        var pipeline = CreatePipeline(store, observability, detector);
        Assert.True(pipeline.TryEnqueue(CreatePayload("observe-only")));
        pipeline.Complete();
        await pipeline.ProcessAsync();

        var persistedEvent = Assert.Single(store.Events);
        Assert.False(persistedEvent.IsSuspicious);
        Assert.Equal(0, persistedEvent.RiskScore);
        Assert.Equal(evidence, Assert.Single(persistedEvent.DetectionEvidence ?? []));
    }

    [Fact]
    public async Task SlowPersistence_SaturatesBoundedQueueThenRecoversWithoutLosingAcceptedEvents()
    {
        using var observability = new IisObservability();
        using var store = new FakeEventStore { BlockNextBatch = true };
        var pipeline = CreatePipeline(store, observability, capacity: 2, batchSize: 1);
        Assert.True(pipeline.TryEnqueue(CreatePayload("first")));

        var processing = Task.Run(pipeline.ProcessAsync);
        Assert.True(store.BatchEntered.Wait(TimeSpan.FromSeconds(5)));
        Assert.True(pipeline.TryEnqueue(CreatePayload("second")));
        Assert.True(pipeline.TryEnqueue(CreatePayload("third")));
        Assert.False(pipeline.TryEnqueue(CreatePayload("fourth")));
        pipeline.Complete();
        store.ReleaseBatch.Set();
        await processing.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(new[] { "first", "second", "third" }, store.Events.Select(static item => item.Id));
        Assert.Equal(3, observability.EventsProcessed);
        Assert.Equal(1, observability.EtwEventsDropped);
        Assert.Equal(0, observability.QueueDepth);
    }

    [Fact]
    public async Task CompletionDrainsAcceptedEvents_EvenWhenShutdownCancellationWasRequested()
    {
        using var observability = new IisObservability();
        var store = new FakeEventStore();
        var pipeline = CreatePipeline(store, observability, batchSize: 2);
        using var shutdown = new CancellationTokenSource();
        Assert.True(pipeline.TryEnqueue(CreatePayload("one")));
        Assert.True(pipeline.TryEnqueue(CreatePayload("two")));
        shutdown.Cancel();
        pipeline.Complete();

        await pipeline.ProcessAsync();

        Assert.Equal(2, store.Events.Count);
        Assert.Equal(2, observability.EventsProcessed);
        Assert.Equal(0, observability.QueueDepth);
    }

    [Fact]
    public async Task TransientSqliteFailure_RetriesSameStableEventsWithoutDuplicatePublication()
    {
        using var observability = new IisObservability();
        var store = new FakeEventStore { TransientFailuresRemaining = 2 };
        var pipeline = CreatePipeline(
            store,
            observability,
            batchSize: 4,
            isTransientStoreFailure: static exception => exception is IOException);
        Assert.True(pipeline.TryEnqueue(CreatePayload("retry-me")));
        pipeline.Complete();

        await pipeline.ProcessAsync();

        Assert.Equal(3, store.BatchCalls);
        Assert.Single(store.Events);
        Assert.Single(store.PublishedEvents);
        Assert.Equal(2, observability.EventProcessingRetries);
        Assert.Equal(1, observability.EventsProcessed);
        var diagnostics = observability.GetOperationalDiagnosticsSnapshot("test", "test");
        Assert.Equal(1, diagnostics.DetectionEventsAnalyzed);
        Assert.Equal(2, diagnostics.RecoveryAttempts);
        Assert.All(diagnostics.RecentOperationalEvents, operationalEvent =>
        {
            Assert.Equal("sqlite", operationalEvent.Component);
            Assert.Equal("recovery", operationalEvent.Kind);
            Assert.Equal("IOException", operationalEvent.FailureType);
        });
    }

    private static EtwIngestionPipeline CreatePipeline(
        FakeEventStore store,
        IisObservability observability,
        FakeDetector? detector = null,
        int capacity = 16,
        int batchSize = 4,
        Func<Exception, bool>? isTransientStoreFailure = null)
        => new(
            store,
            detector ?? new FakeDetector(),
            new FakeAutoDenyService(),
            observability,
            Options.Create(new IisEtwOptions
            {
                IngestionBufferSize = capacity,
                ProcessingBatchSize = batchSize
            }),
            NullLogger<EtwIngestionPipeline>.Instance,
            isTransientStoreFailure);

    private static EtwEventPayload CreatePayload(string id, string path = "/health")
        => new(
            DateTimeOffset.UtcNow,
            id,
            Stopwatch.GetTimestamp(),
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["csuristem"] = path,
                ["scstatus"] = "200",
                ["csmethod"] = "GET",
                ["cip"] = "203.0.113.10",
                ["cshost"] = "example.test"
            });

    private sealed class FakeDetector : ISuspiciousActivityDetector
    {
        public Func<SecurityEvent, SecurityEvent?> AnalyzeEvent { get; init; } = static webEvent => webEvent;
        public DetectionAssessment? Assessment { get; init; }
        public SecurityEvent? Analyze(SecurityEvent webEvent) => AnalyzeEvent(webEvent);
        public DetectionAssessment AnalyzeDetailed(SecurityEvent webEvent)
            => Assessment ?? new(AnalyzeEvent(webEvent), DetectionEvidenceScope.None, DetectionEvidenceStrength.None, 0, []);
    }

    private sealed class FakeAutoDenyService : IIisAutoDenyService
    {
        public void Apply(SecurityEvent securityEvent) { }
    }

    private sealed class FakeEventStore : IEventStore, IDisposable
    {
        private readonly HashSet<string> _eventIds = new(StringComparer.Ordinal);
        private readonly Channel<SecurityEvent> _published = Channel.CreateUnbounded<SecurityEvent>();
        private readonly object _sync = new();
        private IngestionDiagnosticsSnapshot _diagnostics = new(0, 0, 0, 0, 0, 0, 0, 0);

        public List<SecurityEvent> Events { get; } = [];
        public List<SecurityEvent> PublishedEvents { get; } = [];
        public int BatchCalls { get; private set; }
        public int TransientFailuresRemaining { get; set; }
        public bool BlockNextBatch { get; set; }
        public ManualResetEventSlim BatchEntered { get; } = new(false);
        public ManualResetEventSlim ReleaseBatch { get; } = new(false);

        public IReadOnlyList<SecurityEvent> GetRecent(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
            => Events.TakeLast(limit).ToArray();

        public void Publish(SecurityEvent webEvent) => PublishBatch([webEvent]);

        public IReadOnlyList<SecurityEvent> PublishBatch(IReadOnlyList<SecurityEvent> webEvents)
        {
            BatchCalls++;
            if (BlockNextBatch)
            {
                BlockNextBatch = false;
                BatchEntered.Set();
                if (!ReleaseBatch.Wait(TimeSpan.FromSeconds(10)))
                {
                    throw new TimeoutException("The test did not release its blocked persistence call.");
                }
            }

            if (TransientFailuresRemaining > 0)
            {
                TransientFailuresRemaining--;
                throw new IOException("Synthetic temporary storage outage.");
            }

            var inserted = new List<SecurityEvent>();
            lock (_sync)
            {
                foreach (var webEvent in webEvents)
                {
                    if (!_eventIds.Add(webEvent.Id))
                    {
                        continue;
                    }

                    Events.Add(webEvent);
                    PublishedEvents.Add(webEvent);
                    _published.Writer.TryWrite(webEvent);
                    inserted.Add(webEvent);
                }
            }

            return inserted;
        }

        public IngestionDiagnosticsSnapshot GetIngestionDiagnostics() => _diagnostics;
        public void SaveIngestionDiagnostics(IngestionDiagnosticsSnapshot snapshot) => _diagnostics = snapshot;
        public ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken) => _published.Reader;
        public void Dispose()
        {
            BatchEntered.Dispose();
            ReleaseBatch.Dispose();
        }
    }
}
