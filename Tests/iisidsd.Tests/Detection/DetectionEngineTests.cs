using iisidsd.Detection;
using iisidsd.Models;
using iisidsd.Observability;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Detection;

public sealed class DetectionEngineTests
{
    [Fact]
    public void AnalyzeDetailed_DefaultHeuristicPolicyPreservesLegacyScoring()
    {
        var detectionOptions = Options.Create(new DetectionOptions
        {
            SuspiciousPathFragments = ["../"],
            ScannerUserAgents = ["scanner"],
            RateThreshold = int.MaxValue,
            PathScanUniquePathThreshold = int.MaxValue
        });
        var webEvent = CreateEvent("TRACE", "/../private", 404, "scanner/1.0");
        var legacy = new SuspiciousActivityDetector(detectionOptions).AnalyzeDetailed(webEvent);
        var engine = CreateEngine([new SuspiciousActivityDetector(detectionOptions)]);

        var composed = engine.AnalyzeDetailed(webEvent);

        Assert.Equal(legacy.Event?.RiskScore, composed.Event?.RiskScore);
        Assert.Equal(legacy.Event?.RiskSeverity, composed.Event?.RiskSeverity);
        Assert.Equal(legacy.Event?.DetectionReason, composed.Event?.DetectionReason);
        Assert.Equal(legacy.Event?.RiskIndicators, composed.Event?.RiskIndicators);
        Assert.Equal(legacy.Evidence.Select(static evidence => (evidence.Code, evidence.Family, evidence.Contributed)),
            composed.Evidence.Select(static evidence => (evidence.Code, evidence.Family, evidence.Contributed)));
    }

    [Fact]
    public void AnalyzeDetailed_DeduplicatesSharedSignalsAndSelectsFamilyWinnersDeterministically()
    {
        var alpha = new FakeModule("alpha",
        [
            Signal("shared-a", "shared.http.signal", DetectionEvidenceFamily.PathContent, "alpha evidence", 5),
            Signal("weak-method", null, DetectionEvidenceFamily.RequestMethod, "weak method evidence", 2)
        ]);
        var beta = new FakeModule("beta",
        [
            Signal("shared-b", "shared.http.signal", DetectionEvidenceFamily.PathContent, "beta evidence", 5),
            Signal("strong-method", null, DetectionEvidenceFamily.RequestMethod, "strong method evidence", 4)
        ]);

        var moduleOptions = Policies(("alpha", DetectionModuleMode.Contribute), ("beta", DetectionModuleMode.Contribute));
        var first = CreateEngine([beta, alpha], moduleOptions).AnalyzeDetailed(CreateEvent());
        var second = CreateEngine([alpha, beta], moduleOptions).AnalyzeDetailed(CreateEvent());

        Assert.Equal(9, first.Event?.RiskScore);
        Assert.Equal(first.Event?.RiskScore, second.Event?.RiskScore);
        Assert.Equal(first.Event?.RiskIndicators, second.Event?.RiskIndicators);
        Assert.Equal(
            first.Evidence.Select(static evidence => (evidence.DetectorId, evidence.SignalKey, evidence.Contributed)),
            second.Evidence.Select(static evidence => (evidence.DetectorId, evidence.SignalKey, evidence.Contributed)));
        Assert.True(Assert.Single(first.Evidence, static evidence => evidence.DetectorId == "alpha" && evidence.SignalKey == "shared-a").Contributed);
        Assert.False(Assert.Single(first.Evidence, static evidence => evidence.DetectorId == "beta" && evidence.SignalKey == "shared-b").Contributed);
        Assert.True(Assert.Single(first.Evidence, static evidence => evidence.SignalKey == "strong-method").Contributed);
        Assert.False(Assert.Single(first.Evidence, static evidence => evidence.SignalKey == "weak-method").Contributed);
    }

    [Fact]
    public void AnalyzeDetailed_UnconfiguredModuleRunsInObservationModeWithoutChangingEvent()
    {
        var module = new FakeModule("optional",
            [Signal("optional-signal", null, DetectionEvidenceFamily.PathContent, "observed signal", 99)]);
        var assessment = CreateEngine([module]).AnalyzeDetailed(CreateEvent());

        Assert.Null(assessment.Event);
        var evidence = Assert.Single(assessment.Evidence);
        Assert.Equal("optional", evidence.DetectorId);
        Assert.Equal("optional-signal", evidence.SignalKey);
        Assert.True(evidence.ObserveOnly);
        Assert.False(evidence.Contributed);
        Assert.Equal(0, evidence.ScoreContribution);
    }

    [Fact]
    public void AnalyzeDetailed_ModuleFailureDoesNotSuppressOtherDetectors()
    {
        var failing = new FakeModule("broken", [], throwOnDetect: true);
        var working = new FakeModule("working",
            [Signal("working-signal", null, DetectionEvidenceFamily.PathContent, "working signal", 5)]);

        var assessment = CreateEngine(
            [failing, working],
            Policies(("broken", DetectionModuleMode.Contribute), ("working", DetectionModuleMode.Contribute)))
            .AnalyzeDetailed(CreateEvent());

        Assert.Equal(5, assessment.Event?.RiskScore);
        Assert.DoesNotContain(assessment.Evidence, static evidence => evidence.DetectorId == "broken");
        Assert.Contains(assessment.Evidence, static evidence => evidence.DetectorId == "working" && evidence.Contributed);
    }

    [Fact]
    public void AnalyzeDetailed_ReportsModuleHealthProcessingAndSignalMetrics()
    {
        using var observability = new IisObservability();
        var broken = new FakeModule("broken", [], throwOnDetect: true);
        var working = new FakeModule("working",
            [Signal("working-signal", null, DetectionEvidenceFamily.PathContent, "working signal", 5)]);
        var engine = new DetectionEngine(
            [broken, working],
            Options.Create(Policies(("broken", DetectionModuleMode.Contribute))),
            observability);

        _ = engine.AnalyzeDetailed(CreateEvent());

        var snapshot = observability.GetOperationalDiagnosticsSnapshot("0.2.3", "revision");
        Assert.NotNull(snapshot.DetectionModules);
        var brokenHealth = Assert.Single(snapshot.DetectionModules, static module => module.Id == "broken");
        Assert.Equal("degraded", brokenHealth.Status);
        Assert.Equal(1, brokenHealth.EvaluationCount);
        Assert.Equal(1, brokenHealth.FailureCount);
        Assert.Equal("InvalidOperationException", brokenHealth.LastFailureType);
        var workingHealth = Assert.Single(snapshot.DetectionModules, static module => module.Id == "working");
        Assert.Equal("healthy", workingHealth.Status);
        Assert.Equal("observe", workingHealth.Mode);
        Assert.Equal(1, workingHealth.SignalCounts["working-signal"]);
        Assert.NotNull(workingHealth.LastProcessingMilliseconds);

        var metrics = observability.RenderPrometheus();
        Assert.Contains("detection_module_failures_total{detector=\"broken\"} 1", metrics);
        Assert.Contains("detection_module_healthy{detector=\"working\"} 1", metrics);
        Assert.Contains("detection_module_signal_observations_total{detector=\"working\",signal=\"working-signal\"} 1", metrics);
    }

    [Fact]
    public void Constructor_RejectsDuplicateOrUnknownModuleConfiguration()
    {
        var duplicateModules = new IDetectionModule[]
        {
            new FakeModule("duplicate", []),
            new FakeModule("duplicate", [])
        };
        Assert.Throws<InvalidOperationException>(() => CreateEngine(duplicateModules));

        var options = new DetectionModulesOptions();
        options.Modules["missing"] = new DetectionModuleSettings();
        Assert.Throws<InvalidOperationException>(() => CreateEngine([new FakeModule("present", [])], options));
    }

    private static DetectionEngine CreateEngine(
        IEnumerable<IDetectionModule> modules,
        DetectionModulesOptions? options = null)
        => new(modules, Options.Create(options ?? new DetectionModulesOptions()));

    private static DetectionModulesOptions Policies(params (string Id, DetectionModuleMode Mode)[] policies)
    {
        var options = new DetectionModulesOptions();
        foreach (var (id, mode) in policies)
        {
            options.Modules[id] = new DetectionModuleSettings { Enabled = true, Mode = mode };
        }

        return options;
    }

    private static DetectionSignal Signal(
        string key,
        string? correlationKey,
        DetectionEvidenceFamily family,
        string explanation,
        int weight)
        => new(DetectionSignalCode.Custom, key, correlationKey, family, explanation, explanation, explanation, weight);

    private static SecurityEvent CreateEvent(
        string method = "GET",
        string path = "/",
        int statusCode = 200,
        string userAgent = "browser")
        => new(DateTimeOffset.Parse("2026-10-22T12:00:00Z"), "server01", "example.test", method, path,
            "203.0.113.42", statusCode, userAgent, new Dictionary<string, string>());

    private sealed class FakeModule(
        string id,
        IReadOnlyList<DetectionSignal> signals,
        bool throwOnDetect = false) : IDetectionModule
    {
        public DetectionModuleDescriptor Descriptor { get; } = new(id, id, "DetectionModules:Modules:" + id);

        public IReadOnlyList<DetectionSignal> Detect(SecurityEvent webEvent)
        {
            if (throwOnDetect) throw new InvalidOperationException("test failure");
            return signals;
        }
    }
}