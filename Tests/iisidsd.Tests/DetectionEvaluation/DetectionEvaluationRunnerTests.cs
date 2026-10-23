using System.Text.Json;
using System.Text.Json.Nodes;
using iisidsd.Detection;
using iisidsd.DetectionEvaluation;
using iisidsd.Models;
using Microsoft.Extensions.Configuration;

namespace iisidsd.Tests.DetectionEvaluation;

public sealed class DetectionEvaluationRunnerTests
{
    private static readonly JsonSerializerOptions ReportJsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    [Fact]
    public void Evaluate_ReplaysProductionDetectorDeterministicallyAndMatchesCheckedInBaseline()
    {
        var fixturePath = Path.Combine(AppContext.BaseDirectory, "Evaluation", "Fixtures", "baseline-v1.json");
        var baselinePath = Path.Combine(AppContext.BaseDirectory, "Evaluation", "detection-evaluation-baseline.json");
        var configurationPath = Path.Combine(AppContext.BaseDirectory, "Evaluation", "appsettings.json");
        var options = new ConfigurationBuilder()
            .AddJsonFile(configurationPath, optional: false, reloadOnChange: false)
            .Build()
            .GetSection(DetectionOptions.SectionName)
            .Get<DetectionOptions>()!;

        var report = DetectionEvaluationRunner.Evaluate(fixturePath, options);
        var replayedReport = DetectionEvaluationRunner.Evaluate(fixturePath, options);
        var reportJson = JsonSerializer.Serialize(report, ReportJsonOptions);
        var replayedReportJson = JsonSerializer.Serialize(replayedReport, ReportJsonOptions);
        var baselineJson = File.ReadAllText(baselinePath);

        Assert.Equal(reportJson, replayedReportJson);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(baselineJson), JsonNode.Parse(reportJson)));
        Assert.Equal(22, report.ScenarioCount);
        Assert.Equal(225, report.TotalEvents);
        Assert.Equal(0.6458, report.Overall.Precision);
        Assert.Equal(0.4921, report.Overall.Recall);
        Assert.Equal(0.1049, report.Overall.FalsePositiveRate);
        Assert.Equal(0.5079, report.Overall.FalseNegativeRate);
        Assert.False(string.IsNullOrWhiteSpace(report.DetectorVersion));
        Assert.Equal(DetectionEvaluationRunner.DetectorRevision, report.DetectorRevision);
        Assert.Contains("directory_traversal", report.PerClass.Select(item => item.Class));
        Assert.Contains("sql_injection", report.PerClass.Select(item => item.Class));
        Assert.Contains("command_injection", report.PerClass.Select(item => item.Class));
        Assert.Contains("credential_stuffing_like", report.PerClass.Select(item => item.Class));
        Assert.Contains("slow_reconnaissance", report.PerClass.Select(item => item.Class));
        Assert.Contains("distributed_reconnaissance", report.PerClass.Select(item => item.Class));
        Assert.Contains("rotating_source_reconnaissance", report.PerClass.Select(item => item.Class));
        Assert.Contains("legitimate_crawler", report.PerClass.Select(item => item.Class));
        Assert.Contains("monitoring_system", report.PerClass.Select(item => item.Class));
        Assert.Contains("api_client", report.PerClass.Select(item => item.Class));
        Assert.Contains("application_generated_error_burst", report.PerClass.Select(item => item.Class));
        Assert.Contains("equivalent_ip_representations", report.PerClass.Select(item => item.Class));
    }

    [Fact]
    public void Evaluate_ReportsLatencyAndKnownBlindSpotsForBehavioralScenarios()
    {
        var fixturePath = Path.Combine(AppContext.BaseDirectory, "Evaluation", "Fixtures", "baseline-v1.json");
        var configurationPath = Path.Combine(AppContext.BaseDirectory, "Evaluation", "appsettings.json");
        var options = new ConfigurationBuilder()
            .AddJsonFile(configurationPath, optional: false, reloadOnChange: false)
            .Build()
            .GetSection(DetectionOptions.SectionName)
            .Get<DetectionOptions>()!;

        var report = DetectionEvaluationRunner.Evaluate(fixturePath, options);
        var highRateScenario = Assert.Single(report.Scenarios, scenario => scenario.Id == "high-request-rate");
        var distributedScenario = Assert.Single(report.Scenarios, scenario => scenario.Id == "distributed-reconnaissance");
        var rotatingScenario = Assert.Single(report.Scenarios, scenario => scenario.Id == "rotating-source-reconnaissance");

        Assert.Equal(6000, highRateScenario.DetectionLatencyMilliseconds);
        Assert.Null(distributedScenario.DetectionLatencyMilliseconds);
        Assert.Equal(15, distributedScenario.Metrics.FalseNegatives);
        Assert.Null(rotatingScenario.DetectionLatencyMilliseconds);
        Assert.Equal(8, rotatingScenario.Metrics.FalseNegatives);
    }

    [Fact]
    public void Evaluate_ExposesNonProbabilisticEvidenceMetadataForEachEvent()
    {
        var fixturePath = Path.Combine(AppContext.BaseDirectory, "Evaluation", "Fixtures", "baseline-v1.json");
        var configurationPath = Path.Combine(AppContext.BaseDirectory, "Evaluation", "appsettings.json");
        var options = new ConfigurationBuilder()
            .AddJsonFile(configurationPath, optional: false, reloadOnChange: false)
            .Build()
            .GetSection(DetectionOptions.SectionName)
            .Get<DetectionOptions>()!;

        var report = DetectionEvaluationRunner.Evaluate(fixturePath, options);
        var traversalScenario = Assert.Single(report.Scenarios, scenario => scenario.Id == "traversal-and-encoded-traversal");
        var firstEvent = traversalScenario.Events[0];

        Assert.Equal(nameof(DetectionEvidenceScope.SingleRequest), firstEvent.EvidenceScope);
        Assert.Equal(nameof(DetectionEvidenceStrength.Supported), firstEvent.EvidenceStrength);
        Assert.Contains(firstEvent.Evidence, evidence => evidence.Code == nameof(DetectionSignalCode.SuspiciousPathFragment) && evidence.Contributed);
        Assert.All(firstEvent.Evidence, evidence => Assert.True(evidence.ConfiguredWeight >= evidence.ScoreContribution));
    }

    [Fact]
    public void Evaluate_UsesNullForUndefinedMetricDenominators()
    {
        var fixturePath = Path.Combine(AppContext.BaseDirectory, "Evaluation", "Fixtures", "baseline-v1.json");
        var configurationPath = Path.Combine(AppContext.BaseDirectory, "Evaluation", "appsettings.json");
        var options = new ConfigurationBuilder()
            .AddJsonFile(configurationPath, optional: false, reloadOnChange: false)
            .Build()
            .GetSection(DetectionOptions.SectionName)
            .Get<DetectionOptions>()!;

        var report = DetectionEvaluationRunner.Evaluate(fixturePath, options);
        var sqlInjection = Assert.Single(report.PerClass, item => item.Class == "sql_injection");

        Assert.Null(sqlInjection.Metrics.FalsePositiveRate);
        Assert.Equal(0.3333, sqlInjection.Metrics.FalseNegativeRate);
    }

    [Fact]
    public void Compare_ReportsMetricDeltasAndWhetherDatasetMatches()
    {
        var fixturePath = Path.Combine(AppContext.BaseDirectory, "Evaluation", "Fixtures", "baseline-v1.json");
        var configurationPath = Path.Combine(AppContext.BaseDirectory, "Evaluation", "appsettings.json");
        var options = new ConfigurationBuilder()
            .AddJsonFile(configurationPath, optional: false, reloadOnChange: false)
            .Build()
            .GetSection(DetectionOptions.SectionName)
            .Get<DetectionOptions>()!;
        var report = DetectionEvaluationRunner.Evaluate(fixturePath, options);
        var sameVersionComparison = EvaluationComparison.Compare(report, report);
        var candidate = report with
        {
            DetectorVersion = "0.2.14.0",
            DetectorRevision = "candidate-revision",
            DatasetSha256 = "candidate-dataset",
            Overall = report.Overall with
            {
                TruePositives = report.Overall.TruePositives + 1,
                Precision = 0.7
            }
        };
        var changedComparison = EvaluationComparison.Compare(report, candidate);

        Assert.True(sameVersionComparison.SameDataset);
        Assert.Equal(report.DetectorVersion, sameVersionComparison.BaselineDetectorVersion);
        Assert.Equal(report.DetectorVersion, sameVersionComparison.CandidateDetectorVersion);
        Assert.Equal(report.DetectorRevision, sameVersionComparison.CandidateDetectorRevision);
        Assert.Equal(0, sameVersionComparison.Overall.TruePositives);
        Assert.Equal(0, sameVersionComparison.Overall.Precision);
        Assert.Equal(225, sameVersionComparison.EventBehavior.ComparedEvents);
        Assert.Equal(0, sameVersionComparison.EventBehavior.DetectionsAdded);
        Assert.Equal(0, sameVersionComparison.EventBehavior.DetectionsRemoved);
        Assert.Equal(225, sameVersionComparison.EventBehavior.RiskScoresUnchanged);
        Assert.False(changedComparison.SameDataset);
        Assert.Equal("0.2.14.0", changedComparison.BaselineDetectorVersion);
        Assert.Equal("0.2.14.0", changedComparison.CandidateDetectorVersion);
        Assert.Equal(report.DetectorRevision, changedComparison.BaselineDetectorRevision);
        Assert.Equal("candidate-revision", changedComparison.CandidateDetectorRevision);
        Assert.Equal(1, changedComparison.Overall.TruePositives);
        Assert.Equal(0.0542, changedComparison.Overall.Precision);

        var firstScenario = report.Scenarios[0];
        var firstEvent = firstScenario.Events[0];
        var changedEvent = firstEvent with
        {
            Detected = !firstEvent.Detected,
            RiskScore = firstEvent.Detected ? null : 2,
            RiskSeverity = firstEvent.Detected ? null : "Medium"
        };
        var changedScenarios = report.Scenarios.Select(scenario => scenario.Id == firstScenario.Id
            ? scenario with { Events = scenario.Events.Select(item => item.EventId == firstEvent.EventId ? changedEvent : item).ToArray() }
            : scenario).ToArray();
        var eventChangedComparison = EvaluationComparison.Compare(report, candidate with { Scenarios = changedScenarios });

        Assert.Equal(1, eventChangedComparison.EventBehavior.DetectionsAdded + eventChangedComparison.EventBehavior.DetectionsRemoved);
        Assert.Equal(1, eventChangedComparison.EventBehavior.RiskScoresIncreased + eventChangedComparison.EventBehavior.RiskScoresDecreased);
        Assert.Equal(224, eventChangedComparison.EventBehavior.RiskScoresUnchanged);
    }
}