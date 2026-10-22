using System.Threading.Channels;
using System.Collections.Concurrent;
using iisidsd.Detection;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Storage;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Detection;

public sealed class SuspiciousActivityDetectorTests
{
    [Fact]
    public void Analyze_SuspiciousUri_AssignsExpectedScoreAndSeverity()
    {
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions()));
        var webEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/download?file=%2e%2e%2f%2e%2e%2fwindows/win.ini",
            "203.0.113.50",
            200,
            "unit-test",
            new Dictionary<string, string>());

        var suspiciousEvent = detector.Analyze(webEvent);

        Assert.NotNull(suspiciousEvent);
        Assert.True(suspiciousEvent.IsSuspicious);
        Assert.Equal(5, suspiciousEvent.RiskScore);
        Assert.Equal("High", suspiciousEvent.RiskSeverity);
        Assert.Equal("suspicious request URI", suspiciousEvent.DetectionReason);
    }

    [Fact]
    public void Analyze_ScannerAgentStatusAndMethod_AssignsCriticalSeverity()
    {
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions()));
        var webEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "TRACE",
            "/home",
            "203.0.113.51",
            404,
            "sqlmap/1.0",
            new Dictionary<string, string>());

        var suspiciousEvent = detector.Analyze(webEvent);

        Assert.NotNull(suspiciousEvent);
        Assert.Equal(10, suspiciousEvent.RiskScore);
        Assert.Equal("Critical", suspiciousEvent.RiskSeverity);
        Assert.Equal("known security scanner user-agent", suspiciousEvent.DetectionReason);
    }

    [Fact]
    public void Analyze_ZeroWeightSignalDoesNotContributeOrReplaceExplanation()
    {
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            ScannerUserAgentScoreWeight = 0
        }));
        var webEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/missing",
            "203.0.113.71",
            404,
            "Nuclei/3.0",
            new Dictionary<string, string>());

        var suspiciousEvent = detector.Analyze(webEvent);

        Assert.NotNull(suspiciousEvent);
        Assert.Equal(1, suspiciousEvent.RiskScore);
        Assert.Equal("probing/error response", suspiciousEvent.DetectionReason);
        Assert.Equal(["status code meets configured suspicious threshold"], suspiciousEvent.RiskIndicators);
    }

    [Theory]
    [InlineData(1, "Medium")]
    [InlineData(3, "Medium")]
    [InlineData(4, "High")]
    [InlineData(7, "High")]
    [InlineData(8, "Critical")]
    public void Analyze_SeverityBoundariesRemainScoreBased(int score, string expectedSeverity)
    {
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions { StatusScoreWeight = score }));
        var webEvent = new SecurityEvent(DateTimeOffset.UtcNow, "server01", "example.test", "GET", "/", "203.0.113.73", 404,
            "browser", new Dictionary<string, string>());

        var result = detector.Analyze(webEvent);

        Assert.NotNull(result);
        Assert.Equal(score, result.RiskScore);
        Assert.Equal(expectedSeverity, result.RiskSeverity);
    }

    [Fact]
    public void Analyze_AllZeroWeightSignalsReturnNoDetectionOrScoredEvidence()
    {
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            StatusScoreWeight = 0,
            LongPathScoreWeight = 0,
            RepeatedNotFoundScoreWeight = 0,
            AuthenticationFailureScoreWeight = 0,
            UnusualMethodScoreWeight = 0,
            PathFragmentScoreWeight = 0,
            UnknownExtensionScoreWeight = 0,
            ScannerUserAgentScoreWeight = 0,
            RequestRateScoreWeight = 0,
            PathScanScoreWeight = 0,
            SuspiciousPathFragments = ["marker"],
            ScannerUserAgents = ["scanner"]
        }));
        var webEvent = new SecurityEvent(DateTimeOffset.UtcNow, "server01", "example.test", "TRACE", "/marker", "203.0.113.74", 500,
            "scanner", new Dictionary<string, string>());

        var assessment = detector.AnalyzeDetailed(webEvent);

        Assert.Null(assessment.Event);
        Assert.Equal(DetectionEvidenceScope.None, assessment.Scope);
        Assert.Empty(assessment.Evidence);
    }

    [Fact]
    public void AnalyzeDetailed_MarksSingleRequestCorrelatedSequenceAndEvidenceStrengthQualitatively()
    {
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            SuspiciousPathFragments = ["marker"],
            ScannerUserAgents = ["scanner"],
            RateThreshold = 0,
            PathScanUniquePathThreshold = 100
        }));
        var webEvent = new SecurityEvent(DateTimeOffset.UtcNow, "server01", "example.test", "GET", "/marker", "203.0.113.75", 200,
            "scanner/1.0", new Dictionary<string, string>());

        var assessment = detector.AnalyzeDetailed(webEvent);

        Assert.Equal(DetectionEvidenceScope.CorrelatedAttackSequence, assessment.Scope);
        Assert.Equal(DetectionEvidenceStrength.Corroborated, assessment.Strength);
        Assert.Equal(3, assessment.EvidenceFamilyCount);
        Assert.All(assessment.Evidence, evidence => Assert.True(evidence.ScoreContribution > 0));
    }

    [Fact]
    public void Analyze_RepeatedNotFoundOutsideWindowDoesNotAddRepeatedEvidence()
    {
        var now = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var clientIp = "203.0.113.76";
        var eventStore = new FakeEventStore([
            new SecurityEvent(now.AddSeconds(-61), "server01", "example.test", "GET", "/one", clientIp, 404, "browser", new Dictionary<string, string>()),
            new SecurityEvent(now.AddSeconds(-120), "server01", "example.test", "GET", "/two", clientIp, 404, "browser", new Dictionary<string, string>())
        ]);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            NotFoundBurstThreshold = 3,
            NotFoundBurstWindowSeconds = 60
        }), eventStore);

        var result = detector.AnalyzeDetailed(new SecurityEvent(now, "server01", "example.test", "GET", "/three", clientIp, 404,
            "browser", new Dictionary<string, string>()));

        Assert.Equal(1, result.Event?.RiskScore);
        Assert.DoesNotContain(result.Evidence, evidence => evidence.Code == DetectionSignalCode.RepeatedNotFound);
        Assert.DoesNotContain("multiple 404 responses from the same client IP", result.Event?.RiskIndicators ?? []);
    }

    [Fact]
    public void Analyze_ExtremeStatusAndMissingOptionalValuesDoNotOverflowOrThrow()
    {
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            MinimumSuspiciousStatusCode = int.MaxValue,
            StatusScoreWeight = int.MaxValue,
            UnknownExtensionScoreWeight = 0,
            ScannerUserAgentScoreWeight = 0
        }));
        var webEvent = new SecurityEvent(DateTimeOffset.MinValue, "server01", "example.test", null!, null!, null!, int.MaxValue,
            null!, null!);

        var result = detector.AnalyzeDetailed(webEvent);

        Assert.Equal(int.MaxValue, result.Event?.RiskScore);
        Assert.Equal("Critical", result.Event?.RiskSeverity);
        Assert.Equal("probing/error response", result.Event?.DetectionReason);
        Assert.Single(result.Event?.RiskIndicators ?? []);
    }

    [Fact]
    public void Analyze_MissingOrMalformedIdentityDoesNotCreateSharedHistory()
    {
        using var observability = new IisObservability();
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 0,
            PathScanUniquePathThreshold = 1
        }), eventStore: null, observability);
        var timestamp = DateTimeOffset.UtcNow;
        var properties = new Dictionary<string, string>();

        detector.Analyze(new SecurityEvent(timestamp, "server01", "example.test", "GET", "/one", string.Empty, 200,
            "browser", properties));
        detector.Analyze(new SecurityEvent(timestamp, "server01", "example.test", "GET", "/two", "192.0.2.999", 200,
            "browser", properties));
        detector.Analyze(new SecurityEvent(timestamp, "server01", string.Empty, "GET", "/three", "203.0.113.95", 200,
            "browser", properties));
        detector.Analyze(new SecurityEvent(default, "server01", "example.test", "GET", "/four", "203.0.113.95", 200,
            "browser", properties));

        Assert.Contains("detection_client_histories 0", observability.RenderPrometheus());
    }

    [Fact]
    public void Analyze_ConcurrentRequestsProduceConsistentPathThresholdEvidence()
    {
        var start = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = int.MaxValue,
            PathScanUniquePathThreshold = 25,
            PathScanWindowSeconds = 60
        }));
        var results = new ConcurrentBag<SecurityEvent?>();

        Parallel.For(0, 100, index =>
        {
            var webEvent = new SecurityEvent(start, "server01", "example.test", "GET", $"/item/{index}", "203.0.113.77", 200,
                "browser", new Dictionary<string, string>());
            results.Add(detector.Analyze(webEvent));
        });

        var finalResult = detector.Analyze(new SecurityEvent(start, "server01", "example.test", "GET", "/item/final", "203.0.113.77", 200,
            "browser", new Dictionary<string, string>()));

        Assert.Equal(100, results.Count);
        Assert.NotNull(finalResult);
        Assert.Equal(2, finalResult.RiskScore);
        Assert.Contains("many unique request paths from the same client IP", finalResult.RiskIndicators ?? []);
    }

    [Fact]
    public void Analyze_UnknownFileTypeInHistory_IsSuspicious()
    {
        var eventStore = new FakeEventStore([
            new SecurityEvent(DateTimeOffset.UtcNow.AddMinutes(-2), "server01", "example.test", "GET", "/index.html", "203.0.113.10", 200, "unit-test", new Dictionary<string, string>()),
            new SecurityEvent(DateTimeOffset.UtcNow.AddMinutes(-1), "server01", "example.test", "GET", "/site.css", "203.0.113.11", 200, "unit-test", new Dictionary<string, string>())
        ]);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions()), eventStore);

        var suspiciousEvent = detector.Analyze(new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/wordpress/unrecognized.php",
            "203.0.113.99",
            500,
            "unit-test",
            new Dictionary<string, string>()));

        Assert.NotNull(suspiciousEvent);
        Assert.Equal("unrecognized file type request", suspiciousEvent.DetectionReason);
        Assert.Equal(2, suspiciousEvent.RiskScore);
        Assert.Equal("Medium", suspiciousEvent.RiskSeverity);
    }

    [Fact]
    public void Analyze_KnownFileTypeFromHistory_IsNotSuspiciousByFileTypeRule()
    {
        var eventStore = new FakeEventStore([
            new SecurityEvent(DateTimeOffset.UtcNow.AddMinutes(-1), "server01", "example.test", "GET", "/app.js", "203.0.113.10", 200, "unit-test", new Dictionary<string, string>())
        ]);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions()), eventStore);

        var suspiciousEvent = detector.Analyze(new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/scripts/main.js",
            "203.0.113.99",
            404,
            "unit-test",
            new Dictionary<string, string>()));

        Assert.NotNull(suspiciousEvent);
        Assert.Equal("probing/error response", suspiciousEvent.DetectionReason);
        Assert.Equal(1, suspiciousEvent.RiskScore);
    }

    [Fact]
    public void Analyze_UnknownFileTypeWithErrorStatus_AddsToExistingSignals()
    {
        var eventStore = new FakeEventStore([
            new SecurityEvent(DateTimeOffset.UtcNow.AddMinutes(-2), "server01", "example.test", "GET", "/index.html", "203.0.113.10", 200, "unit-test", new Dictionary<string, string>()),
            new SecurityEvent(DateTimeOffset.UtcNow.AddMinutes(-1), "server01", "example.test", "GET", "/site.css", "203.0.113.11", 200, "unit-test", new Dictionary<string, string>())
        ]);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions()), eventStore);

        var suspiciousEvent = detector.Analyze(new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/unrecognized.php",
            "203.0.113.99",
            404,
            "unit-test",
            new Dictionary<string, string>()));

        Assert.NotNull(suspiciousEvent);
        Assert.Equal("unrecognized file type request", suspiciousEvent.DetectionReason);
        Assert.Equal(2, suspiciousEvent.RiskScore);
        Assert.Equal("Medium", suspiciousEvent.RiskSeverity);
    }

    [Fact]
    public void Analyze_RepeatedNotFoundResponseUsesOneResponseOutcomeContribution()
    {
        const string repeatedIp = "203.0.113.250";
        var timestamp = DateTimeOffset.UtcNow;
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions()));
        detector.Analyze(new SecurityEvent(timestamp.AddSeconds(-20), "server01", "example.test", "GET", "/missing-one", repeatedIp, 404, "unit-test", new Dictionary<string, string>()));
        detector.Analyze(new SecurityEvent(timestamp.AddSeconds(-10), "server01", "example.test", "GET", "/missing-two", repeatedIp, 404, "unit-test", new Dictionary<string, string>()));

        var suspiciousEvent = detector.Analyze(new SecurityEvent(
            timestamp,
            "server01",
            "example.test",
            "GET",
            "/missing-three",
            repeatedIp,
            404,
            "unit-test",
            new Dictionary<string, string>()));

        Assert.NotNull(suspiciousEvent);
        Assert.Equal("repeated not found probing", suspiciousEvent.DetectionReason);
        Assert.Equal(3, suspiciousEvent.RiskScore);
        Assert.Equal("Medium", suspiciousEvent.RiskSeverity);
        Assert.Contains("multiple 404 responses from the same client IP", suspiciousEvent.RiskIndicators ?? []);
    }

    [Fact]
    public void Analyze_RepeatedAuthenticationFailuresAreBehaviorEvidenceWithoutStackingStatusScore()
    {
        var start = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            AuthenticationFailureThreshold = 3,
            AuthenticationFailureWindowSeconds = 10,
            RateThreshold = 100,
            PathScanUniquePathThreshold = 100
        }));

        SecurityEvent CreateEvent(int second)
            => new(start.AddSeconds(second), "server01", "example.test", "POST", "/account/sign-in", "203.0.113.72", 401,
                "browser", new Dictionary<string, string>());

        var first = detector.AnalyzeDetailed(CreateEvent(0));
        var second = detector.AnalyzeDetailed(CreateEvent(1));
        var third = detector.AnalyzeDetailed(CreateEvent(2));

        Assert.Equal(1, first.Event?.RiskScore);
        Assert.Equal(1, second.Event?.RiskScore);
        Assert.Equal(1, third.Event?.RiskScore);
        Assert.Equal("repeated authentication failures", third.Event?.DetectionReason);
        Assert.Equal(DetectionEvidenceScope.RepeatedBehavior, third.Scope);
        Assert.Contains("repeated authentication failures from the same client IP", third.Event?.RiskIndicators ?? []);
        Assert.DoesNotContain("status code meets configured suspicious threshold", third.Event?.RiskIndicators ?? []);
    }

    [Fact]
    public void Analyze_UsesConfiguredStatusPathAndUriThresholds()
    {
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            MinimumSuspiciousStatusCode = 500,
            RequestPathLengthThreshold = 5,
            SuspiciousPathFragments = ["custom-marker"]
        }));
        var webEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/custom-marker",
            "203.0.113.52",
            404,
            "unit-test",
            new Dictionary<string, string>());

        var suspiciousEvent = detector.Analyze(webEvent);

        Assert.NotNull(suspiciousEvent);
        Assert.Equal(7, suspiciousEvent.RiskScore);
        Assert.Contains("request path exceeds configured length threshold", suspiciousEvent.RiskIndicators ?? []);
        Assert.DoesNotContain("status code meets configured suspicious threshold", suspiciousEvent.RiskIndicators ?? []);
        Assert.Contains("suspicious request URI pattern", suspiciousEvent.RiskIndicators ?? []);
    }

    [Fact]
    public void Analyze_UsesConfiguredWeightsAndCollapsesCorrelatedSignalFamilies()
    {
        var clientIp = "203.0.113.53";
        var eventStore = new FakeEventStore([
            new SecurityEvent(DateTimeOffset.UtcNow.AddSeconds(-20), "server01", "example.test", "GET", "/missing-one", clientIp, 404, "unit-test", new Dictionary<string, string>()),
            new SecurityEvent(DateTimeOffset.UtcNow.AddSeconds(-10), "server01", "example.test", "GET", "/missing-two", clientIp, 404, "unit-test", new Dictionary<string, string>())
        ]);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RequestPathLengthThreshold = 10,
            StatusScoreWeight = 11,
            LongPathScoreWeight = 13,
            RepeatedNotFoundScoreWeight = 17,
            UnusualMethodScoreWeight = 19,
            PathFragmentScoreWeight = 23,
            UnknownExtensionScoreWeight = 29,
            ScannerUserAgentScoreWeight = 31,
            NotFoundBurstThreshold = 3,
            SuspiciousPathFragments = ["custom-marker"],
            ScannerUserAgents = ["custom-scanner"],
            RateThreshold = 1000,
            PathScanUniquePathThreshold = 1000
        }), eventStore);
        var webEvent = new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "TRACE",
            $"/custom-marker{new string('x', 20)}.asp",
            clientIp,
            404,
            "custom-scanner/1.0",
            new Dictionary<string, string>());

        detector.Analyze(webEvent with { Timestamp = webEvent.Timestamp.AddSeconds(-2), Path = "/missing-one" });
        detector.Analyze(webEvent with { Timestamp = webEvent.Timestamp.AddSeconds(-1), Path = "/missing-two" });

        var assessment = detector.AnalyzeDetailed(webEvent);
        var suspiciousEvent = assessment.Event;

        Assert.NotNull(suspiciousEvent);
        Assert.Equal(115, suspiciousEvent.RiskScore);
        Assert.Equal(5, suspiciousEvent.RiskIndicators?.Count);
        Assert.Equal(7, assessment.Evidence.Count);
        Assert.False(Assert.Single(assessment.Evidence, evidence => evidence.Code == DetectionSignalCode.SuspiciousStatus).Contributed);
        Assert.False(Assert.Single(assessment.Evidence, evidence => evidence.Code == DetectionSignalCode.RepeatedNotFound).Contributed);
        Assert.True(Assert.Single(assessment.Evidence, evidence => evidence.Code == DetectionSignalCode.UnknownExtension).Contributed);
    }

    [Fact]
    public void Analyze_RequestRateUsesPerIpSlidingWindow()
    {
        var start = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 2,
            RateWindowSeconds = 5,
            RequestRateScoreWeight = 7,
            PathScanUniquePathThreshold = 100
        }));

        SecurityEvent CreateEvent(DateTimeOffset timestamp, string domain, string path)
            => new(timestamp, "server01", domain, "GET", path, "203.0.113.54", 200, "unit-test", new Dictionary<string, string>());

        Assert.Null(detector.Analyze(CreateEvent(start, "alpha.test", "/one")));
        Assert.Null(detector.Analyze(CreateEvent(start.AddSeconds(1), "alpha.test", "/two")));

        var rateFinding = detector.Analyze(CreateEvent(start.AddSeconds(2), "alpha.test", "/three"));

        Assert.NotNull(rateFinding);
        Assert.Equal(7, rateFinding.RiskScore);
        Assert.Equal("high request rate", rateFinding.DetectionReason);
        Assert.Contains("request rate exceeded the configured threshold", rateFinding.RiskIndicators ?? []);
        Assert.Null(detector.Analyze(CreateEvent(start.AddSeconds(8), "alpha.test", "/four")));
    }

    [Fact]
    public void Analyze_RequestRateHistoryIsIsolatedByDomainForSharedClientIp()
    {
        var start = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 2,
            RateWindowSeconds = 10,
            RequestRateScoreWeight = 4,
            PathScanUniquePathThreshold = 100
        }));

        SecurityEvent CreateEvent(int seconds, string domain)
            => new(start.AddSeconds(seconds), "server01", domain, "GET", $"/item/{seconds}", "203.0.113.78", 200,
                "browser", new Dictionary<string, string>());

        Assert.Null(detector.Analyze(CreateEvent(0, "alpha.example")));
        Assert.Null(detector.Analyze(CreateEvent(1, "beta.example")));
        Assert.Null(detector.Analyze(CreateEvent(2, "alpha.example")));
    }

    [Fact]
    public void Analyze_MapsIpv4MappedIpv6ToCanonicalIpv4HistoryKey()
    {
        var start = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 1,
            RateWindowSeconds = 10,
            PathScanUniquePathThreshold = 100
        }));

        SecurityEvent CreateEvent(int seconds, string clientIp)
            => new(start.AddSeconds(seconds), "server01", "example.test", "GET", $"/item/{seconds}", clientIp, 200,
                "browser", new Dictionary<string, string>());

        Assert.Null(detector.Analyze(CreateEvent(0, "::ffff:203.0.113.81")));

        var result = detector.Analyze(CreateEvent(1, "203.0.113.81"));

        Assert.NotNull(result);
        Assert.Equal(2, result.RiskScore);
        Assert.Contains("request rate exceeded the configured threshold", result.RiskIndicators ?? []);
    }

    [Fact]
    public void Analyze_AuthenticationFailureHistoryIsIsolatedByDomainForSharedClientIp()
    {
        var start = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            AuthenticationFailureThreshold = 2,
            AuthenticationFailureScoreWeight = 1
        }));

        SecurityEvent CreateEvent(int seconds, string domain)
            => new(start.AddSeconds(seconds), "server01", domain, "POST", "/login", "203.0.113.80", 401,
                "browser", new Dictionary<string, string>());

        var firstAlpha = detector.AnalyzeDetailed(CreateEvent(0, "alpha.example"));
        var firstBeta = detector.AnalyzeDetailed(CreateEvent(1, "beta.example"));
        var secondAlpha = detector.AnalyzeDetailed(CreateEvent(2, "alpha.example"));

        Assert.DoesNotContain(firstAlpha.Evidence, evidence => evidence.Code == DetectionSignalCode.RepeatedAuthenticationFailure);
        Assert.DoesNotContain(firstBeta.Evidence, evidence => evidence.Code == DetectionSignalCode.RepeatedAuthenticationFailure);
        Assert.Contains(secondAlpha.Evidence, evidence => evidence.Code == DetectionSignalCode.RepeatedAuthenticationFailure && evidence.Contributed);
        Assert.Equal(1, secondAlpha.Event?.RiskScore);
    }

    [Fact]
    public void Analyze_Repeated404HistoryIsIsolatedByDomainForSharedClientIp()
    {
        var now = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var clientIp = "203.0.113.79";
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions { NotFoundBurstThreshold = 3 }));
        detector.Analyze(new SecurityEvent(now.AddSeconds(-20), "server01", "other.example", "GET", "/one", clientIp, 404, "browser", new Dictionary<string, string>()));
        detector.Analyze(new SecurityEvent(now.AddSeconds(-10), "server01", "other.example", "GET", "/two", clientIp, 404, "browser", new Dictionary<string, string>()));

        var result = detector.AnalyzeDetailed(new SecurityEvent(now, "server01", "target.example", "GET", "/three", clientIp, 404,
            "browser", new Dictionary<string, string>()));

        Assert.Equal(1, result.Event?.RiskScore);
        Assert.DoesNotContain(result.Evidence, evidence => evidence.Code == DetectionSignalCode.RepeatedNotFound);
    }

    [Fact]
    public void Analyze_Repeated404HistoryResetsWhenDetectorRestarts()
    {
        var start = DateTimeOffset.UtcNow.AddMinutes(-1);
        const string clientIp = "203.0.113.82";
        var options = Options.Create(new DetectionOptions { NotFoundBurstThreshold = 3 });
        var firstProcess = new SuspiciousActivityDetector(options);
        firstProcess.Analyze(new SecurityEvent(start, "server01", "example.test", "GET", "/one", clientIp, 404, "browser", new Dictionary<string, string>()));
        firstProcess.Analyze(new SecurityEvent(start.AddSeconds(1), "server01", "example.test", "GET", "/two", clientIp, 404, "browser", new Dictionary<string, string>()));

        var restartedProcess = new SuspiciousActivityDetector(options);
        var afterRestart = restartedProcess.AnalyzeDetailed(new SecurityEvent(start.AddSeconds(2), "server01", "example.test", "GET", "/three", clientIp, 404,
            "browser", new Dictionary<string, string>()));

        Assert.DoesNotContain(afterRestart.Evidence, evidence => evidence.Code == DetectionSignalCode.RepeatedNotFound);
        Assert.Equal(1, afterRestart.Event?.RiskScore);
    }

    [Fact]
    public void Analyze_Repeated404CountRespectsConfiguredLookbackLimit()
    {
        var start = DateTimeOffset.UtcNow.AddMinutes(-1);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            NotFoundBurstThreshold = 3,
            NotFoundBurstLookbackLimit = 2,
            PathScanUniquePathThreshold = 100
        }));

        SecurityEvent CreateEvent(int seconds)
            => new(start.AddSeconds(seconds), "server01", "example.test", "GET", $"/missing/{seconds}", "203.0.113.87", 404,
                "browser", new Dictionary<string, string>());

        detector.Analyze(CreateEvent(0));
        detector.Analyze(CreateEvent(1));
        var third = detector.AnalyzeDetailed(CreateEvent(2));

        Assert.DoesNotContain(third.Evidence, evidence => evidence.Code == DetectionSignalCode.RepeatedNotFound);
    }

    [Fact]
    public void Analyze_RejectsExcessivelyLateEventsAndReportsThem()
    {
        var start = DateTimeOffset.UtcNow.AddMinutes(-2);
        using var observability = new IisObservability();
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 1,
            PathScanUniquePathThreshold = 100,
            MaximumEventLatenessSeconds = 2
        }), eventStore: null, observability);

        SecurityEvent CreateEvent(int seconds)
            => new(start.AddSeconds(seconds), "server01", "example.test", "GET", $"/{seconds}", "203.0.113.83", 200,
                "browser", new Dictionary<string, string>());

        Assert.Null(detector.Analyze(CreateEvent(10)));
        Assert.Null(detector.Analyze(CreateEvent(0)));
        var inOrder = detector.Analyze(CreateEvent(11));

        Assert.NotNull(inOrder);
        Assert.Contains("detection_events_out_of_order 1", observability.RenderPrometheus());
    }

    [Fact]
    public void Analyze_RejectsFutureTimestampWithoutPoisoningWindow()
    {
        var now = DateTimeOffset.UtcNow;
        var timeProvider = new AdjustableTimeProvider(now);
        using var observability = new IisObservability();
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 1,
            PathScanUniquePathThreshold = 100,
            MaximumEventLatenessSeconds = 2
        }), eventStore: null, observability, timeProvider);

        SecurityEvent CreateEvent(DateTimeOffset timestamp, string path)
            => new(timestamp, "server01", "example.test", "GET", path, "203.0.113.92", 200,
                "browser", new Dictionary<string, string>());

        Assert.Null(detector.Analyze(CreateEvent(now.AddSeconds(3), "/future")));
        Assert.Null(detector.Analyze(CreateEvent(now, "/current")));
        Assert.NotNull(detector.Analyze(CreateEvent(now.AddSeconds(1), "/next")));
        Assert.Contains("detection_events_out_of_order 1", observability.RenderPrometheus());
    }

    [Fact]
    public void Analyze_AcceptsEventsWithinConfiguredLatenessUsingEventTimeBuckets()
    {
        var start = DateTimeOffset.UtcNow.AddMinutes(-2);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 3,
            RateWindowSeconds = 10,
            PathScanUniquePathThreshold = 100,
            MaximumEventLatenessSeconds = 2
        }));

        SecurityEvent CreateEvent(int seconds)
            => new(start.AddSeconds(seconds), "server01", "example.test", "GET", $"/{seconds}", "203.0.113.84", 200,
                "browser", new Dictionary<string, string>());

        Assert.Null(detector.Analyze(CreateEvent(10)));
        Assert.Null(detector.Analyze(CreateEvent(9)));
        Assert.Null(detector.Analyze(CreateEvent(11)));
        Assert.NotNull(detector.Analyze(CreateEvent(12)));
    }

    [Fact]
    public void Analyze_UsesInclusiveSecondBucketsAtWindowBoundary()
    {
        var start = DateTimeOffset.UtcNow.AddMinutes(-2);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 1,
            RateWindowSeconds = 2,
            PathScanUniquePathThreshold = 100
        }));

        SecurityEvent CreateEvent(int seconds)
            => new(start.AddSeconds(seconds), "server01", "example.test", "GET", $"/{seconds}", "203.0.113.85", 200,
                "browser", new Dictionary<string, string>());

        Assert.Null(detector.Analyze(CreateEvent(0)));
        Assert.Null(detector.Analyze(CreateEvent(2)));
        Assert.NotNull(detector.Analyze(CreateEvent(3)));
    }

    [Fact]
    public void Analyze_SystemClockRollbackResetsEphemeralWindows()
    {
        var initialTime = DateTimeOffset.UtcNow.AddMinutes(-1);
        var timeProvider = new AdjustableTimeProvider(initialTime);
        using var observability = new IisObservability();
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            NotFoundBurstThreshold = 3,
            RateThreshold = 100,
            PathScanUniquePathThreshold = 100
        }), eventStore: null, observability, timeProvider);

        SecurityEvent CreateEvent(DateTimeOffset timestamp, int index)
            => new(timestamp, "server01", "example.test", "GET", $"/missing/{index}", "203.0.113.91", 404,
                "browser", new Dictionary<string, string>());

        detector.Analyze(CreateEvent(initialTime, 0));
        detector.Analyze(CreateEvent(initialTime, 1));
        timeProvider.Advance(TimeSpan.FromSeconds(1));
        timeProvider.SetWallClock(initialTime.AddHours(-1));

        var afterRollback = detector.AnalyzeDetailed(CreateEvent(timeProvider.GetUtcNow(), 2));

        Assert.Equal(1, afterRollback.Event?.RiskScore);
        Assert.DoesNotContain(afterRollback.Evidence, evidence => evidence.Code == DetectionSignalCode.RepeatedNotFound);
        Assert.Contains("detection_clock_resets 1", observability.RenderPrometheus());
    }

    [Fact]
    public void Analyze_NormalizesHostCaseAndTrailingDotsButKeepsPortsAndSitesDistinct()
    {
        var start = DateTimeOffset.UtcNow.AddMinutes(-1);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 1,
            PathScanUniquePathThreshold = 100
        }));

        SecurityEvent CreateEvent(int seconds, string domain, string siteName)
            => new(start.AddSeconds(seconds), "server01", domain, "GET", $"/{seconds}", "203.0.113.86", 200,
                "browser", new Dictionary<string, string> { ["ssitename"] = siteName });

        Assert.Null(detector.Analyze(CreateEvent(0, "Example.Test.:443", "Primary")));
        Assert.NotNull(detector.Analyze(CreateEvent(1, "example.test:443", "primary")));
        Assert.Null(detector.Analyze(CreateEvent(2, "example.test:8443", "primary")));
        Assert.Null(detector.Analyze(CreateEvent(3, "example.test:443", "Other Site")));
    }

    [Fact]
    public void Analyze_RejectsAbbreviatedNumericHostInsteadOfMergingItWithAnIpAddress()
    {
        using var observability = new IisObservability();
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 0,
            PathScanUniquePathThreshold = 100
        }), eventStore: null, observability);

        detector.Analyze(new SecurityEvent(DateTimeOffset.UtcNow, "server01", "127.1", "GET", "/one", "203.0.113.96", 200,
            "browser", new Dictionary<string, string>()));

        Assert.Contains("detection_client_histories 0", observability.RenderPrometheus());
    }

    [Fact]
    public void Analyze_HighCardinalityClientAddressesAreBoundedAndObservable()
    {
        using var observability = new IisObservability();
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = int.MaxValue,
            PathScanUniquePathThreshold = 1000,
            MaximumTrackedClientHistories = 2
        }), eventStore: null, observability);
        var timestamp = DateTimeOffset.UtcNow.AddSeconds(-1);

        for (var index = 0; index < 100; index++)
        {
            var clientIp = $"198.51.{index / 256}.{index % 256}";
            detector.Analyze(new SecurityEvent(timestamp, "server01", "example.test", "GET", "/", clientIp, 200,
                "browser", new Dictionary<string, string>()));
        }

        var metrics = observability.RenderPrometheus();
        Assert.Contains("detection_client_histories 2", metrics);
        var capacityMetric = Assert.Single(metrics.Split(Environment.NewLine), line => line.StartsWith("detection_history_capacity_rejections ", StringComparison.Ordinal));
        Assert.Equal("detection_history_capacity_rejections 98", capacityMetric);
    }

    [Fact]
    public void Analyze_GlobalBucketCapacityRejectsNewHistoryWithoutGrowingState()
    {
        using var observability = new IisObservability();
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = int.MaxValue,
            PathScanUniquePathThreshold = 100,
            MaximumTrackedHistoryBuckets = 1
        }), eventStore: null, observability);
        var timestamp = DateTimeOffset.UtcNow.AddSeconds(-1);

        detector.Analyze(new SecurityEvent(timestamp, "server01", "example.test", "GET", "/one", "203.0.113.93", 200,
            "browser", new Dictionary<string, string>()));
        detector.Analyze(new SecurityEvent(timestamp, "server01", "example.test", "GET", "/two", "203.0.113.94", 200,
            "browser", new Dictionary<string, string>()));

        var metrics = observability.RenderPrometheus();
        Assert.Contains("detection_client_histories 1", metrics);
        Assert.Contains("detection_history_buckets 1", metrics);
        Assert.Contains("detection_history_capacity_rejections 1", metrics);
    }

    [Fact]
    public void Analyze_PathHistoryStopsAtConfiguredPerClientCap()
    {
        using var observability = new IisObservability();
        var start = DateTimeOffset.UtcNow.AddMinutes(-1);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = int.MaxValue,
            PathScanUniquePathThreshold = 3,
            MaximumTrackedPathsPerHistory = 2
        }), eventStore: null, observability);

        SecurityEvent CreateEvent(int seconds)
            => new(start.AddSeconds(seconds), "server01", "example.test", "GET", $"/unique/{seconds}", "203.0.113.87", 200,
                "browser", new Dictionary<string, string>());

        Assert.Null(detector.Analyze(CreateEvent(0)));
        Assert.Null(detector.Analyze(CreateEvent(1)));
        Assert.Null(detector.Analyze(CreateEvent(2)));
        Assert.Contains("detection_path_capacity_rejections 1", observability.RenderPrometheus());
    }

    [Fact]
    public void Analyze_SaturatedExtensionCacheDisablesUnknownExtensionInference()
    {
        using var observability = new IisObservability();
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions { MaximumExtensionsPerSite = 1 }),
            eventStore: null, observability);
        var start = DateTimeOffset.UtcNow.AddMinutes(-1);

        SecurityEvent CreateEvent(int seconds, string path, int statusCode)
            => new(start.AddSeconds(seconds), "server01", "example.test", "GET", path, "203.0.113.88", statusCode,
                "browser", new Dictionary<string, string>());

        Assert.Null(detector.Analyze(CreateEvent(0, "/known.one", 200)));
        Assert.Null(detector.Analyze(CreateEvent(1, "/second.two", 200)));
        var failure = detector.AnalyzeDetailed(CreateEvent(2, "/unknown.three", 500));

        Assert.Equal(1, failure.Event?.RiskScore);
        Assert.DoesNotContain(failure.Evidence, evidence => evidence.Code == DetectionSignalCode.UnknownExtension);
        Assert.Contains("detection_extension_cache_capacity_rejections 1", observability.RenderPrometheus());
    }

    [Fact]
    public void Analyze_ExtensionSiteCapacityRejectsNewSiteInferenceAndReportsIt()
    {
        using var observability = new IisObservability();
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions { MaximumTrackedExtensionSites = 1 }),
            eventStore: null, observability);
        var start = DateTimeOffset.UtcNow.AddMinutes(-1);

        detector.Analyze(new SecurityEvent(start, "server01", "first.example", "GET", "/known.one", "203.0.113.89", 200,
            "browser", new Dictionary<string, string>()));
        var secondSite = detector.AnalyzeDetailed(new SecurityEvent(start.AddSeconds(1), "server01", "second.example", "GET",
            "/unknown.two", "203.0.113.90", 500, "browser", new Dictionary<string, string>()));

        Assert.Equal(1, secondSite.Event?.RiskScore);
        Assert.DoesNotContain(secondSite.Evidence, evidence => evidence.Code == DetectionSignalCode.UnknownExtension);
        var metrics = observability.RenderPrometheus();
        Assert.Contains("detection_extension_sites 1", metrics);
        Assert.Contains("detection_extension_cache_capacity_rejections 1", metrics);
    }

    [Fact]
    public void Analyze_RequestRateHistoryIsIsolatedPerClientIp()
    {
        var start = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 1,
            RateWindowSeconds = 10,
            PathScanUniquePathThreshold = 100
        }));

        SecurityEvent CreateEvent(int seconds, string clientIp)
            => new(start.AddSeconds(seconds), "server01", "example.test", "GET", $"/{seconds}", clientIp, 200, "unit-test", new Dictionary<string, string>());

        Assert.Null(detector.Analyze(CreateEvent(0, "203.0.113.60")));
        Assert.Null(detector.Analyze(CreateEvent(1, "203.0.113.61")));

        var rateFinding = detector.Analyze(CreateEvent(2, "203.0.113.60"));

        Assert.NotNull(rateFinding);
        Assert.Contains("request rate exceeded the configured threshold", rateFinding.RiskIndicators ?? []);
        Assert.Equal(2, rateFinding.RiskScore);
    }

    [Fact]
    public void Analyze_ManyUniquePathsFromSameIpAddsPathScanSignal()
    {
        var start = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions
        {
            RateThreshold = 100,
            PathScanUniquePathThreshold = 3,
            PathScanWindowSeconds = 10,
            PathScanScoreWeight = 4
        }));

        SecurityEvent CreateEvent(int seconds, string path)
            => new(start.AddSeconds(seconds), "server01", "example.test", "GET", path, "203.0.113.55", 200, "unit-test", new Dictionary<string, string>());

        Assert.Null(detector.Analyze(CreateEvent(0, "/one?item=1")));
        Assert.Null(detector.Analyze(CreateEvent(1, "/one?item=2")));
        Assert.Null(detector.Analyze(CreateEvent(2, "/two")));

        var pathScanFinding = detector.Analyze(CreateEvent(3, "/three"));

        Assert.NotNull(pathScanFinding);
        Assert.Equal(4, pathScanFinding.RiskScore);
        Assert.Equal("path scanning activity", pathScanFinding.DetectionReason);
        Assert.Contains("many unique request paths from the same client IP", pathScanFinding.RiskIndicators ?? []);
    }

    [Fact]
    public void Analyze_DefaultPatternsIncludeCommonExploitAndScannerSignatures()
    {
        var options = new DetectionOptions();
        var fragmentDetector = new SuspiciousActivityDetector(Options.Create(options));
        var scannerDetector = new SuspiciousActivityDetector(Options.Create(options));

        var exploitFinding = fragmentDetector.Analyze(new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/.git/config",
            "203.0.113.56",
            200,
            "unit-test",
            new Dictionary<string, string>()));
        var scannerFinding = scannerDetector.Analyze(new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/home",
            "203.0.113.57",
            200,
            "Acunetix/1.0",
            new Dictionary<string, string>()));

        Assert.Equal(5, exploitFinding?.RiskScore);
        Assert.Equal(6, scannerFinding?.RiskScore);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(7)]
    public void Analyze_AllIndicatorsStayWithinConfiguredScoreRange(int weight)
    {
        var timestamp = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var clientIp = "203.0.113.58";
        var eventStore = new FakeEventStore([
            new SecurityEvent(timestamp.AddSeconds(-1), "server01", "example.test", "GET", "/missing", clientIp, 404, "unit-test", new Dictionary<string, string>())
        ]);
        var options = new DetectionOptions
        {
            MinimumSuspiciousStatusCode = 400,
            RequestPathLengthThreshold = 5,
            NotFoundBurstThreshold = 2,
            RateThreshold = 0,
            RateWindowSeconds = 10,
            PathScanUniquePathThreshold = 1,
            PathScanWindowSeconds = 10,
            StatusScoreWeight = weight,
            LongPathScoreWeight = weight,
            RepeatedNotFoundScoreWeight = weight,
            UnusualMethodScoreWeight = weight,
            PathFragmentScoreWeight = weight,
            UnknownExtensionScoreWeight = weight,
            RequestRateScoreWeight = weight,
            PathScanScoreWeight = weight,
            ScannerUserAgentScoreWeight = weight,
            SuspiciousPathFragments = ["exploit"],
            ScannerUserAgents = ["scanner"]
        };
        var detector = new SuspiciousActivityDetector(Options.Create(options), eventStore);
        detector.Analyze(new SecurityEvent(timestamp.AddSeconds(-1), "server01", "example.test", "GET", "/missing", clientIp, 404, "unit-test", new Dictionary<string, string>()));
        var webEvent = new SecurityEvent(
            timestamp,
            "server01",
            "example.test",
            "TRACE",
            "/exploit/long-path.blob",
            clientIp,
            404,
            "scanner/1.0",
            new Dictionary<string, string>());

        var finding = detector.Analyze(webEvent);

        Assert.NotNull(finding);
        Assert.InRange(finding.RiskScore, 0, 6 * weight);
        Assert.Equal(6 * weight, finding.RiskScore);
        Assert.Equal(6, finding.RiskIndicators?.Count);
        Assert.DoesNotContain("status code meets configured suspicious threshold", finding.RiskIndicators ?? []);
        Assert.Contains("request path exceeds configured length threshold", finding.RiskIndicators ?? []);
        Assert.Contains("multiple 404 responses from the same client IP", finding.RiskIndicators ?? []);
        Assert.Contains("unusual HTTP method", finding.RiskIndicators ?? []);
        Assert.Contains("suspicious request URI pattern", finding.RiskIndicators ?? []);
        Assert.DoesNotContain("request targets file type not seen in site history", finding.RiskIndicators ?? []);
        Assert.DoesNotContain("request rate exceeded the configured threshold", finding.RiskIndicators ?? []);
        Assert.Contains("many unique request paths from the same client IP", finding.RiskIndicators ?? []);
        Assert.Contains("known scanner user-agent", finding.RiskIndicators ?? []);
        Assert.Equal(weight == 1 ? "High" : "Critical", finding.RiskSeverity);
    }

    [Fact]
    public void Analyze_SaturatesRiskScoreInsteadOfOverflowing()
    {
        var timestamp = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        const string clientIp = "203.0.113.59";
        var eventStore = new FakeEventStore([
            new SecurityEvent(timestamp.AddSeconds(-1), "server01", "example.test", "GET", "/missing", clientIp, 404, "unit-test", new Dictionary<string, string>())
        ]);
        var options = new DetectionOptions
        {
            MinimumSuspiciousStatusCode = 400,
            RequestPathLengthThreshold = 5,
            NotFoundBurstThreshold = 2,
            RateThreshold = 0,
            RateWindowSeconds = 10,
            PathScanUniquePathThreshold = 1,
            PathScanWindowSeconds = 10,
            StatusScoreWeight = int.MaxValue,
            LongPathScoreWeight = int.MaxValue,
            RepeatedNotFoundScoreWeight = int.MaxValue,
            UnusualMethodScoreWeight = int.MaxValue,
            PathFragmentScoreWeight = int.MaxValue,
            UnknownExtensionScoreWeight = int.MaxValue,
            RequestRateScoreWeight = int.MaxValue,
            PathScanScoreWeight = int.MaxValue,
            ScannerUserAgentScoreWeight = int.MaxValue,
            SuspiciousPathFragments = ["exploit"],
            ScannerUserAgents = ["scanner"]
        };
        var detector = new SuspiciousActivityDetector(Options.Create(options), eventStore);
        detector.Analyze(new SecurityEvent(timestamp.AddSeconds(-1), "server01", "example.test", "GET", "/missing", clientIp, 404, "unit-test", new Dictionary<string, string>()));
        var webEvent = new SecurityEvent(
            timestamp,
            "server01",
            "example.test",
            "TRACE",
            "/exploit/long-path.blob",
            clientIp,
            404,
            "scanner/1.0",
            new Dictionary<string, string>());

        var finding = detector.Analyze(webEvent);

        Assert.NotNull(finding);
        Assert.Equal(int.MaxValue, finding.RiskScore);
        Assert.Equal("Critical", finding.RiskSeverity);
        Assert.Equal(6, finding.RiskIndicators?.Count);
    }

    private sealed class FakeEventStore(IReadOnlyList<SecurityEvent> events) : IEventStore
    {
        public IReadOnlyList<SecurityEvent> GetRecent(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
            => events
                .Where(webEvent => clientIp is null || string.Equals(webEvent.ClientIp, clientIp, StringComparison.OrdinalIgnoreCase))
                .Where(webEvent => domain is null || string.Equals(webEvent.Domain, domain, StringComparison.OrdinalIgnoreCase))
                .Where(webEvent => !suspiciousOnly || webEvent.IsSuspicious)
                .Take(limit)
                .ToArray();

        public void Publish(SecurityEvent webEvent) => throw new NotSupportedException();

        public ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class AdjustableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;
        private long _timestamp;

        public override DateTimeOffset GetUtcNow() => _utcNow;
        public override long GetTimestamp() => _timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public void Advance(TimeSpan duration)
        {
            _utcNow += duration;
            _timestamp += duration.Ticks;
        }

        public void SetWallClock(DateTimeOffset utcNow) => _utcNow = utcNow;
    }
}
