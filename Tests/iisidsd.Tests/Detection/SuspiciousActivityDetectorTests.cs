using System.Threading.Channels;
using iisidsd.Detection;
using iisidsd.Models;
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
        Assert.Equal(3, suspiciousEvent.RiskScore);
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
        Assert.Equal(3, suspiciousEvent.RiskScore);
        Assert.Equal("Medium", suspiciousEvent.RiskSeverity);
    }

    [Fact]
    public void Analyze_RepeatedNotFoundResponsesFromSameIp_IsHighRisk()
    {
        var repeatedIp = "203.0.113.250";
        var eventStore = new FakeEventStore([
            new SecurityEvent(DateTimeOffset.UtcNow.AddMinutes(-2), "server01", "example.test", "GET", "/missing-one", repeatedIp, 404, "unit-test", new Dictionary<string, string>()),
            new SecurityEvent(DateTimeOffset.UtcNow.AddMinutes(-1), "server01", "example.test", "GET", "/missing-two", repeatedIp, 404, "unit-test", new Dictionary<string, string>())
        ]);
        var detector = new SuspiciousActivityDetector(Options.Create(new DetectionOptions()), eventStore);

        var suspiciousEvent = detector.Analyze(new SecurityEvent(
            DateTimeOffset.UtcNow,
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
        Assert.Equal(4, suspiciousEvent.RiskScore);
        Assert.Equal("High", suspiciousEvent.RiskSeverity);
        Assert.Contains("multiple 404 responses from the same client IP", suspiciousEvent.RiskIndicators ?? []);
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
    public void Analyze_UsesConfiguredWeightsForEveryExistingSignal()
    {
        var clientIp = "203.0.113.53";
        var eventStore = new FakeEventStore([
            new SecurityEvent(DateTimeOffset.UtcNow.AddMinutes(-2), "server01", "example.test", "GET", "/missing-one", clientIp, 404, "unit-test", new Dictionary<string, string>()),
            new SecurityEvent(DateTimeOffset.UtcNow.AddMinutes(-1), "server01", "example.test", "GET", "/missing-two", clientIp, 404, "unit-test", new Dictionary<string, string>())
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

        var suspiciousEvent = detector.Analyze(webEvent);

        Assert.NotNull(suspiciousEvent);
        Assert.Equal(143, suspiciousEvent.RiskScore);
        Assert.Equal(7, suspiciousEvent.RiskIndicators?.Count);
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
        Assert.Null(detector.Analyze(CreateEvent(start.AddSeconds(1), "beta.test", "/two")));

        var rateFinding = detector.Analyze(CreateEvent(start.AddSeconds(2), "alpha.test", "/three"));

        Assert.NotNull(rateFinding);
        Assert.Equal(7, rateFinding.RiskScore);
        Assert.Equal("high request rate", rateFinding.DetectionReason);
        Assert.Contains("request rate exceeded the configured threshold", rateFinding.RiskIndicators ?? []);
        Assert.Null(detector.Analyze(CreateEvent(start.AddSeconds(8), "alpha.test", "/four")));
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
        Assert.InRange(finding.RiskScore, 0, 9 * weight);
        Assert.Equal(9 * weight, finding.RiskScore);
        Assert.Equal(9, finding.RiskIndicators?.Count);
        Assert.Contains("status code meets configured suspicious threshold", finding.RiskIndicators ?? []);
        Assert.Contains("request path exceeds configured length threshold", finding.RiskIndicators ?? []);
        Assert.Contains("multiple 404 responses from the same client IP", finding.RiskIndicators ?? []);
        Assert.Contains("unusual HTTP method", finding.RiskIndicators ?? []);
        Assert.Contains("suspicious request URI pattern", finding.RiskIndicators ?? []);
        Assert.Contains("request targets file type not seen in site history", finding.RiskIndicators ?? []);
        Assert.Contains("request rate exceeded the configured threshold", finding.RiskIndicators ?? []);
        Assert.Contains("many unique request paths from the same client IP", finding.RiskIndicators ?? []);
        Assert.Contains("known scanner user-agent", finding.RiskIndicators ?? []);
        Assert.Equal("Critical", finding.RiskSeverity);
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
        Assert.Equal(9, finding.RiskIndicators?.Count);
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
}
