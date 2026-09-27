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
            "/wordpress/wp-login.php",
            "203.0.113.99",
            500,
            "unit-test",
            new Dictionary<string, string>()));

        Assert.NotNull(suspiciousEvent);
        Assert.Equal("unrecognized file type request", suspiciousEvent.DetectionReason);
        Assert.Equal(4, suspiciousEvent.RiskScore);
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
            "/wp-login.php",
            "203.0.113.99",
            404,
            "unit-test",
            new Dictionary<string, string>()));

        Assert.NotNull(suspiciousEvent);
        Assert.Equal("unrecognized file type request", suspiciousEvent.DetectionReason);
        Assert.Equal(5, suspiciousEvent.RiskScore);
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
