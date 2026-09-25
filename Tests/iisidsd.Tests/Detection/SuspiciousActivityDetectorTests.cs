using iisidsd.Detection;
using iisidsd.Models;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Detection;

public sealed class SuspiciousActivityDetectorTests
{
    [Fact]
    public void Analyze_PathTraversal_AddsRiskAndFlagsEvent()
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
        Assert.True(suspiciousEvent.RiskScore >= 35);
        Assert.Contains("path traversal", string.Join(';', suspiciousEvent.RiskIndicators ?? []), StringComparison.OrdinalIgnoreCase);
    }
}
