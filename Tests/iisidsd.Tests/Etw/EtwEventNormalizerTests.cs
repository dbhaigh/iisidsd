using iisidsd.Etw;

namespace iisidsd.Tests.Etw;

public sealed class EtwEventNormalizerTests
{
    [Fact]
    public void TryNormalize_RecognizesW3cStyleIisFieldNames()
    {
        var payload = new EtwEventPayload(
            DateTimeOffset.UtcNow,
            "event-1",
            0,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["s-computername"] = "server01",
                ["s-sitename"] = "Example Site",
                ["cs-host"] = "www.example.test",
                ["cs-method"] = "GET",
                ["cs-uri-stem"] = "/health",
                ["c-ip"] = "203.0.113.12",
                ["sc-status"] = "404",
                ["cs(User-Agent)"] = "test-agent"
            });

        var normalized = EtwEventNormalizer.TryNormalize(payload, out var securityEvent, out var failureCode);

        Assert.True(normalized, failureCode);
        Assert.NotNull(securityEvent);
        Assert.Equal("server01", securityEvent.Server);
        Assert.Equal("www.example.test", securityEvent.Domain);
        Assert.Equal("GET", securityEvent.Method);
        Assert.Equal("/health", securityEvent.Path);
        Assert.Equal("203.0.113.12", securityEvent.ClientIp);
        Assert.Equal(404, securityEvent.StatusCode);
        Assert.Equal("test-agent", securityEvent.UserAgent);
    }

    [Fact]
    public void TryNormalize_DoesNotTreatSiteNameAsDomain()
    {
        var payload = new EtwEventPayload(
            DateTimeOffset.UtcNow,
            "event-2",
            0,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["s-sitename"] = "Example Site",
                ["cs-uri-stem"] = "/health",
                ["c-ip"] = "203.0.113.12"
            });

        var normalized = EtwEventNormalizer.TryNormalize(payload, out var securityEvent, out var failureCode);

        Assert.True(normalized, failureCode);
        Assert.NotNull(securityEvent);
        Assert.Empty(securityEvent.Domain);
        Assert.Equal("Example Site", securityEvent.Properties["s-sitename"]);
    }
}
