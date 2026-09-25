using iisidsd.Models;
using Microsoft.Extensions.Options;
using System.Net;
using System.Text.RegularExpressions;

namespace iisidsd.Detection;

public sealed class SuspiciousActivityDetector(IOptions<DetectionOptions> options) : ISuspiciousActivityDetector
{
    private readonly DetectionOptions _options = options.Value;

    private static readonly Regex InvalidPercentEscape = new("%(?![0-9a-fA-F]{2})", RegexOptions.Compiled);
    private static readonly Regex ControlCharacter = new(@"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", RegexOptions.Compiled);

    public SecurityEvent? Analyze(SecurityEvent webEvent)
    {
        var path = webEvent.Path ?? string.Empty;
        var normalizedPath = path.ToLowerInvariant();
        var reasons = new List<string>();
        var indicators = new List<string>();
        var riskScore = 0;

        if (webEvent.StatusCode >= _options.MinimumSuspiciousStatusCode)
        {
            reasons.Add($"HTTP status {webEvent.StatusCode}");
        }

        if (path.Length >= _options.RequestPathLengthThreshold)
        {
            reasons.Add($"request path length {path.Length}");
            AddRisk(10, $"request target length {path.Length} exceeds {_options.RequestPathLengthThreshold}");
        }

        foreach (var fragment in _options.SuspiciousPathFragments)
        {
            if (!string.IsNullOrWhiteSpace(fragment) && normalizedPath.Contains(fragment.ToLowerInvariant(), StringComparison.Ordinal))
            {
                reasons.Add($"suspicious path fragment '{fragment}'");
                AddRisk(25, $"suspicious request fragment '{fragment}'");
            }
        }

        if (InvalidPercentEscape.IsMatch(path))
        {
            AddRisk(20, "invalid percent encoding");
        }

        if (ControlCharacter.IsMatch(path))
        {
            AddRisk(25, "control character in request target");
        }

        var decodedPath = Uri.UnescapeDataString(path).ToLowerInvariant();
        if (decodedPath.Contains("../", StringComparison.Ordinal) || decodedPath.Contains("..\\", StringComparison.Ordinal))
        {
            AddRisk(35, "encoded or literal path traversal");
        }

        if (Uri.TryCreate(path, UriKind.Absolute, out var absoluteUri))
        {
            if (!string.Equals(absoluteUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(absoluteUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                AddRisk(40, $"unexpected URI scheme '{absoluteUri.Scheme}'");
            }

            if (!string.IsNullOrEmpty(absoluteUri.UserInfo))
            {
                AddRisk(25, "userinfo component in requested URL");
            }

            if (IPAddress.TryParse(absoluteUri.Host, out _))
            {
                AddRisk(15, "numeric IP host in requested URL");
            }

            if (absoluteUri.Host.Contains("xn--", StringComparison.OrdinalIgnoreCase))
            {
                AddRisk(10, "internationalized/punycode host");
            }
        }

        var severity = GetSeverity(riskScore);
        var suspicious = reasons.Count > 0 || riskScore >= 20;
        if (!suspicious && riskScore == 0)
        {
            return null;
        }

        var allReasons = reasons.Concat(indicators).Distinct(StringComparer.Ordinal);
        return webEvent with
        {
            IsSuspicious = suspicious,
            DetectionReason = string.Join("; ", allReasons),
            RiskScore = riskScore,
            RiskSeverity = severity,
            RiskIndicators = indicators
        };

        void AddRisk(int points, string indicator)
        {
            riskScore = Math.Min(100, riskScore + points);
            indicators.Add(indicator);
        }
    }

    private static string GetSeverity(int score) => score switch
    {
        >= 80 => "Critical",
        >= 50 => "High",
        >= 20 => "Medium",
        _ => "Low"
    };
}
