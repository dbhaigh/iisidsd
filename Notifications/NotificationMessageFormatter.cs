using System.Text;
using System.Text.RegularExpressions;
using iisidsd.Models;

namespace iisidsd.Notifications;

public static partial class NotificationMessageFormatter
{
    private const int MaximumMessageLength = 12_000;
    private const int MaximumEvidenceItems = 8;

    [GeneratedRegex("""(?i)["']?(password|passwd|token|secret|authorization|cookie|api[-_]?key)["']?(\s*[:=]\s*)["']?(?:bearer\s+)?[^"'\s,;]+["']?""", RegexOptions.CultureInvariant)]
    private static partial Regex SensitiveValuePattern();

    public static NotificationMessage Create(NotificationIncident incident, string dashboardUrl)
        => new(
            incident.Id,
            incident.ClientIp,
            incident.TargetSite,
            incident.Summary,
            incident.RiskScore,
            incident.RiskSeverity,
            incident.EventTimestampUtc,
            incident.FirstSeenUtc,
            incident.LastSeenUtc,
            incident.Evidence.Take(MaximumEvidenceItems).ToArray(),
            dashboardUrl);

    public static string Format(NotificationMessage message)
    {
        var builder = new StringBuilder();
        builder.AppendLine("iisidsd security notification");
        AppendLine(builder, "Severity", message.RiskSeverity);
        AppendLine(builder, "Incident", message.IncidentId);
        AppendLine(builder, "Summary", message.Summary);
        AppendLine(builder, "Client", message.ClientIp);
        AppendLine(builder, "Target site", message.TargetSite);
        AppendLine(builder, "Risk score", message.RiskScore.ToString(System.Globalization.CultureInfo.InvariantCulture));
        AppendLine(builder, "Event time (UTC)", message.EventTimestampUtc.ToUniversalTime().ToString("O"));
        AppendLine(builder, "First seen (UTC)", message.FirstSeenUtc.ToUniversalTime().ToString("O"));
        AppendLine(builder, "Last seen (UTC)", message.LastSeenUtc.ToUniversalTime().ToString("O"));
        builder.AppendLine("Evidence:");
        foreach (var evidence in message.Evidence.Take(MaximumEvidenceItems))
        {
            AppendLine(builder, $"- {evidence.DetectorId}/{evidence.SignalKey}", evidence.Explanation);
        }

        AppendLine(builder, "Dashboard", message.DashboardUrl);
        if (builder.Length > MaximumMessageLength)
        {
            builder.Length = MaximumMessageLength;
            builder.AppendLine();
            builder.Append("[truncated]");
        }

        return builder.ToString();
    }

    private static void AppendLine(StringBuilder builder, string name, string? value)
    {
        var normalized = new string((value ?? string.Empty)
            .Select(static character => char.IsControl(character) ? ' ' : character)
            .ToArray());
        normalized = SensitiveValuePattern().Replace(normalized, "$1$2[redacted]");
        builder.Append(name).Append(": ").AppendLine(normalized);
    }
}