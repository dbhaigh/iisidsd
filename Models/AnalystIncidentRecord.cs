namespace iisidsd.Models;

public sealed record AnalystIncidentRecord(
    string ClientIp,
    string Status,
    string Note,
    DateTimeOffset UpdatedAtUtc,
    string UpdatedBy);

public sealed record AnalystIncidentUpdateRequest(string Status, string Note);