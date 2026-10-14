namespace iisidsd.Models;

/// <summary>Summarizes the latest automatic deny-list action for health and tray status.</summary>
public sealed record LastAutoDenyStatus(string ClientIp, DateTimeOffset OccurredAt, bool DryRun, string Outcome);
