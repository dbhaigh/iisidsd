using iisidsd.Models;

namespace iisidsd.Detection;

public enum DetectionModuleMode
{
    Observe,
    Contribute
}

public sealed record DetectionModuleDescriptor(
    string Id,
    string DisplayName,
    string ConfigurationSection);

public sealed class DetectionModuleSettings
{
    public bool Enabled { get; set; } = true;
    public DetectionModuleMode Mode { get; set; } = DetectionModuleMode.Observe;
}

public sealed class DetectionModulesOptions
{
    public const string SectionName = "DetectionModules";

    public Dictionary<string, DetectionModuleSettings> Modules { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public bool IsValid()
        => Modules is not null && Modules.Count <= 32 && Modules.All(pair =>
            IsValidId(pair.Key) &&
            pair.Value is not null &&
            Enum.IsDefined(pair.Value.Mode));

    internal static bool IsValidId(string value)
        => value.Length is > 0 and <= 32 &&
            value[0] is >= 'a' and <= 'z' &&
            value.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.');
}

public sealed record DetectionSignal(
    DetectionSignalCode Code,
    string Key,
    string? CorrelationKey,
    DetectionEvidenceFamily Family,
    string Indicator,
    string Explanation,
    string Reason,
    int Weight,
    int FamilyPriority = 0,
    bool RepeatedBehavior = false,
    bool ReasonOnlyWhenGeneric = false);

public interface IDetectionModule
{
    DetectionModuleDescriptor Descriptor { get; }

    IReadOnlyList<DetectionSignal> Detect(SecurityEvent webEvent);
}

public static class DetectionSignalKeys
{
    public static string ForHeuristic(DetectionSignalCode code)
        => code switch
        {
            DetectionSignalCode.SuspiciousStatus => "http.status.suspicious",
            DetectionSignalCode.LongPath => "http.path.long",
            DetectionSignalCode.RepeatedNotFound => "http.behavior.repeated-not-found",
            DetectionSignalCode.RepeatedAuthenticationFailure => "http.behavior.repeated-auth-failure",
            DetectionSignalCode.UnusualMethod => "http.method.unusual",
            DetectionSignalCode.SuspiciousPathFragment => "http.path.suspicious-fragment",
            DetectionSignalCode.UnknownExtension => "http.path.unknown-extension",
            DetectionSignalCode.HighRequestRate => "http.behavior.high-rate",
            DetectionSignalCode.PathEnumeration => "http.behavior.path-enumeration",
            DetectionSignalCode.ScannerUserAgent => "http.user-agent.scanner",
            _ => $"heuristic.{code.ToString().ToLowerInvariant()}"
        };
}