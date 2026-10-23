using System.ComponentModel.DataAnnotations;

namespace iisidsd.Configuration;

public sealed class IisAdminOptions
{
    public const string SectionName = "IisAdmin";

    public bool EnableDenyListChanges { get; set; } = true;
    [MaxLength(16)]
    public string? EnforcementMode { get; set; } = "Enforce";
    [Required]
    public string[] AllowList { get; set; } = [];
    [Range(0, int.MaxValue)]
    public int TemporaryBanMinutes { get; set; }
    public bool DryRun { get; set; }
    public bool RequireMultipleIndicators { get; set; } = true;

    public DenyListEnforcementPolicy GetEnforcementPolicy()
    {
        if (!EnableDenyListChanges)
        {
            return new DenyListEnforcementPolicy(DenyListEnforcementMode.Observe, WritesEnabled: false);
        }

        var mode = string.IsNullOrWhiteSpace(EnforcementMode)
            ? DryRun ? DenyListEnforcementMode.Simulate : DenyListEnforcementMode.Enforce
            : Enum.Parse<DenyListEnforcementMode>(EnforcementMode, ignoreCase: true);
        if (DryRun && mode == DenyListEnforcementMode.Enforce)
        {
            mode = DenyListEnforcementMode.Simulate;
        }

        return new DenyListEnforcementPolicy(mode, WritesEnabled: true);
    }

    public static bool IsValidEnforcementMode(string? mode)
    {
        if (string.IsNullOrWhiteSpace(mode))
        {
            return true;
        }

        return Enum.TryParse<DenyListEnforcementMode>(mode, ignoreCase: true, out var parsed) &&
            Enum.IsDefined(parsed) &&
            string.Equals(Enum.GetName(parsed), mode.Trim(), StringComparison.OrdinalIgnoreCase);
    }
}

public enum DenyListEnforcementMode
{
    Observe,
    Simulate,
    Enforce
}

public sealed record DenyListEnforcementPolicy(DenyListEnforcementMode Mode, bool WritesEnabled)
{
    public bool CanMutate => WritesEnabled && Mode == DenyListEnforcementMode.Enforce;
    public bool IsSimulation => WritesEnabled && Mode == DenyListEnforcementMode.Simulate;
}
