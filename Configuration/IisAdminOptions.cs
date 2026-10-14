using System.ComponentModel.DataAnnotations;

namespace iisidsd.Configuration;

public sealed class IisAdminOptions
{
    public const string SectionName = "IisAdmin";

    public bool EnableDenyListChanges { get; set; } = false;
    [Required]
    public string[] AllowList { get; set; } = [];
    [Range(0, int.MaxValue)]
    public int TemporaryBanMinutes { get; set; }
    public bool DryRun { get; set; } = true;
    public bool RequireMultipleIndicators { get; set; } = true;
}
