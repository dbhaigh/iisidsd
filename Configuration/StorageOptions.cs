using System.ComponentModel.DataAnnotations;

namespace iisidsd.Configuration;

public sealed class StorageOptions
{
    public const string SectionName = "Storage";

    [Required]
    public string DatabasePath { get; set; } = "data/iisidsd.sqlite3";
    [Range(1, int.MaxValue)]
    public int EventRetentionLimit { get; set; } = 100_000;
    [Range(1, int.MaxValue)]
    public int EventRetentionDays { get; set; } = 30;
    [Range(1, int.MaxValue)]
    public int FindingRetentionDays { get; set; } = 30;
}
