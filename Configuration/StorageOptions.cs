using System.ComponentModel.DataAnnotations;

namespace iisidsd.Configuration;

public sealed class StorageOptions
{
    public const string SectionName = "Storage";

    [Required]
    public string DatabasePath { get; set; } = "data/iisidsd.sqlite3";
    [RegularExpression("(?i)^(WAL|DELETE)$")]
    public string JournalMode { get; set; } = "WAL";
    [RegularExpression("(?i)^(FULL|EXTRA|NORMAL)$")]
    public string SynchronousMode { get; set; } = "FULL";
    [Range(1, 120)]
    public int BusyTimeoutSeconds { get; set; } = 5;
    [Range(1, 1_000_000)]
    public int EventRetentionLimit { get; set; } = 100_000;
    [Range(1, int.MaxValue)]
    public int EventRetentionDays { get; set; } = 30;
    [Range(1, int.MaxValue)]
    public int FindingRetentionDays { get; set; } = 30;
}
