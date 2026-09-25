namespace iisidsd.Configuration;

public sealed class StorageOptions
{
    public const string SectionName = "Storage";

    public string DatabasePath { get; set; } = "data/iisidsd.sqlite3";
    public int EventRetentionLimit { get; set; } = 100_000;
    public int FindingRetentionDays { get; set; } = 30;
}
