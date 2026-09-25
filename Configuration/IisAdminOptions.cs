namespace iisidsd.Configuration;

public sealed class IisAdminOptions
{
    public const string SectionName = "IisAdmin";

    public bool EnableDenyListChanges { get; set; } = false;
}
