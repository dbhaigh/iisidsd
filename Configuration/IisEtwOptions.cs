using System.ComponentModel.DataAnnotations;

namespace iisidsd.Configuration;

public sealed class IisEtwOptions
{
    public const string SectionName = "IisEtw";

    public bool Enabled { get; set; } = true;
    [Required]
    public string ProviderName { get; set; } = "Microsoft-Windows-IIS-Logging";
    public Guid ProviderId { get; set; } = Guid.Parse("7e8ad27f-b271-4ea2-a783-a47bde29143b");
    [Required]
    public string SessionName { get; set; } = "iisidsd-iis-logging";
    [Range(1, int.MaxValue)]
    public int SubscriptionBufferSize { get; set; } = 1_000;
    [Range(1, int.MaxValue)]
    public int IngestionBufferSize { get; set; } = 10_000;
}
