using System.ComponentModel.DataAnnotations;

namespace iisidsd.Configuration;

public sealed class TrayOptions
{
    public const string SectionName = "Tray";

    [Required, Url]
    public string BrowserUrl { get; set; } = "http://localhost:5080/";
}
