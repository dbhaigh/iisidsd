namespace iisidsd.Models;

public sealed class DetectionOptions
{
    public const string SectionName = "Detection";

    public int MinimumSuspiciousStatusCode { get; set; } = 400;
    public int RequestPathLengthThreshold { get; set; } = 512;
    public string[] SuspiciousPathFragments { get; set; } =
    [
        "../", "..\\", "/etc/passwd", "cmd.exe", "powershell", "<script", "union select", "xp_cmdshell"
    ];
}
