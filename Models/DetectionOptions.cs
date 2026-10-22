using System.ComponentModel.DataAnnotations;

namespace iisidsd.Models;

public sealed class DetectionOptions
{
    public const string SectionName = "Detection";

    [Range(100, 599)]
    public int MinimumSuspiciousStatusCode { get; set; } = 400;
    [Range(1, int.MaxValue)]
    public int RequestPathLengthThreshold { get; set; } = 512;
    [Range(2, int.MaxValue)]
    public int NotFoundBurstThreshold { get; set; } = 3;
    [Range(1, int.MaxValue)]
    public int NotFoundBurstLookbackLimit { get; set; } = 250;
    [Range(1, 300)]
    public int NotFoundBurstWindowSeconds { get; set; } = 60;
    [Range(2, int.MaxValue)]
    public int AuthenticationFailureThreshold { get; set; } = 5;
    [Range(1, 300)]
    public int AuthenticationFailureWindowSeconds { get; set; } = 60;
    [Range(0, int.MaxValue)]
    public int AuthenticationFailureScoreWeight { get; set; } = 1;
    [Range(0, int.MaxValue)]
    public int StatusScoreWeight { get; set; } = 1;
    [Range(0, int.MaxValue)]
    public int LongPathScoreWeight { get; set; } = 2;
    [Range(0, int.MaxValue)]
    public int RepeatedNotFoundScoreWeight { get; set; } = 3;
    [Range(0, int.MaxValue)]
    public int UnusualMethodScoreWeight { get; set; } = 3;
    [Range(0, int.MaxValue)]
    public int PathFragmentScoreWeight { get; set; } = 5;
    [Range(0, int.MaxValue)]
    public int UnknownExtensionScoreWeight { get; set; } = 2;
    [Range(0, int.MaxValue)]
    public int ScannerUserAgentScoreWeight { get; set; } = 6;
    [Range(0, int.MaxValue)]
    public int RequestRateScoreWeight { get; set; } = 2;
    [Range(0, int.MaxValue)]
    public int PathScanScoreWeight { get; set; } = 2;
    [Range(0, int.MaxValue)]
    public int RateThreshold { get; set; } = 60;
    [Range(1, 300)]
    public int RateWindowSeconds { get; set; } = 60;
    [Range(1, int.MaxValue)]
    public int PathScanUniquePathThreshold { get; set; } = 20;
    [Range(1, 300)]
    public int PathScanWindowSeconds { get; set; } = 60;
    [Range(1, 8192)]
    public int MaximumTrackedClientHistories { get; set; } = 1024;
    [Range(1, 262144)]
    public int MaximumTrackedHistoryBuckets { get; set; } = 131072;
    [Range(1, 1024)]
    public int MaximumTrackedPathsPerHistory { get; set; } = 128;
    [Range(1, 131072)]
    public int MaximumTrackedPathsTotal { get; set; } = 65536;
    [Range(64, 1024)]
    public int MaximumTrackedPathLengthCharacters { get; set; } = 1024;
    [Range(1, 512)]
    public int MaximumTrackedExtensionSites { get; set; } = 256;
    [Range(1, 256)]
    public int MaximumExtensionsPerSite { get; set; } = 128;
    [Range(0, 30)]
    public int MaximumEventLatenessSeconds { get; set; } = 2;
    [Required]
    public string[] SuspiciousPathFragments { get; set; } =
    [
        "../", "..\\", "%2e", "%2f", "%5c", "%00", "%252e", "wp-admin", "wp-login.php",
        "phpmyadmin", "/.env", "/.git", "git/config", "/etc/passwd", "/etc/shadow",
        "/proc/self/environ", "cmd.exe", "powershell", "cmd=", "exec=", "<script",
        "union select", "sleep(", "benchmark(", "xp_cmdshell", "jndi:", "${jndi:",
        "actuator", "server-status", "manager/html", "cgi-bin", "eval-stdin.php",
        "vendor/phpunit", "solr/admin", "console/login", "aws/credentials"
    ];
    [Required]
    public string[] ScannerUserAgents { get; set; } =
    [
        "sqlmap", "nikto", "nmap", "masscan", "burp", "acunetix", "nessus", "openvas",
        "owasp zap", "zaproxy", "dirbuster", "gobuster", "ffuf", "feroxbuster", "nuclei",
        "wpscan", "metasploit", "arachni", "w3af", "whatweb", "skipfish", "hydra"
    ];
}
