using System.ComponentModel.DataAnnotations;

namespace iisidsd.Configuration;

public sealed class NotificationOptions
{
    public const string SectionName = "Notifications";

    public bool Enabled { get; set; }

    public string Provider { get; set; } = "None";

    public string MinimumSeverity { get; set; } = "High";

    [Range(0, int.MaxValue)]
    public int MinimumRiskScore { get; set; } = 8;

    [Range(1, 10_000)]
    public int QueueCapacity { get; set; } = 1_000;

    [Range(100, 100_000)]
    public int StoredIncidentLimit { get; set; } = 10_000;

    [Range(1, 1_440)]
    public int CooldownMinutes { get; set; } = 15;

    [Range(1, 10)]
    public int MaximumAttempts { get; set; } = 5;

    [Range(1, 3_600)]
    public int RetryDelaySeconds { get; set; } = 15;

    [Range(1, 86_400)]
    public int MaximumRetryDelaySeconds { get; set; } = 300;

    [Range(1, 120)]
    public int DeliveryTimeoutSeconds { get; set; } = 10;

    [Range(1, 365)]
    public int RetentionDays { get; set; } = 30;

    public string DashboardUrl { get; set; } = "http://127.0.0.1:5080/";

    public bool IsValid()
        => (string.Equals(Provider, "None", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Provider, "WindowsEventLog", StringComparison.OrdinalIgnoreCase)) &&
            Enum.TryParse<NotificationSeverity>(MinimumSeverity, ignoreCase: true, out var minimumSeverity) &&
            Enum.IsDefined(minimumSeverity) &&
            (!Enabled || !string.Equals(Provider, "None", StringComparison.OrdinalIgnoreCase)) &&
            MaximumRetryDelaySeconds >= RetryDelaySeconds &&
            IsValidDashboardUrl(DashboardUrl);

    public bool MeetsAlertThreshold(int riskScore, string severity)
        => Enabled &&
            !string.Equals(Provider, "None", StringComparison.OrdinalIgnoreCase) &&
            riskScore >= MinimumRiskScore &&
            Enum.TryParse<NotificationSeverity>(severity, ignoreCase: true, out var actual) &&
            Enum.IsDefined(actual) &&
            Enum.TryParse<NotificationSeverity>(MinimumSeverity, ignoreCase: true, out var minimum) &&
            Enum.IsDefined(minimum) &&
            actual >= minimum;

    private static bool IsValidDashboardUrl(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri is null)
        {
            return false;
        }

        return (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps) &&
            uri.IsLoopback &&
            string.IsNullOrEmpty(uri.UserInfo) &&
            string.IsNullOrEmpty(uri.Query) &&
            string.IsNullOrEmpty(uri.Fragment);
    }
}

public enum NotificationSeverity
{
    Low,
    Medium,
    High,
    Critical
}