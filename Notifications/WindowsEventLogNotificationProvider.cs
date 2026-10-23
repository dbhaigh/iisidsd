using System.Diagnostics;
using iisidsd.Configuration;
using iisidsd.Models;

namespace iisidsd.Notifications;

public sealed class WindowsEventLogNotificationProvider(IWindowsEventLogWriter writer) : INotificationProvider
{
    public string Name => "WindowsEventLog";

    public Task DeliverAsync(NotificationMessage message, CancellationToken cancellationToken)
        => Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            writer.Write(
                NotificationMessageFormatter.Format(message),
                Enum.TryParse<NotificationSeverity>(message.RiskSeverity, ignoreCase: true, out var severity)
                    ? severity
                    : NotificationSeverity.Low);
        }, cancellationToken);
}

public sealed class WindowsEventLogWriter : IWindowsEventLogWriter
{
    private const string EventSource = "iisidsd";

    public void Write(string message, NotificationSeverity severity)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows Event Log delivery is available only on Windows.");
        }

        var entryType = severity >= NotificationSeverity.High
            ? EventLogEntryType.Error
            : EventLogEntryType.Warning;
        EventLog.WriteEntry(EventSource, message, entryType, eventID: 1001);
    }
}