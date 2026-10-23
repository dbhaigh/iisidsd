using iisidsd.Configuration;
using iisidsd.Models;

namespace iisidsd.Notifications;

public interface INotificationProvider
{
    string Name { get; }

    Task DeliverAsync(NotificationMessage message, CancellationToken cancellationToken);
}

public interface IWindowsEventLogWriter
{
    void Write(string message, NotificationSeverity severity);
}