using System.Diagnostics;
using System.Windows.Forms;
using iisidsd.Configuration;
using Microsoft.Extensions.Options;

namespace iisidsd.Tray;

public sealed class TrayIconService(
    IOptions<TrayOptions> options,
    IHostApplicationLifetime applicationLifetime,
    ILogger<TrayIconService> logger) : BackgroundService
{
    private readonly TrayOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var contextReady = new TaskCompletionSource<TrayApplicationContext>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        // NotifyIcon and its ContextMenuStrip must both be created on the same STA
        // thread that owns the message loop. Creating the context before starting
        // the thread leaves the WinForms objects owned by the host thread (which
        // is normally MTA), and the shell can then ignore menu requests.
        using var registration = stoppingToken.Register(() =>
        {
            if (contextReady.Task.IsCompletedSuccessfully)
            {
                contextReady.Task.Result.ExitThread();
            }
            else
            {
                _ = contextReady.Task.ContinueWith(
                    task =>
                    {
                        if (task.Status == TaskStatus.RanToCompletion)
                        {
                            task.Result.ExitThread();
                        }
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        });

        var thread = new Thread(() =>
        {
            try
            {
                // Construct the entire WinForms object graph after the apartment
                // state has been set and immediately before starting its loop.
                using var context = new TrayApplicationContext(_options.BrowserUrl, applicationLifetime, logger);
                contextReady.TrySetResult(context);
                Application.Run(context);
            }
            catch (Exception exception)
            {
                contextReady.TrySetException(exception);
                logger.LogError(exception, "The notification-area icon could not be started.");
            }
            finally
            {
                completed.TrySetResult();
            }
        })
        {
            IsBackground = true,
            Name = "iisidsd notification area"
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        await completed.Task;
    }

    private sealed class TrayApplicationContext : ApplicationContext
    {
        private readonly NotifyIcon _icon;
        private readonly string _browserUrl;
        private readonly IHostApplicationLifetime _applicationLifetime;
        private readonly ILogger _logger;

        public TrayApplicationContext(string browserUrl, IHostApplicationLifetime applicationLifetime, ILogger logger)
        {
            _browserUrl = browserUrl;
            _applicationLifetime = applicationLifetime;
            _logger = logger;
            _icon = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Text = "iisidsd - IIS intrusion detection",
                Visible = true,
                ContextMenuStrip = CreateMenu()
            };
            _icon.DoubleClick += (_, _) => OpenDashboard();
        }

        private ContextMenuStrip CreateMenu()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Open dashboard", null, (_, _) => OpenDashboard());
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Exit", null, (_, _) => _applicationLifetime.StopApplication());
            return menu;
        }

        private void OpenDashboard()
        {
            try
            {
                Process.Start(new ProcessStartInfo(_browserUrl) { UseShellExecute = true });
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Unable to open the iisidsd dashboard at {Url}.", _browserUrl);
            }
        }

        public void ExitThread()
        {
            _icon.Visible = false;
            _icon.Dispose();
            ExitThreadCore();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _icon.Visible = false;
                _icon.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
