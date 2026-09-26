using System.Diagnostics;
using System.Security.Principal;
using System.ServiceProcess;
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
        private const string ServiceName = "iisidsd";

        private readonly NotifyIcon _icon;
        private readonly string _browserUrl;
        private readonly IHostApplicationLifetime _applicationLifetime;
        private readonly ILogger _logger;
        private readonly ToolStripMenuItem _installService;
        private readonly ToolStripMenuItem _startService;
        private readonly ToolStripMenuItem _stopService;
        private readonly ToolStripMenuItem _restartService;
        private readonly ToolStripMenuItem _uninstallService;

        public TrayApplicationContext(string browserUrl, IHostApplicationLifetime applicationLifetime, ILogger logger)
        {
            _browserUrl = browserUrl;
            _applicationLifetime = applicationLifetime;
            _logger = logger;

            var menu = new ContextMenuStrip();
            menu.Items.Add("Open dashboard", null, (_, _) => OpenDashboard());
            menu.Items.Add(new ToolStripSeparator());
            _installService = new ToolStripMenuItem("Install service", null, (_, _) => InstallService());
            _startService = new ToolStripMenuItem("Start service", null, (_, _) => StartService());
            _stopService = new ToolStripMenuItem("Stop service", null, (_, _) => StopService());
            _restartService = new ToolStripMenuItem("Restart service", null, (_, _) => RestartService());
            _uninstallService = new ToolStripMenuItem("Uninstall service", null, (_, _) => UninstallService());
            menu.Items.Add(_installService);
            menu.Items.Add(_startService);
            menu.Items.Add(_stopService);
            menu.Items.Add(_restartService);
            menu.Items.Add(_uninstallService);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Exit", null, (_, _) => _applicationLifetime.StopApplication());
            menu.Opening += (_, _) => UpdateServiceMenuState();

            _icon = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Text = "iisidsd - IIS intrusion detection",
                Visible = true,
                ContextMenuStrip = menu
            };
            _icon.DoubleClick += (_, _) => OpenDashboard();
        }

        private void UpdateServiceMenuState()
        {
            var installed = TryGetServiceStatus(out var status);
            var running = status is ServiceControllerStatus.Running;
            var administrator = IsAdministrator();

            _installService.Enabled = administrator && !installed;
            _startService.Enabled = administrator && installed && !running;
            _stopService.Enabled = administrator && installed && running;
            _restartService.Enabled = administrator && installed && running;
            _uninstallService.Enabled = administrator && installed;
        }

        private static bool IsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static bool TryGetServiceStatus(out ServiceControllerStatus? status)
        {
            try
            {
                using var service = new ServiceController(ServiceName);
                status = service.Status;
                return true;
            }
            catch (InvalidOperationException)
            {
                status = null;
                return false;
            }
        }

        private void InstallService()
        {
            var processPath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(processPath))
            {
                ShowResult("Install service", false, "Unable to determine the current executable path.");
                return;
            }

            var created = RunScCommand($"create {ServiceName} binPath= \"\"{processPath}\"\" start= auto");
            var described = created && RunScCommand($"description {ServiceName} \"IIS intrusion detection service\"");
            var started = described && RunScCommand($"start {ServiceName}");
            ShowResult("Install service", started, "Run as Administrator to manage Windows services.");
        }

        private void StartService()
        {
            var success = RunScCommand($"start {ServiceName}");
            ShowResult("Start service", success, "Run as Administrator to manage Windows services.");
        }

        private void StopService()
        {
            var success = RunScCommand($"stop {ServiceName}");
            ShowResult("Stop service", success, "Run as Administrator to manage Windows services.");
        }

        private void RestartService()
        {
            var stopped = RunScCommand($"stop {ServiceName}");
            var started = stopped && RunScCommand($"start {ServiceName}");
            ShowResult("Restart service", started, "Run as Administrator to manage Windows services.");
        }

        private void UninstallService()
        {
            _ = RunScCommand($"stop {ServiceName}");
            var success = RunScCommand($"delete {ServiceName}");
            ShowResult("Uninstall service", success, "Run as Administrator to manage Windows services.");
        }

        private bool RunScCommand(string arguments)
        {
            try
            {
                using var process = Process.Start(new ProcessStartInfo("sc.exe", arguments)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                });
                if (process is null)
                {
                    return false;
                }

                process.WaitForExit();
                if (process.ExitCode == 0)
                {
                    return true;
                }

                var error = process.StandardError.ReadToEnd();
                var output = process.StandardOutput.ReadToEnd();
                var detail = string.IsNullOrWhiteSpace(error) ? output : error;
                _logger.LogWarning("sc.exe {Arguments} failed with exit code {ExitCode}. Output: {Output}", arguments, process.ExitCode, detail);
                return false;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Unable to execute service command: sc.exe {Arguments}", arguments);
                return false;
            }
        }

        private void ShowResult(string operation, bool success, string failureHint)
        {
            var message = success ? $"{operation} completed." : $"{operation} failed. {failureHint}";
            MessageBox.Show(message, "iisidsd service", MessageBoxButtons.OK, success ? MessageBoxIcon.Information : MessageBoxIcon.Error);
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
