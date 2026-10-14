using System.Diagnostics;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;
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
        private const string TrayCompanionTaskName = "iisidsd Tray Companion";

        private readonly NotifyIcon _icon;
        private readonly string _browserUrl;
        private readonly IHostApplicationLifetime _applicationLifetime;
        private readonly ILogger _logger;
        private readonly ToolStripMenuItem _installService;
        private readonly ToolStripMenuItem _serviceStatusItem;
        private readonly ToolStripMenuItem _dashboardStatusItem;
        private readonly ToolStripMenuItem _dryRunStatusItem;
        private readonly ToolStripMenuItem _droppedEventsStatusItem;
        private readonly ToolStripMenuItem _lastAutoDenyStatusItem;
        private readonly ToolStripMenuItem _startService;
        private readonly ToolStripMenuItem _stopService;
        private readonly ToolStripMenuItem _restartService;
        private readonly ToolStripMenuItem _uninstallService;
        private readonly System.Windows.Forms.Timer _serviceStateTimer;
        private readonly HttpClient _healthClient = new() { Timeout = TimeSpan.FromSeconds(2) };
        private bool _healthCheckInProgress;
        private readonly bool _trayOnlyProcess = Environment.GetCommandLineArgs()
            .Any(arg => string.Equals(arg, "--tray-only", StringComparison.OrdinalIgnoreCase));

        public TrayApplicationContext(string browserUrl, IHostApplicationLifetime applicationLifetime, ILogger logger)
        {
            _browserUrl = browserUrl;
            _applicationLifetime = applicationLifetime;
            _logger = logger;

            var menu = new ContextMenuStrip();
            _serviceStatusItem = new ToolStripMenuItem("Service: Checking") { Enabled = false };
            _dashboardStatusItem = new ToolStripMenuItem("Dashboard: Checking") { Enabled = false };
            _dryRunStatusItem = new ToolStripMenuItem("DryRun: Checking") { Enabled = false };
            _droppedEventsStatusItem = new ToolStripMenuItem("Dropped events: Checking") { Enabled = false };
            _lastAutoDenyStatusItem = new ToolStripMenuItem("Last auto-deny: Checking") { Enabled = false };
            menu.Items.Add(_serviceStatusItem);
            menu.Items.Add(_dashboardStatusItem);
            menu.Items.Add(_dryRunStatusItem);
            menu.Items.Add(_droppedEventsStatusItem);
            menu.Items.Add(_lastAutoDenyStatusItem);
            menu.Items.Add(new ToolStripSeparator());
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

            _serviceStateTimer = new System.Windows.Forms.Timer { Interval = 3_000 };
            _serviceStateTimer.Tick += (_, _) => UpdateServiceMenuState();
            _serviceStateTimer.Start();
            UpdateServiceMenuState();
        }

        private void UpdateServiceMenuState()
        {
            var installed = TryGetServiceStatus(out var status);
            _serviceStatusItem.Text = $"Service: {(installed ? status?.ToString() ?? "Unknown" : "Not installed")}";
            var administrator = IsAdministrator();

            _installService.Enabled = administrator && !installed;
            _startService.Enabled = administrator && installed && status == ServiceControllerStatus.Stopped;
            _stopService.Enabled = administrator && installed && status == ServiceControllerStatus.Running;
            _restartService.Enabled = administrator && installed && status == ServiceControllerStatus.Running;
            _uninstallService.Enabled = administrator && installed;
            _ = RefreshDashboardStatusAsync();
        }

        private async Task RefreshDashboardStatusAsync()
        {
            if (_healthCheckInProgress)
            {
                return;
            }

            _healthCheckInProgress = true;
            try
            {
                if (Uri.TryCreate(_browserUrl, UriKind.Absolute, out var baseUri))
                {
                    using var response = await _healthClient.GetAsync(new Uri(baseUri, "health"));
                    _dashboardStatusItem.Text = response.IsSuccessStatusCode
                        ? "Dashboard: Available"
                        : $"Dashboard: Unavailable (HTTP {(int)response.StatusCode})";
                    if (response.IsSuccessStatusCode)
                    {
                        using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
                        var health = document.RootElement;
                        _dryRunStatusItem.Text = health.GetProperty("dryRun").GetBoolean() ? "DryRun: ON" : "DryRun: OFF";
                        _droppedEventsStatusItem.Text =
                            $"Dropped events: {health.GetProperty("droppedEventCount").GetInt64():N0}";

                        var lastAutoDeny = health.GetProperty("lastAutoDeny");
                        _lastAutoDenyStatusItem.Text = lastAutoDeny.ValueKind == JsonValueKind.Null
                            ? "Last auto-deny: none"
                            : $"Last auto-deny: {lastAutoDeny.GetProperty("clientIp").GetString()} at " +
                              $"{lastAutoDeny.GetProperty("occurredAt").GetDateTimeOffset():g}" +
                              (lastAutoDeny.GetProperty("dryRun").GetBoolean()
                                  ? $" (dry run, {lastAutoDeny.GetProperty("outcome").GetString()})"
                                  : $" ({lastAutoDeny.GetProperty("outcome").GetString()})");
                    }
                    else
                    {
                        SetOperationsStatusUnavailable();
                    }
                }
                else
                {
                    _dashboardStatusItem.Text = "Dashboard: Unavailable (invalid URL)";
                    SetOperationsStatusUnavailable();
                }
            }
            catch (Exception exception)
            {
                _dashboardStatusItem.Text = "Dashboard: Unavailable";
                SetOperationsStatusUnavailable();
                _logger.LogDebug(exception, "Unable to query dashboard health at {Url}.", _browserUrl);
            }
            finally
            {
                _healthCheckInProgress = false;
            }
        }

        private void SetOperationsStatusUnavailable()
        {
            _dryRunStatusItem.Text = "DryRun: unavailable";
            _droppedEventsStatusItem.Text = "Dropped events: unavailable";
            _lastAutoDenyStatusItem.Text = "Last auto-deny: unavailable";
        }

        private static bool IsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private bool TryGetServiceStatus(out ServiceControllerStatus? status)
        {
            try
            {
                using var service = new ServiceController(ServiceName);
                service.Refresh();
                status = service.Status;
                return true;
            }
            catch (Exception exception)
            {
                _logger.LogDebug(exception, "Unable to query service status for {ServiceName}.", ServiceName);
                status = null;
                return false;
            }
        }

        private void InstallService()
            => _ = ExecuteServiceOperationAsync("Install service", () => StartServiceWithShutdownAsync("Install service"));

        private void StartService()
            => _ = ExecuteServiceOperationAsync("Start service", () => StartServiceWithShutdownAsync("Start service"));

        private async Task StartServiceWithShutdownAsync(string operation)
        {
            if (!await Task.Run(EnsureServiceInstalled))
            {
                ShowResult(operation, false, "Run as Administrator to manage Windows services.");
                return;
            }

            if (_trayOnlyProcess)
            {
                var started = await Task.Run(() =>
                    RunScCommand($"start {ServiceName}") || ScheduleDetachedStartRetries());
                started = started && await WaitForServiceDashboardReadyAsync(TimeSpan.FromSeconds(60));
                ShowResult(operation, started, "Run as Administrator to manage Windows services.");
                return;
            }

            if (!await Task.Run(ScheduleDetachedStartRetries))
            {
                ShowResult(operation, false, "Run as Administrator to manage Windows services.");
                return;
            }

            _ = await Task.Run(LaunchTrayCompanion);
            BeginGracefulShutdownAfterServiceReady();

            MessageBox.Show(
                "iisidsd service startup is running in the background. This instance will close after the service dashboard is ready.",
                "iisidsd service",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        private void StopService()
            => _ = ExecuteServiceOperationAsync("Stop service", async () =>
            {
                var success = await Task.Run(() => StopServiceAndWait(TimeSpan.FromSeconds(60)));
                ShowResult("Stop service", success, "Run as Administrator to manage Windows services.");
            });

        private void RestartService()
            => _ = ExecuteServiceOperationAsync("Restart service", async () =>
            {
                var stopped = await Task.Run(() => StopServiceAndWait(TimeSpan.FromSeconds(60)));
                var started = stopped && await Task.Run(() => RunScCommand($"start {ServiceName}"));
                started = started && await WaitForServiceDashboardReadyAsync(TimeSpan.FromSeconds(60));
                ShowResult("Restart service", started, "Run as Administrator to manage Windows services.");
            });

        private bool StopServiceAndWait(TimeSpan timeout)
        {
            if (!TryGetServiceStatus(out var status))
            {
                return false;
            }

            if (status == ServiceControllerStatus.Stopped)
            {
                return true;
            }

            if (status != ServiceControllerStatus.Running)
            {
                return false;
            }

            if (!RunScCommand($"stop {ServiceName}"))
            {
                return false;
            }

            return WaitForServiceStatus(ServiceControllerStatus.Stopped, timeout);
        }

        private bool WaitForServiceStatus(ServiceControllerStatus targetStatus, TimeSpan timeout)
        {
            try
            {
                using var service = new ServiceController(ServiceName);
                service.WaitForStatus(targetStatus, timeout);
                service.Refresh();
                return service.Status == targetStatus;
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Service {ServiceName} did not reach state {Status} within {Timeout}.", ServiceName, targetStatus, timeout);
                return false;
            }
        }

        private void UninstallService()
            => _ = ExecuteServiceOperationAsync("Uninstall service", async () =>
            {
                var success = await Task.Run(() =>
                    StopServiceAndWait(TimeSpan.FromSeconds(60)) &&
                    RunScCommand($"delete {ServiceName}") &&
                    RemoveTrayCompanionAutoStart());
                ShowResult("Uninstall service", success, "Run as Administrator to manage Windows services.");
            });

        private async Task ExecuteServiceOperationAsync(string operation, Func<Task> action)
        {
            try
            {
                await action();
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Service operation {Operation} failed unexpectedly.", operation);
                ShowResult(operation, false, "See the application log for details.");
            }
        }

        private bool EnsureServiceInstalled()
        {
            if (TryGetServiceStatus(out _))
            {
                return EnsureServiceStartupAndRecovery() && EnsureTrayCompanionAutoStart();
            }

            var processPath = ResolveServiceProcessPath();
            if (string.IsNullOrWhiteSpace(processPath))
            {
                return false;
            }

            var created = RunScCommand($"create {ServiceName} binPath= \"{processPath}\" start= auto");
            if (!created || !RunScCommand($"description {ServiceName} \"IIS intrusion detection service\""))
            {
                return false;
            }

            return EnsureServiceStartupAndRecovery() && EnsureTrayCompanionAutoStart();
        }

        private bool EnsureServiceStartupAndRecovery()
        {
            return RunScCommand($"config {ServiceName} start= auto") &&
                RunScCommand($"failure {ServiceName} reset= 86400 actions= restart/5000/restart/15000/restart/60000") &&
                RunScCommand($"failureflag {ServiceName} 1");
        }

        private bool ScheduleDetachedStartRetries()
        {
            try
            {
                var retryCommand = $"/c \"timeout /t 2 /nobreak >nul & for /l %i in (1,1,20) do (sc.exe start {ServiceName} && exit /b 0 || timeout /t 1 /nobreak >nul)\"";
                using var process = Process.Start(new ProcessStartInfo("cmd.exe", retryCommand)
                {
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });
                return process is not null;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Unable to schedule detached service start retries for {ServiceName}.", ServiceName);
                return false;
            }
        }

        private bool EnsureTrayCompanionAutoStart()
        {
            var processPath = ResolveServiceProcessPath();
            if (string.IsNullOrWhiteSpace(processPath))
            {
                return false;
            }

            var trayCommand = $"\"{processPath}\" --tray-only";
            var arguments = $"/create /tn \"{TrayCompanionTaskName}\" /sc onlogon /tr \"{trayCommand}\" /rl LIMITED /f";
            var success = RunSchtasksCommand(arguments, ignoreNotFound: false);
            if (!success)
            {
                _logger.LogWarning("Unable to register tray companion auto-start task {TaskName}.", TrayCompanionTaskName);
            }

            return success;
        }

        private bool RemoveTrayCompanionAutoStart()
        {
            var arguments = $"/delete /tn \"{TrayCompanionTaskName}\" /f";
            return RunSchtasksCommand(arguments, ignoreNotFound: true);
        }

        private bool RunSchtasksCommand(string arguments, bool ignoreNotFound)
        {
            try
            {
                using var process = Process.Start(new ProcessStartInfo("schtasks.exe", arguments)
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
                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();

                if (process.ExitCode == 0)
                {
                    return true;
                }

                var detail = string.IsNullOrWhiteSpace(error) ? output : error;
                if (ignoreNotFound && detail.Contains("cannot find", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                _logger.LogWarning("schtasks.exe {Arguments} failed with exit code {ExitCode}. Output: {Output}", arguments, process.ExitCode, detail);
                return false;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Unable to execute task scheduler command: schtasks.exe {Arguments}", arguments);
                return false;
            }
        }

        private bool LaunchTrayCompanion()
        {
            var processPath = ResolveServiceProcessPath();
            if (string.IsNullOrWhiteSpace(processPath))
            {
                return false;
            }

            try
            {
                using var process = Process.Start(new ProcessStartInfo(processPath, "--tray-only")
                {
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });
                return process is not null;
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Unable to launch tray companion mode.");
                return false;
            }
        }

        private void BeginGracefulShutdownAfterServiceReady()
        {
            _ = Task.Run(async () =>
            {
                var ready = await WaitForServiceDashboardReadyAsync(TimeSpan.FromSeconds(60));
                if (!ready)
                {
                    _logger.LogWarning("Service/dashboard readiness check timed out. Closing interactive host to let service continue.");
                }

                _applicationLifetime.StopApplication();
            });
        }

        private async Task<bool> WaitForServiceDashboardReadyAsync(TimeSpan timeout)
        {
            var deadline = DateTime.UtcNow + timeout;

            while (DateTime.UtcNow < deadline)
            {
                if (TryGetServiceStatus(out var status) && status == ServiceControllerStatus.Running)
                {
                    try
                    {
                        if (Uri.TryCreate(_browserUrl, UriKind.Absolute, out var baseUri))
                        {
                            using var response = await _healthClient.GetAsync(new Uri(baseUri, "health"));
                            if (response.IsSuccessStatusCode)
                            {
                                return true;
                            }
                        }
                    }
                    catch (HttpRequestException exception)
                    {
                        _logger.LogDebug(exception, "Dashboard readiness check failed at {Url}.", _browserUrl);
                    }
                    catch (TaskCanceledException exception)
                    {
                        _logger.LogDebug(exception, "Dashboard readiness check timed out at {Url}.", _browserUrl);
                    }
                }

                await Task.Delay(1_000);
            }

            return false;
        }

        private static string? ResolveServiceProcessPath()
        {
            if (!string.IsNullOrWhiteSpace(Environment.ProcessPath))
            {
                return Environment.ProcessPath;
            }

            try
            {
                return Process.GetCurrentProcess().MainModule?.FileName;
            }
            catch
            {
                return null;
            }
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

        public new void ExitThread()
        {
            _serviceStateTimer.Stop();
            _icon.Visible = false;
            _icon.Dispose();
            ExitThreadCore();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _serviceStateTimer.Stop();
                _serviceStateTimer.Dispose();
                _healthClient.Dispose();
                _icon.Visible = false;
                _icon.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
