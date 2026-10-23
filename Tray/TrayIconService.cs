using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;
using Microsoft.Win32;
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
                var serviceHandoffRequested = Environment.GetCommandLineArgs()
                    .Any(arg => arg.StartsWith("--service-handoff-pid=", StringComparison.OrdinalIgnoreCase));
                using var trayMutex = new Mutex(initiallyOwned: false, "Local\\iisidsd-tray-companion");
                bool ownsMutex;
                try
                {
                    ownsMutex = trayMutex.WaitOne(0);
                    if (!ownsMutex && serviceHandoffRequested)
                    {
                        ownsMutex = trayMutex.WaitOne();
                    }
                }
                catch (AbandonedMutexException)
                {
                    ownsMutex = true;
                }

                if (!ownsMutex)
                {
                    contextReady.TrySetCanceled();
                    return;
                }

                try
                {
                    using var context = new TrayApplicationContext(_options.BrowserUrl, applicationLifetime, logger);
                    contextReady.TrySetResult(context);
                    Application.Run(context);
                }
                finally
                {
                    trayMutex.ReleaseMutex();
                }
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
        private const string ServiceAccount = "NT SERVICE\\iisidsd";
        private const string PerformanceLogUsersSid = "S-1-5-32-559";
        private const string InstallerRegistryKeyPath = @"SOFTWARE\iisidsd";
        private const string EtwGroupMembershipValue = "InstallerAddedPerformanceLogUsersMembership";

        private readonly NotifyIcon _icon;
        private readonly string _browserUrl;
        private readonly IHostApplicationLifetime _applicationLifetime;
        private readonly ILogger _logger;
        private readonly ToolStripMenuItem _installService;
        private readonly ToolStripMenuItem _serviceStatusItem;
        private readonly ToolStripMenuItem _dashboardStatusItem;
        private readonly ToolStripMenuItem _enforcementModeStatusItem;
        private readonly ToolStripMenuItem _droppedEventsStatusItem;
        private readonly ToolStripMenuItem _lastEnforcementStatusItem;
        private readonly ToolStripMenuItem _startService;
        private readonly ToolStripMenuItem _stopService;
        private readonly ToolStripMenuItem _restartService;
        private readonly ToolStripMenuItem _uninstallService;
        private readonly System.Windows.Forms.Timer _serviceStateTimer;
        private readonly HttpClient _healthClient = new(new HttpClientHandler { UseDefaultCredentials = true })
        {
            Timeout = TimeSpan.FromSeconds(2)
        };
        private bool _healthCheckInProgress;
        private readonly bool _trayOnlyProcess = Environment.GetCommandLineArgs()
            .Any(arg => string.Equals(arg, "--tray-only", StringComparison.OrdinalIgnoreCase));
        private bool _openDashboardWhenReady;
        private readonly int? _serviceHandoffParentProcessId;

        public TrayApplicationContext(string browserUrl, IHostApplicationLifetime applicationLifetime, ILogger logger)
        {
            _browserUrl = browserUrl;
            _applicationLifetime = applicationLifetime;
            _logger = logger;
            var arguments = Environment.GetCommandLineArgs();
            var suppressDashboardOpen = arguments
                .Any(arg => string.Equals(arg, "--suppress-dashboard-open", StringComparison.OrdinalIgnoreCase));
            _serviceHandoffParentProcessId = GetServiceHandoffParentProcessId(arguments);
            _openDashboardWhenReady = !suppressDashboardOpen &&
                (_trayOnlyProcess ||
                 (TryGetServiceStatus(out var serviceStatus) &&
                  serviceStatus == ServiceControllerStatus.Running));

            var menu = new ContextMenuStrip();
            _serviceStatusItem = new ToolStripMenuItem("Service: Checking") { Enabled = false };
            _dashboardStatusItem = new ToolStripMenuItem("Dashboard: Checking") { Enabled = false };
            _enforcementModeStatusItem = new ToolStripMenuItem("Enforcement: Checking") { Enabled = false };
            _droppedEventsStatusItem = new ToolStripMenuItem("Dropped events: Checking") { Enabled = false };
            _lastEnforcementStatusItem = new ToolStripMenuItem("Last enforcement: Checking") { Enabled = false };
            menu.Items.Add(_serviceStatusItem);
            menu.Items.Add(_dashboardStatusItem);
            menu.Items.Add(_enforcementModeStatusItem);
            menu.Items.Add(_droppedEventsStatusItem);
            menu.Items.Add(_lastEnforcementStatusItem);
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
            if (_serviceHandoffParentProcessId is int parentProcessId)
            {
                _ = StartServiceAfterHostExitAsync(parentProcessId);
            }
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
                    using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
                    var health = document.RootElement;
                    var isLive = health.TryGetProperty("liveness", out var liveness) && liveness.GetString() == "live";
                    var isReady = health.TryGetProperty("readiness", out var readiness) && readiness.GetString() == "ready";
                    _dashboardStatusItem.Text = !isLive
                        ? $"Dashboard: Unavailable (HTTP {(int)response.StatusCode})"
                        : isReady ? "Dashboard: Available" : "Dashboard: Degraded";
                    if (isLive)
                    {
                        _enforcementModeStatusItem.Text =
                            $"Enforcement: {health.GetProperty("enforcementMode").GetString()}";
                        _droppedEventsStatusItem.Text =
                            $"Dropped events: {health.GetProperty("droppedEventCount").GetInt64():N0}";

                                                var lastEnforcement = health.GetProperty("lastEnforcement");
                                                _lastEnforcementStatusItem.Text = lastEnforcement.ValueKind == JsonValueKind.Null
                                                        ? "Last enforcement: none"
                                                        : $"Last enforcement: {lastEnforcement.GetProperty("outcome").GetString()} at " +
                                                            $"{lastEnforcement.GetProperty("occurredAt").GetDateTimeOffset():g}" +
                                                            (lastEnforcement.GetProperty("dryRun").ValueKind == JsonValueKind.True ? " (simulation)" : string.Empty);

                        if (_openDashboardWhenReady)
                        {
                            _openDashboardWhenReady = false;
                            OpenDashboard();
                        }
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
            _enforcementModeStatusItem.Text = "Enforcement: unavailable";
            _droppedEventsStatusItem.Text = "Dropped events: unavailable";
            _lastEnforcementStatusItem.Text = "Last enforcement: unavailable";
        }

        private static bool IsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private bool TryGetServiceStatus(out ServiceControllerStatus? status)
            => TryGetServiceStatus(out status, out _);

        private bool TryGetServiceStatus(out ServiceControllerStatus? status, out bool serviceNotInstalled)
        {
            serviceNotInstalled = false;
            try
            {
                using var service = new ServiceController(ServiceName);
                service.Refresh();
                status = service.Status;
                return true;
            }
            catch (InvalidOperationException exception) when (IsServiceNotInstalled(exception))
            {
                serviceNotInstalled = true;
                status = null;
                return false;
            }
            catch (Win32Exception exception) when (exception.NativeErrorCode == 1060)
            {
                serviceNotInstalled = true;
                status = null;
                return false;
            }
            catch (Exception exception)
            {
                _logger.LogDebug(exception, "Unable to query service status for {ServiceName}.", ServiceName);
                status = null;
                return false;
            }
        }

        private static bool IsServiceNotInstalled(InvalidOperationException exception)
            => exception.InnerException is Win32Exception { NativeErrorCode: 1060 };

        private void InstallService()
            => _ = ExecuteServiceOperationAsync("Install service", () => StartServiceWithShutdownAsync("Install service"));

        private void StartService()
            => _ = ExecuteServiceOperationAsync("Start service", () => StartServiceWithShutdownAsync("Start service"));

        private async Task StartServiceWithShutdownAsync(string operation)
        {
            if (!await Task.Run(EnsureServiceInstalled))
            {
                ShowResult(operation, false, "Run as Administrator and verify ETW trace permissions.");
                return;
            }

            if (_trayOnlyProcess)
            {
                var started = await Task.Run(StartServiceWithBoundedRetries);
                started = started && await WaitForServiceDashboardReadyAsync(TimeSpan.FromSeconds(60));
                ShowResult(operation, started, "Run as Administrator and verify ETW trace permissions.");
                return;
            }

            if (!await Task.Run(() => LaunchTrayCompanion(Environment.ProcessId)))
            {
                ShowResult(operation, false, "The tray companion could not be started.");
                return;
            }

            _applicationLifetime.StopApplication();
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
                var started = stopped && await Task.Run(StartServiceWithBoundedRetries);
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

            if (!RunScCommand("stop", ServiceName))
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
                var success = await Task.Run(UninstallServiceAndClean);
                ShowResult("Uninstall service", success, "Run as Administrator to manage Windows services.");
            });

        private bool UninstallServiceAndClean()
        {
            if (!TryGetServiceStatus(out var status, out var serviceNotInstalled))
            {
                if (!serviceNotInstalled)
                {
                    return false;
                }

                var taskRemoved = RemoveTrayCompanionAutoStart();
                var membershipRemovedWithoutService = RemoveInstallerManagedEtwMembership();
                return taskRemoved && membershipRemovedWithoutService;
            }

            if (status != ServiceControllerStatus.Stopped && !StopServiceAndWait(TimeSpan.FromSeconds(60)))
            {
                return false;
            }

            if (!RunScCommand("delete", ServiceName) &&
                (!TryGetServiceStatus(out _, out serviceNotInstalled) || !serviceNotInstalled))
            {
                return false;
            }

            var trayTaskRemoved = RemoveTrayCompanionAutoStart();
            var etwMembershipRemoved = RemoveInstallerManagedEtwMembership();
            return trayTaskRemoved && etwMembershipRemoved;
        }

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
            var processPath = ResolveServiceProcessPath();
            if (string.IsNullOrWhiteSpace(processPath) || !File.Exists(processPath))
            {
                return false;
            }

            var serviceAlreadyInstalled = TryGetServiceStatus(out _, out var serviceNotInstalled);
            if (!serviceAlreadyInstalled && !serviceNotInstalled)
            {
                return false;
            }
            var created = serviceAlreadyInstalled
                ? RunScCommand(
                    "config", ServiceName,
                    "binPath=", $"\"{processPath}\"",
                    "start=", "auto")
                : RunScCommand(
                    "create", ServiceName,
                    "binPath=", $"\"{processPath}\"",
                    "start=", "auto",
                    "obj=", ServiceAccount);
            if (!created || !RunScCommand("description", ServiceName, "IIS intrusion detection service"))
            {
                return false;
            }

            return EnsureServiceStartupAndRecovery() &&
                EnsureServiceRuntimePermissions(processPath, grantVirtualServiceAccount: !serviceAlreadyInstalled) &&
                EnsureEtwTraceAccess() &&
                EnsureTrayCompanionAutoStart();
        }

        private bool EnsureServiceStartupAndRecovery()
        {
            return RunScCommand("config", ServiceName, "start=", "auto") &&
                RunScCommand("failure", ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000") &&
                RunScCommand("failureflag", ServiceName, "1") &&
                RunScCommand("sidtype", ServiceName, "unrestricted");
        }

        private bool EnsureServiceRuntimePermissions(string processPath, bool grantVirtualServiceAccount)
        {
            var installDirectory = Path.GetDirectoryName(processPath);
            if (string.IsNullOrWhiteSpace(installDirectory)) return false;
            var dataDirectory = Path.Combine(installDirectory, "data");
            var settingsPath = Path.Combine(installDirectory, "appsettings.json");
            Directory.CreateDirectory(dataDirectory);
            if (!grantVirtualServiceAccount) return true;
            if (!File.Exists(settingsPath)) return false;
            return RunIcaclsCommand(installDirectory, "/grant", $"{ServiceAccount}:(OI)(CI)(RX)", "/T", "/C") &&
                RunIcaclsCommand(installDirectory, "/grant", $"{ServiceAccount}:(WD)") &&
                RunIcaclsCommand(settingsPath, "/grant", $"{ServiceAccount}:(M)") &&
                RunIcaclsCommand(dataDirectory, "/grant", $"{ServiceAccount}:(OI)(CI)(M)", "/T", "/C");
        }

        private bool EnsureEtwTraceAccess()
        {
            if (!TryGetPerformanceLogUsersMembership(out var groupName, out var isMember))
            {
                return false;
            }

            if (isMember)
            {
                return true;
            }

            if (!RunNetLocalGroupCommand(out _, "localgroup", groupName, ServiceAccount, "/add"))
            {
                return false;
            }

            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(InstallerRegistryKeyPath, writable: true)
                    ?? throw new InvalidOperationException("Unable to create the iisidsd installer registry key.");
                key.SetValue(EtwGroupMembershipValue, 1, RegistryValueKind.DWord);
                return true;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Unable to record installer ownership of the ETW trace permission.");
                if (!RunNetLocalGroupCommand(out _, "localgroup", groupName, ServiceAccount, "/delete"))
                {
                    _logger.LogError("The service account remains in Performance Log Users because rollback failed.");
                }

                return false;
            }
        }

        private bool RemoveInstallerManagedEtwMembership()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(InstallerRegistryKeyPath))
                {
                    if (key?.GetValue(EtwGroupMembershipValue) is not int installedByIisidsd ||
                        installedByIisidsd != 1)
                    {
                        return true;
                    }
                }

                if (!TryGetPerformanceLogUsersMembership(out var groupName, out var isMember))
                {
                    return false;
                }

                if (isMember &&
                    !RunNetLocalGroupCommand(out _, "localgroup", groupName, ServiceAccount, "/delete"))
                {
                    return false;
                }

                using var writableKey = Registry.LocalMachine.OpenSubKey(InstallerRegistryKeyPath, writable: true);
                writableKey?.DeleteValue(EtwGroupMembershipValue, throwOnMissingValue: false);
                return true;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Unable to remove installer-managed ETW trace permissions.");
                return false;
            }
        }

        private bool TryGetPerformanceLogUsersMembership(out string groupName, out bool isMember)
        {
            groupName = string.Empty;
            isMember = false;
            try
            {
                var groupAccount = new SecurityIdentifier(PerformanceLogUsersSid)
                    .Translate(typeof(NTAccount))
                    .Value;
                var separator = groupAccount.LastIndexOf('\\');
                if (separator < 0)
                {
                    throw new InvalidOperationException("Unable to resolve the Performance Log Users group name.");
                }

                groupName = groupAccount[(separator + 1)..];
                if (!RunNetLocalGroupCommand(out var members, "localgroup", groupName))
                {
                    return false;
                }

                isMember = members
                    .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                    .Any(member => string.Equals(member.Trim(), ServiceAccount, StringComparison.OrdinalIgnoreCase));
                return true;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Unable to inspect Performance Log Users membership.");
                return false;
            }
        }

        private bool RunNetLocalGroupCommand(out string output, params string[] arguments)
        {
            output = string.Empty;
            try
            {
                var startInfo = new ProcessStartInfo("net.exe")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
                using var process = Process.Start(startInfo);
                if (process is null)
                {
                    return false;
                }

                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(30_000))
                {
                    process.Kill(entireProcessTree: true);
                    _logger.LogError("net.exe localgroup {Operation} timed out.", arguments.LastOrDefault() ?? "query");
                    return false;
                }

                Task.WaitAll(outputTask, errorTask);
                output = $"{outputTask.Result}{Environment.NewLine}{errorTask.Result}";
                if (process.ExitCode == 0)
                {
                    return true;
                }

                _logger.LogError(
                    "net.exe localgroup {Arguments} failed with exit code {ExitCode}. {Output}",
                    string.Join(" ", arguments),
                    process.ExitCode,
                    output.Trim());
                return false;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Unable to run net.exe localgroup {Arguments}.", arguments);
                return false;
            }
        }

        private bool RunIcaclsCommand(params string[] arguments)
        {
            try
            {
                var startInfo = new ProcessStartInfo("icacls.exe")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
                using var process = Process.Start(startInfo);
                if (process is null) return false;
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(30_000))
                {
                    process.Kill(entireProcessTree: true);
                    _logger.LogError("icacls.exe timed out while granting service runtime permissions.");
                    return false;
                }

                Task.WaitAll(outputTask, errorTask);
                if (process.ExitCode == 0) return true;
                _logger.LogError("icacls.exe failed with exit code {ExitCode} while granting service runtime permissions.", process.ExitCode);
                return false;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Unable to grant service runtime permissions.");
                return false;
            }
        }

        private bool StartServiceWithBoundedRetries()
        {
            for (var attempt = 1; attempt <= 3; attempt++)
            {
                if (RunScCommand("start", ServiceName) ||
                    (TryGetServiceStatus(out var status) && status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending))
                {
                    return true;
                }

                if (attempt < 3) Thread.Sleep(TimeSpan.FromSeconds(attempt));
            }

            _logger.LogError("Service {ServiceName} did not accept a start request after three bounded attempts.", ServiceName);
            return false;
        }

        private bool EnsureTrayCompanionAutoStart()
        {
            var processPath = ResolveServiceProcessPath();
            if (string.IsNullOrWhiteSpace(processPath))
            {
                return false;
            }

            var trayCommand = $"\"{processPath}\" --tray-only";
            var success = RunSchtasksCommand(
                ignoreNotFound: false,
                "/create", "/tn", TrayCompanionTaskName,
                "/sc", "onlogon",
                "/tr", trayCommand,
                "/rl", "LIMITED", "/f");
            if (!success)
            {
                _logger.LogWarning("Unable to register tray companion auto-start task {TaskName}.", TrayCompanionTaskName);
            }

            return success;
        }

        private bool RemoveTrayCompanionAutoStart()
        {
            return RunSchtasksCommand(
                ignoreNotFound: true,
                "/delete", "/tn", TrayCompanionTaskName, "/f");
        }

        private bool RunSchtasksCommand(bool ignoreNotFound, params string[] arguments)
        {
            try
            {
                var startInfo = new ProcessStartInfo("schtasks.exe")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
                using var process = Process.Start(startInfo);
                if (process is null)
                {
                    return false;
                }

                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(30_000))
                {
                    process.Kill(entireProcessTree: true);
                    _logger.LogError("schtasks.exe {Operation} timed out.", arguments.FirstOrDefault() ?? "task operation");
                    return false;
                }

                Task.WaitAll(outputTask, errorTask);

                if (process.ExitCode == 0)
                {
                    return true;
                }

                var detail = string.IsNullOrWhiteSpace(errorTask.Result) ? outputTask.Result : errorTask.Result;
                if (ignoreNotFound && detail.Contains("cannot find", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                _logger.LogWarning(
                    "schtasks.exe {Operation} failed with exit code {ExitCode}. {Output}",
                    arguments.FirstOrDefault() ?? "task operation",
                    process.ExitCode,
                    detail.Trim());
                return false;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Unable to execute task scheduler command: schtasks.exe {Arguments}", arguments);
                return false;
            }
        }

        private bool LaunchTrayCompanion(int parentProcessId)
        {
            var processPath = ResolveServiceProcessPath();
            if (string.IsNullOrWhiteSpace(processPath))
            {
                return false;
            }

            try
            {
                var startInfo = new ProcessStartInfo(processPath)
                {
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    WorkingDirectory = Path.GetDirectoryName(processPath) ?? AppContext.BaseDirectory
                };
                startInfo.ArgumentList.Add("--tray-only");
                startInfo.ArgumentList.Add("--suppress-dashboard-open");
                startInfo.ArgumentList.Add($"--service-handoff-pid={parentProcessId}");
                using var process = Process.Start(startInfo);
                return process is not null;
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Unable to launch tray companion mode.");
                return false;
            }
        }

        private async Task StartServiceAfterHostExitAsync(int parentProcessId)
        {
            if (!await WaitForHostProcessExitAsync(parentProcessId))
            {
                _logger.LogError(
                    "The interactive dashboard process {ProcessId} did not exit; the service handoff was cancelled.",
                    parentProcessId);
                return;
            }

            if (!await Task.Run(EnsureServiceStartRequested))
            {
                _logger.LogError("Unable to start the iisidsd service after the interactive dashboard closed.");
                return;
            }

            if (!await WaitForServiceDashboardReadyAsync(TimeSpan.FromSeconds(60)))
            {
                _logger.LogError("The iisidsd service did not serve the complete dashboard after startup.");
            }
        }

        private async Task<bool> WaitForHostProcessExitAsync(int processId)
        {
            try
            {
                using var hostProcess = Process.GetProcessById(processId);
                await hostProcess.WaitForExitAsync();
                return true;
            }
            catch (ArgumentException)
            {
                return true;
            }
            catch (InvalidOperationException exception)
            {
                _logger.LogError(exception, "Unable to wait for dashboard process {ProcessId} to exit.", processId);
                return false;
            }
            catch (System.ComponentModel.Win32Exception exception)
            {
                _logger.LogError(exception, "Unable to inspect dashboard process {ProcessId}.", processId);
                return false;
            }
        }

        private bool EnsureServiceStartRequested()
        {
            if (TryGetServiceStatus(out var status) &&
                status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)
            {
                return true;
            }

            return StartServiceWithBoundedRetries() ||
                (TryGetServiceStatus(out status) &&
                 status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending);
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
                            using var healthResponse = await _healthClient.GetAsync(new Uri(baseUri, "health"));
                            using var healthDocument = JsonDocument.Parse(await healthResponse.Content.ReadAsStreamAsync());
                            var health = healthDocument.RootElement;
                            var isReady = health.TryGetProperty("readiness", out var readiness) &&
                                readiness.ValueKind == JsonValueKind.String &&
                                string.Equals(readiness.GetString(), "ready", StringComparison.Ordinal);
                            var expectedVersion = typeof(TrayIconService).Assembly.GetName().Version?.ToString(3);
                            var isExpectedVersion = health.TryGetProperty("version", out var version) &&
                                version.ValueKind == JsonValueKind.String &&
                                string.Equals(version.GetString(), expectedVersion, StringComparison.Ordinal);
                            var dashboardUri = new Uri(baseUri.GetLeftPart(UriPartial.Authority) + "/");
                            using var pageResponse = await _healthClient.GetAsync(dashboardUri);
                            using var scriptResponse = await _healthClient.GetAsync(new Uri(baseUri, "app.js"));
                            using var stylesResponse = await _healthClient.GetAsync(new Uri(baseUri, "site.css"));
                            if (healthResponse.IsSuccessStatusCode && isReady && isExpectedVersion &&
                                pageResponse.IsSuccessStatusCode &&
                                string.Equals(
                                    pageResponse.Content.Headers.ContentType?.MediaType,
                                    "text/html",
                                    StringComparison.OrdinalIgnoreCase) &&
                                scriptResponse.IsSuccessStatusCode &&
                                stylesResponse.IsSuccessStatusCode)
                            {
                                return true;
                            }

                            _logger.LogDebug(
                                "Service dashboard readiness check returned HTTP {HealthStatus}, {PageStatus}, {ScriptStatus}, and {StylesStatus}; Ready={Ready} ExpectedVersion={ExpectedVersion}.",
                                (int)healthResponse.StatusCode,
                                (int)pageResponse.StatusCode,
                                (int)scriptResponse.StatusCode,
                                (int)stylesResponse.StatusCode,
                                isReady,
                                isExpectedVersion);
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
                    catch (JsonException)
                    {
                        _logger.LogDebug("Dashboard readiness endpoint did not return the expected JSON response.");
                    }
                }

                await Task.Delay(1_000);
            }

            return false;
        }

        private static int? GetServiceHandoffParentProcessId(string[] arguments)
        {
            const string prefix = "--service-handoff-pid=";
            var argument = arguments.FirstOrDefault(value =>
                value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
            return argument is not null &&
                int.TryParse(argument[prefix.Length..], out var processId) &&
                processId > 0
                    ? processId
                    : null;
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

        private bool RunScCommand(params string[] arguments)
        {
            try
            {
                var startInfo = new ProcessStartInfo("sc.exe")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
                using var process = Process.Start(startInfo);
                if (process is null)
                {
                    return false;
                }

                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(30_000))
                {
                    process.Kill(entireProcessTree: true);
                    _logger.LogError("sc.exe {Operation} timed out.", arguments.FirstOrDefault() ?? "service operation");
                    return false;
                }

                Task.WaitAll(outputTask, errorTask);
                if (process.ExitCode == 0)
                {
                    return true;
                }

                var detail = string.IsNullOrWhiteSpace(errorTask.Result) ? outputTask.Result : errorTask.Result;
                _logger.LogWarning(
                    "sc.exe {Operation} failed with exit code {ExitCode}. {Output}",
                    arguments.FirstOrDefault() ?? "service operation",
                    process.ExitCode,
                    detail.Trim());
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
