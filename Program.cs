using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.ServiceProcess;
using System.Text.Json;
using iisidsd.Api;
using iisidsd.Configuration;
using iisidsd.Detection;
using iisidsd.Etw;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Notifications;
using iisidsd.Observability;
using iisidsd.Runtime;
using iisidsd.Services;
using iisidsd.Storage;
using iisidsd.Tray;
using Microsoft.Extensions.Options;
using OpenTelemetry.Metrics;

if (!RuntimePrerequisiteChecker.EnsureRuntimeAvailable())
{
    return;
}

var executableDirectory = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;
var filteredArgs = args
    .Where(arg =>
        !string.Equals(arg, "--tray-only", StringComparison.OrdinalIgnoreCase) &&
        !string.Equals(arg, "--suppress-dashboard-open", StringComparison.OrdinalIgnoreCase) &&
        !arg.StartsWith("--service-handoff-pid=", StringComparison.OrdinalIgnoreCase) &&
        !string.Equals(arg, "--service-handoff-allow-version-mismatch", StringComparison.OrdinalIgnoreCase))
    .ToArray();
var runWithTray = OperatingSystem.IsWindows() && Environment.UserInteractive;
var trayOnlyMode = runWithTray &&
    (args.Any(arg => string.Equals(arg, "--tray-only", StringComparison.OrdinalIgnoreCase)) ||
     IsServiceRunning("iisidsd"));

if (runWithTray)
{
    HideConsoleWindow();
}

if (trayOnlyMode)
{
    var trayBuilder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
    {
        Args = filteredArgs,
        ContentRootPath = executableDirectory
    });
    trayBuilder.Services.AddIisIdsdOptions(trayBuilder.Configuration);
    trayBuilder.Services.AddHostedService<TrayIconService>();

    var trayHost = trayBuilder.Build();
    await trayHost.RunAsync();
    return;
}

var isWindowsService = OperatingSystem.IsWindows() && !Environment.UserInteractive;
var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = filteredArgs,
    ContentRootPath = isWindowsService ? executableDirectory : null,
    WebRootPath = isWindowsService ? Path.Combine(executableDirectory, "wwwroot") : null
});
var configuredUrls = builder.Configuration["Urls"];
if (!string.IsNullOrWhiteSpace(configuredUrls))
{
    builder.WebHost.UseUrls(configuredUrls);
}

builder.Host.UseWindowsService(options =>
{
    options.ServiceName = "iisidsd";
});
builder.Services.AddIisIdsdOptions(builder.Configuration);
builder.Services.AddOptions<ForwardedHeadersOptions>()
    .Configure<IOptions<TrustedProxyOptions>>((options, trustedProxyOptionsAccessor) =>
        trustedProxyOptionsAccessor.Value.ConfigureForwardedHeaders(options));
builder.Services.AddOpenApi();
builder.Services.AddSingleton<IisObservability>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<SqliteHealthProbe>();
builder.Services.AddSingleton<IBackendConfigurationStore, BackendConfigurationStore>();

Uri? otlpEndpoint = null;
var configuredOtlpEndpoint = builder.Configuration["OpenTelemetry:OtlpEndpoint"];
if (!string.IsNullOrWhiteSpace(configuredOtlpEndpoint))
{
    if (!Uri.TryCreate(configuredOtlpEndpoint, UriKind.Absolute, out otlpEndpoint) ||
        (otlpEndpoint.Scheme != Uri.UriSchemeHttp && otlpEndpoint.Scheme != Uri.UriSchemeHttps))
    {
        throw new InvalidOperationException("OpenTelemetry:OtlpEndpoint must be an absolute HTTP or HTTPS URL.");
    }
}

builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics.AddMeter(IisObservability.MeterName);
        if (otlpEndpoint is not null)
        {
            metrics.AddOtlpExporter(exporter => exporter.Endpoint = otlpEndpoint);
        }
    });

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("DashboardAdministrator", policy =>
        policy.RequireAuthenticatedUser()
            .RequireAssertion(context => context.Resource is HttpContext httpContext &&
                DashboardAccessPolicy.CanAccessAdministratorFeatures(
                    context.User,
                    DashboardAccessPolicy.IsLocalRequest(httpContext.Connection.RemoteIpAddress))));
});
builder.Services.AddSingleton<IFindingStore, SqliteFindingStore>();
builder.Services.AddSingleton<IAnalystIncidentStore, SqliteAnalystIncidentStore>();
builder.Services.AddSingleton<INotificationQueue, SqliteNotificationQueue>();
builder.Services.AddSingleton<IWindowsEventLogWriter, WindowsEventLogWriter>();
builder.Services.AddSingleton<INotificationProvider, WindowsEventLogNotificationProvider>();
builder.Services.AddSingleton<IEventStore, SqliteEventStore>();
builder.Services.AddSingleton<IReplayableEventStore>(serviceProvider =>
    (IReplayableEventStore)serviceProvider.GetRequiredService<IEventStore>());
builder.Services.AddSingleton<IEventRetentionStore>(serviceProvider =>
    (IEventRetentionStore)serviceProvider.GetRequiredService<IEventStore>());
builder.Services.AddSingleton<IBanCountService, BanCountService>();
builder.Services.AddSingleton<IIpAggregationService, IpAggregationService>();
builder.Services.AddSingleton<IIisSiteDiscoveryService, IisSiteDiscoveryService>();
builder.Services.AddSingleton<IIpAllowList, IisIpAllowList>();
builder.Services.AddSingleton<IDenyListStore, SqliteDenyListStore>();
builder.Services.AddSingleton<IIisDenyListWriter, IisDenyListWriter>();
builder.Services.AddSingleton<IAppCmdRunner>(serviceProvider =>
    new AppCmdRunner(serviceProvider.GetRequiredService<ILogger<IisDenyListService>>()));
builder.Services.AddSingleton<IIisDenyListService, IisDenyListService>();
builder.Services.AddSingleton<IIisAutoDenyService, IisAutoDenyService>();
builder.Services.AddSingleton<SuspiciousActivityDetector>();
builder.Services.AddSingleton<IDetectionModule>(serviceProvider =>
    serviceProvider.GetRequiredService<SuspiciousActivityDetector>());
builder.Services.AddSingleton<ISuspiciousActivityDetector, DetectionEngine>();
builder.Services.AddHostedService<EventDbInitializer>();
builder.Services.AddHostedService<NotificationDeliveryService>();
builder.Services.AddHostedService<FindingPrunerService>();
builder.Services.AddHostedService<EventPrunerService>();
builder.Services.AddHostedService<TemporaryDenyListCleaner>();
builder.Services.AddHostedService<IisEtwListener>();
if (runWithTray)
{
    builder.Services.AddHostedService<TrayIconService>();
}

builder.Services.AddRouting();

var webApp = builder.Build();
if (webApp.Services.GetRequiredService<IOptions<TrustedProxyOptions>>().Value.Enabled)
{
    webApp.UseForwardedHeaders();
}

if (!webApp.Environment.WebRootFileProvider.GetFileInfo("index.html").Exists)
{
    webApp.Logger.LogError(
        "Dashboard UI index.html was not found under web root {WebRootPath}.",
        webApp.Environment.WebRootPath);
}

var dashboardOptions = webApp.Services.GetRequiredService<IOptions<DashboardOptions>>().Value;
var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
webApp.UseAuthentication();
dashboardOptions.TryGetCanonicalAllowedHosts(out var allowedHosts);
webApp.UseDashboardAccessPolicy(dashboardOptions.RemoteAccessEnabled, allowedHosts);
webApp.UseAuthorization();
webApp.UseDefaultFiles();
webApp.UseStaticFiles();

if (webApp.Environment.IsDevelopment())
{
    webApp.MapOpenApi();
}

webApp.MapDashboardEndpoints(jsonOptions);
webApp.MapBackendConfigurationEndpoints();

webApp.MapFallbackToFile("index.html");

if (runWithTray)
{
    var browserUrl = webApp.Services.GetRequiredService<IOptions<TrayOptions>>().Value.BrowserUrl;
    webApp.Lifetime.ApplicationStarted.Register(() => OpenDashboardBrowser(browserUrl, webApp.Logger));
}

webApp.Run();

static void OpenDashboardBrowser(string browserUrl, ILogger logger)
{
    try
    {
        Process.Start(new ProcessStartInfo(browserUrl) { UseShellExecute = true });
    }
    catch (Exception)
    {
        logger.LogError("Unable to open the iisidsd dashboard in the default browser.");
    }
}

static bool IsServiceRunning(string serviceName)
{
    try
    {
        using var service = new ServiceController(serviceName);
        service.Refresh();
        return service.Status == ServiceControllerStatus.Running;
    }
    catch
    {
        return false;
    }
}

static void HideConsoleWindow()
{
    NativeConsole.HideWindow();
}

internal static class NativeConsole
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    internal static void HideWindow()
    {
        var consoleWindow = GetConsoleWindow();
        if (consoleWindow != IntPtr.Zero)
        {
            _ = ShowWindow(consoleWindow, 0);
        }
    }
}
