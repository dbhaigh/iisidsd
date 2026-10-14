using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
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

var filteredArgs = args
    .Where(arg =>
        !string.Equals(arg, "--tray-only", StringComparison.OrdinalIgnoreCase) &&
        !string.Equals(arg, "--suppress-dashboard-open", StringComparison.OrdinalIgnoreCase) &&
        !arg.StartsWith("--service-handoff-pid=", StringComparison.OrdinalIgnoreCase))
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
        ContentRootPath = AppContext.BaseDirectory
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
    ContentRootPath = isWindowsService ? AppContext.BaseDirectory : null,
    WebRootPath = isWindowsService ? Path.Combine(AppContext.BaseDirectory, "wwwroot") : null
});
builder.Host.UseWindowsService(options =>
{
    options.ServiceName = "iisidsd";
});
builder.Services.AddIisIdsdOptions(builder.Configuration);
builder.Services.AddSingleton<IisObservability>();
builder.Services.AddSingleton<SqliteHealthProbe>();

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
var hostIsAdministrator = DashboardAccessPolicy.IsCurrentProcessAdministrator();
var httpContextAccessor = new HttpContextAccessor();
builder.Services.AddSingleton<IHttpContextAccessor>(httpContextAccessor);
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("DashboardAdministrator", policy =>
        policy.RequireAssertion(context =>
            DashboardAccessPolicy.CanAccessAdministratorFeatures(
                context.User,
                httpContextAccessor.HttpContext is { } httpContext &&
                DashboardAccessPolicy.IsLocalRequest(httpContext.Connection.RemoteIpAddress),
                hostIsAdministrator)));
});
builder.Services.AddSingleton<IFindingStore, SqliteFindingStore>();
builder.Services.AddSingleton<IEventStore, SqliteEventStore>();
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
builder.Services.AddSingleton<ISuspiciousActivityDetector, SuspiciousActivityDetector>();
builder.Services.AddHostedService<EventDbInitializer>();
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
if (!webApp.Environment.WebRootFileProvider.GetFileInfo("index.html").Exists)
{
    webApp.Logger.LogError(
        "Dashboard UI index.html was not found under web root {WebRootPath}.",
        webApp.Environment.WebRootPath);
}

var remoteAccessEnabled = builder.Configuration.GetValue<bool>("Dashboard:RemoteAccessEnabled");
var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
webApp.UseAuthentication();
webApp.UseDashboardAccessPolicy(remoteAccessEnabled);
webApp.UseAuthorization();
webApp.UseDefaultFiles();
webApp.UseStaticFiles();

webApp.MapDashboardEndpoints(jsonOptions);

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
    catch (Exception exception)
    {
        logger.LogError(exception, "Unable to open the iisidsd dashboard at {Url}.", browserUrl);
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
