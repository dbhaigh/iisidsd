using System.Text.Json;
using iisidsd.Configuration;
using iisidsd.Detection;
using iisidsd.Etw;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Services;
using iisidsd.Storage;
using iisidsd.Tray;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
builder.Services.Configure<IisEtwOptions>(builder.Configuration.GetSection(IisEtwOptions.SectionName));
builder.Services.Configure<DetectionOptions>(builder.Configuration.GetSection(DetectionOptions.SectionName));
builder.Services.Configure<TrayOptions>(builder.Configuration.GetSection(TrayOptions.SectionName));
builder.Services.Configure<StorageOptions>(builder.Configuration.GetSection(StorageOptions.SectionName));
builder.Services.Configure<IisAdminOptions>(builder.Configuration.GetSection(IisAdminOptions.SectionName));
builder.Services.AddSingleton<IEventStore, SqliteEventStore>();
builder.Services.AddSingleton<IBanCountService, BanCountService>();
builder.Services.AddSingleton<IIpAggregationService, IpAggregationService>();
builder.Services.AddSingleton<IIisSiteDiscoveryService, IisSiteDiscoveryService>();
builder.Services.AddSingleton<IIisDenyListService, IisDenyListService>();
builder.Services.AddSingleton<ISuspiciousActivityDetector, SuspiciousActivityDetector>();
builder.Services.AddHostedService<EventDbInitializer>();
builder.Services.AddHostedService<IisEtwListener>();
builder.Services.AddHostedService<TrayIconService>();

builder.Services.AddRouting();

var webApp = builder.Build();
var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
webApp.UseDefaultFiles();
webApp.UseStaticFiles();

webApp.MapGet("/health", () => Results.Ok(new { status = "ok", time = DateTimeOffset.UtcNow }));

webApp.MapGet("/api/events", (IEventStore store, int? limit, string? clientIp, string? domain, bool? suspiciousOnly) =>
    Results.Ok(store.GetRecent(limit ?? 100, clientIp, domain, suspiciousOnly ?? false)));

webApp.MapGet("/api/findings", (IIpAggregationService aggregationService, int? limit, string? domain) =>
    Results.Ok(aggregationService.GetFindings(limit ?? 100, domain)));

webApp.MapGet("/api/findings/{clientIp}", (IIpAggregationService aggregationService, string clientIp, string? domain) =>
{
    var finding = aggregationService.GetFinding(clientIp, domain);
    return finding is null ? Results.NotFound() : Results.Ok(finding);
});

webApp.MapGet("/api/findings/{clientIp}/events", (IEventStore store, string clientIp, int? limit, string? domain, bool? suspiciousOnly) =>
    Results.Ok(store.GetRecent(limit ?? 250, clientIp, domain, suspiciousOnly ?? false)));

webApp.MapGet("/api/ban-counts", (IBanCountService banCountService, int? limit) =>
    Results.Ok(banCountService.GetBanCounts(limit ?? 250)));

webApp.MapPut("/api/ban-counts/{clientIp}", (IBanCountService banCountService, string clientIp, BanCountUpdateRequest request) =>
{
    if (request.BanCount < 0)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            [nameof(request.BanCount)] = ["Ban count must be non-negative."]
        });
    }

    return Results.Ok(banCountService.SetBanCount(clientIp, request.BanCount));
});

webApp.MapGet("/api/iis/sites", (IIisSiteDiscoveryService siteDiscoveryService) =>
    Results.Ok(siteDiscoveryService.GetSites()));

webApp.MapGet("/api/iis/sites/{siteName}/deny-list", (IIisDenyListService denyListService, string siteName) =>
    Results.Ok(denyListService.GetDeniedIps(siteName)));

webApp.MapPost("/api/iis/sites/{siteName}/deny-list", (IIisDenyListService denyListService, IOptions<IisAdminOptions> adminOptions, string siteName, DeniedIpUpdateRequest request) =>
{
    if (!adminOptions.Value.EnableDenyListChanges)
    {
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }

    if (string.IsNullOrWhiteSpace(request.ClientIp))
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            [nameof(request.ClientIp)] = ["Client IP is required."]
        });
    }

    return denyListService.AddDeniedIp(siteName, request.ClientIp)
        ? Results.Ok(new { siteName, clientIp = request.ClientIp, denied = true })
        : Results.Problem($"Unable to add deny-list entry for '{request.ClientIp}' on '{siteName}'.");
});

webApp.MapDelete("/api/iis/sites/{siteName}/deny-list/{clientIp}", (IIisDenyListService denyListService, IOptions<IisAdminOptions> adminOptions, string siteName, string clientIp) =>
{
    if (!adminOptions.Value.EnableDenyListChanges)
    {
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }

    return denyListService.RemoveDeniedIp(siteName, clientIp)
        ? Results.Ok(new { siteName, clientIp, denied = false })
        : Results.Problem($"Unable to remove deny-list entry for '{clientIp}' on '{siteName}'.");
});

webApp.MapGet("/api/events/stream", async (HttpContext context, IEventStore store, string? clientIp, string? domain, bool? suspiciousOnly) =>
{
    context.Response.ContentType = "text/event-stream";
    context.Response.Headers.CacheControl = "no-cache";
    context.Response.Headers.Connection = "keep-alive";

    await foreach (var webEvent in store.Subscribe(context.RequestAborted).ReadAllAsync(context.RequestAborted))
    {
        if (clientIp is not null && !string.Equals(webEvent.ClientIp, clientIp, StringComparison.OrdinalIgnoreCase))
        {
            continue;
        }

        if (domain is not null && !string.Equals(webEvent.Domain, domain, StringComparison.OrdinalIgnoreCase))
        {
            continue;
        }

        if (suspiciousOnly == true && !webEvent.IsSuspicious)
        {
            continue;
        }

        await context.Response.WriteAsync($"event: etw\ndata: {JsonSerializer.Serialize(webEvent, jsonOptions)}\n\n", context.RequestAborted);
        await context.Response.Body.FlushAsync(context.RequestAborted);
    }
});

webApp.MapFallbackToFile("index.html");

webApp.Run();
