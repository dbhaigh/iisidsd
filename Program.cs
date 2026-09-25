using System.Text.Json;
using iisidsd.Configuration;
using iisidsd.Detection;
using iisidsd.Etw;
using iisidsd.Models;
using iisidsd.Storage;
using iisidsd.Tray;

var builder = WebApplication.CreateBuilder(args);
builder.Services.Configure<IisEtwOptions>(builder.Configuration.GetSection(IisEtwOptions.SectionName));
builder.Services.Configure<DetectionOptions>(builder.Configuration.GetSection(DetectionOptions.SectionName));
builder.Services.Configure<TrayOptions>(builder.Configuration.GetSection(TrayOptions.SectionName));
builder.Services.AddSingleton<IEventStore, InMemoryEventStore>();
builder.Services.AddSingleton<ISuspiciousActivityDetector, SuspiciousActivityDetector>();
builder.Services.AddHostedService<IisEtwListener>();
builder.Services.AddHostedService<TrayIconService>();

builder.Services.AddRouting();

var webApp = builder.Build();
var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
webApp.UseDefaultFiles();
webApp.UseStaticFiles();

webApp.MapGet("/health", () => Results.Ok(new { status = "ok", time = DateTimeOffset.UtcNow }));

webApp.MapGet("/api/events", (IEventStore store, int? limit) =>
    Results.Ok(store.GetRecent(limit ?? 100)));

webApp.MapGet("/api/events/stream", async (HttpContext context, IEventStore store) =>
{
    context.Response.ContentType = "text/event-stream";
    context.Response.Headers.CacheControl = "no-cache";
    context.Response.Headers.Connection = "keep-alive";

    await foreach (var webEvent in store.Subscribe(context.RequestAborted).ReadAllAsync(context.RequestAborted))
    {
        await context.Response.WriteAsync($"event: etw\ndata: {JsonSerializer.Serialize(webEvent, jsonOptions)}\n\n", context.RequestAborted);
        await context.Response.Body.FlushAsync(context.RequestAborted);
    }
});

webApp.MapFallbackToFile("index.html");

webApp.Run();
