using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using iisidsd.Api;
using iisidsd.Configuration;
using iisidsd.Iis;
using iisidsd.Models;
using iisidsd.Observability;
using iisidsd.Services;
using iisidsd.Storage;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authorization;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Logging;

namespace iisidsd.Tests.Api;

public sealed class DashboardEndpointTests : IAsyncLifetime
{
    private const string ClientIp = "203.0.113.10";
    private readonly string _contentRoot = Path.Combine(Path.GetTempPath(), "iisidsd-api-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeEventStore _eventStore = new();
    private readonly FakeAggregationService _aggregationService = new();
    private readonly FakeBanCountService _banCountService = new();
    private readonly FakeSiteDiscoveryService _siteDiscoveryService = new();
    private readonly FakeDenyListService _denyListService = new();
    private readonly FakeDenyListStore _denyListStore = new();
    private readonly FakeAnalystIncidentStore _incidentStore = new();
    private readonly FakeNotificationQueue _notificationQueue = new();
    private readonly FakeBackendConfigurationStore _configurationStore = new();
    private readonly NonMatchingAllowList _allowList = new();
    private WebApplication _app = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_contentRoot);
        var databasePath = Path.Combine(_contentRoot, "health.sqlite3");
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString()))
        {
            connection.Open();
        }

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ContentRootPath = _contentRoot,
            EnvironmentName = "Development"
        });
        builder.WebHost.UseTestServer();
        builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = TestAuthenticationHandler.SchemeName;
                options.DefaultChallengeScheme = TestAuthenticationHandler.SchemeName;
            })
            .AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(
                TestAuthenticationHandler.SchemeName,
                _ => { });
        builder.Services.AddAuthorization(options =>
            options.AddPolicy("DashboardAdministrator", policy =>
                policy.RequireAuthenticatedUser().RequireRole("administrator")));
        builder.Services.Configure<StorageOptions>(options => options.DatabasePath = databasePath);
        builder.Services.Configure<IisAdminOptions>(options =>
        {
            options.EnableDenyListChanges = true;
            options.DryRun = false;
        });
        builder.Services.Configure<DashboardOptions>(options =>
        {
            options.MaximumEventStreamSubscribers = 2;
            options.EventStreamHeartbeatSeconds = 1;
            options.EventStreamWriteTimeoutSeconds = 2;
        });
        builder.Services.AddSingleton<IisObservability>();
        builder.Services.AddSingleton<SqliteHealthProbe>();
        builder.Services.AddSingleton<IBackendConfigurationStore>(_configurationStore);
        builder.Services.AddSingleton<IEventStore>(_eventStore);
        builder.Services.AddSingleton<IReplayableEventStore>(_eventStore);
        builder.Services.AddSingleton<IAnalystIncidentStore>(_incidentStore);
        builder.Services.AddSingleton<INotificationQueue>(_notificationQueue);
        builder.Services.AddSingleton<IIpAggregationService>(_aggregationService);
        builder.Services.AddSingleton<IBanCountService>(_banCountService);
        builder.Services.AddSingleton<IIisSiteDiscoveryService>(_siteDiscoveryService);
        builder.Services.AddSingleton<IIisDenyListService>(_denyListService);
        builder.Services.AddSingleton<IDenyListStore>(_denyListStore);
        builder.Services.AddSingleton<IIpAllowList>(_allowList);

        _app = builder.Build();
        _app.Use(async (context, next) =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse(
                context.Request.Headers["X-Test-Remote-IP"].FirstOrDefault() ?? "198.51.100.50");
            await next();
        });
        _app.UseAuthentication();
        _app.UseDashboardAccessPolicy(remoteAccessEnabled: true, ["localhost", "dashboard.example"]);
        _app.UseAuthorization();
        _app.MapDashboardEndpoints(new JsonSerializerOptions(JsonSerializerDefaults.Web));
        _app.MapBackendConfigurationEndpoints();
        _app.Services.GetRequiredService<IisObservability>()
            .SetEtwSubscriptionState(EtwSubscriptionState.Listening);
        await _app.StartAsync();
        _client = _app.GetTestClient();
        _client.BaseAddress = new Uri("https://localhost");
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_contentRoot))
        {
            Directory.Delete(_contentRoot, recursive: true);
        }
    }

    [Fact]
    public async Task PublicEndpoints_ReturnSuccessfulResponses()
    {
        var paths = new[]
        {
            "/health",
            "/health/live",
            "/health/ready",
            "/api/events",
            "/api/findings",
            $"/api/findings/{ClientIp}",
            $"/api/findings/{ClientIp}/events",
            "/api/events/stream"
        };

        foreach (var path in paths)
        {
            using var anonymousResponse = await _client.GetAsync(path);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);

            using var response = await SendAsync(HttpMethod.Get, path, body: null, role: "user");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        using var healthResponse = await SendAsync(HttpMethod.Get, "/health", body: null, role: "user");
        using var health = JsonDocument.Parse(await healthResponse.Content.ReadAsStringAsync());
        Assert.Equal("ok", health.RootElement.GetProperty("status").GetString());
        Assert.Equal("live", health.RootElement.GetProperty("liveness").GetString());
        Assert.Equal("ready", health.RootElement.GetProperty("readiness").GetString());
        Assert.Equal(12, health.RootElement.GetProperty("configurationRevision").GetString()?.Length);
        Assert.Equal("enforce", health.RootElement.GetProperty("enforcementMode").GetString());
        Assert.Equal(0, health.RootElement.GetProperty("droppedEventCount").GetInt64());
        Assert.Equal(JsonValueKind.Null, health.RootElement.GetProperty("lastEnforcement").ValueKind);
        Assert.DoesNotContain(ClientIp, health.RootElement.GetRawText());

        using var streamResponse = await SendAsync(HttpMethod.Get, "/api/events/stream?afterSequence=0", body: null, role: "user");
        var streamContent = await streamResponse.Content.ReadAsStringAsync();
        Assert.Contains("event: etw", streamContent);
        Assert.Contains(ClientIp, streamContent);
        var streamDiagnostics = _app.Services.GetRequiredService<IisObservability>()
            .GetOperationalDiagnosticsSnapshot("test", "test");
        Assert.Equal(0, streamDiagnostics.ActiveEventStreams);
        Assert.Equal(2, streamDiagnostics.EventStreamConnections);
    }

    [Fact]
    public async Task EventStream_OpensBeforeTheFirstEventArrives()
    {
        _eventStore.EmitOnSubscribe = false;
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/events/stream");
        request.Headers.Add(TestAuthenticationHandler.RoleHeader, "user");

        using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("no-cache", response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task Health_ReadinessTracksEtwWhileLivenessRemainsAvailable()
    {
        var observability = _app.Services.GetRequiredService<IisObservability>();
        observability.SetEtwSubscriptionState(EtwSubscriptionState.Unsupported);

        using var liveResponse = await SendAsync(HttpMethod.Get, "/health/live", body: null, role: "user");
        using var readyResponse = await SendAsync(HttpMethod.Get, "/health/ready", body: null, role: "user");

        Assert.Equal(HttpStatusCode.OK, liveResponse.StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, readyResponse.StatusCode);
        using var readiness = JsonDocument.Parse(await readyResponse.Content.ReadAsStringAsync());
        Assert.Equal("not-ready", readiness.RootElement.GetProperty("readiness").GetString());
        Assert.Equal("unsupported", readiness.RootElement.GetProperty("checks").GetProperty("etw").GetProperty("state").GetString());
    }

    [Fact]
    public async Task VersionedEvents_ReturnCursorPagesAndValidateBounds()
    {
        using var latestResponse = await SendAsync(HttpMethod.Get, "/api/v2/events?limit=10", body: null, role: "user");
        Assert.Equal(HttpStatusCode.OK, latestResponse.StatusCode);
        using var latest = JsonDocument.Parse(await latestResponse.Content.ReadAsStringAsync());
        Assert.Equal("latest", latest.RootElement.GetProperty("direction").GetString());
        var envelope = Assert.Single(latest.RootElement.GetProperty("items").EnumerateArray());
        Assert.Equal(1, envelope.GetProperty("cursor").GetInt64());
        Assert.Equal("iis.request", envelope.GetProperty("type").GetString());
        Assert.Equal(ClientIp, envelope.GetProperty("payload").GetProperty("clientIp").GetString());

        using var replayResponse = await SendAsync(HttpMethod.Get, "/api/v2/events?afterSequence=0", body: null, role: "user");
        using var replay = JsonDocument.Parse(await replayResponse.Content.ReadAsStringAsync());
        Assert.Equal("after", replay.RootElement.GetProperty("direction").GetString());
        Assert.Equal(1, replay.RootElement.GetProperty("items")[0].GetProperty("cursor").GetInt64());

        using var beforeResponse = await SendAsync(HttpMethod.Get, "/api/v2/events?beforeSequence=2", body: null, role: "user");
        using var before = JsonDocument.Parse(await beforeResponse.Content.ReadAsStringAsync());
        Assert.Equal(1, before.RootElement.GetProperty("items")[0].GetProperty("cursor").GetInt64());

        using var boundaryResponse = await SendAsync(HttpMethod.Get, "/api/v2/events?afterSequence=1", body: null, role: "user");
        using var boundary = JsonDocument.Parse(await boundaryResponse.Content.ReadAsStringAsync());
        Assert.Empty(boundary.RootElement.GetProperty("items").EnumerateArray());

        using var invalidLimit = await SendAsync(HttpMethod.Get, "/api/v2/events?limit=1001", body: null, role: "user");
        Assert.Equal(HttpStatusCode.BadRequest, invalidLimit.StatusCode);
    }

    [Fact]
    public async Task VersionedEventStream_ReplaysEnvelopeAndReportsRetentionGaps()
    {
        _eventStore.PrunedThroughSequence = 2;
        using var response = await SendAsync(HttpMethod.Get, "/api/v2/events/stream?afterSequence=0", body: null, role: "user");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var stream = await response.Content.ReadAsStringAsync();
        Assert.Contains("event: recovery", stream);
        Assert.Contains("retention_gap", stream);
        Assert.Contains("event: iis.event.v1", stream);
        Assert.Contains("\"cursor\":1", stream);
        Assert.Contains("\"type\":\"iis.request\"", stream);
        Assert.Contains("event: checkpoint", stream);
        Assert.Contains("id: 2", stream);
    }

    [Fact]
    public async Task VersionedEventStream_CheckpointsWhenRetentionRemovedEveryReplayRow()
    {
        _eventStore.EmitOnSubscribe = false;
        _eventStore.PruneAllEvents = true;
        _eventStore.PrunedThroughSequence = 1;
        using var response = await SendAsync(HttpMethod.Get, "/api/v2/events/stream?afterSequence=0", body: null, role: "user");
        var stream = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("retention_gap", stream);
        Assert.Contains("event: checkpoint", stream);
        Assert.Contains("id: 1", stream);
        Assert.DoesNotContain("event: iis.event.v1", stream);
    }

    [Fact]
    public async Task VersionedEventStream_ReplaysEventsPublishedDuringReconnectOnlyOnce()
    {
        _eventStore.PublishDuringSubscribe = true;
        using var response = await SendAsync(HttpMethod.Get, "/api/v2/events/stream?afterSequence=0", body: null, role: "user");
        var stream = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, stream.Split("event: iis.event.v1").Length - 1);
        Assert.Contains("/during-replay", stream);
        Assert.Contains("id: 2", stream);
    }

    [Fact]
    public async Task VersionedEventStream_UsesLastEventIdForReconnect()
    {
        using var request = CreateStreamRequest("/api/v2/events/stream?afterSequence=999");
        request.Headers.Add("Last-Event-ID", "0");
        using var response = await _client.SendAsync(request);
        var stream = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("event: iis.event.v1", stream);
        Assert.Contains("id: 1", stream);
    }

    [Fact]
    public async Task VersionedEventStream_SendsHeartbeatWhileNoEventsArrive()
    {
        _eventStore.EmitOnSubscribe = false;
        _eventStore.CompleteOnSubscribe = false;
        using var request = CreateStreamRequest("/api/v2/events/stream");
        using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        await using var stream = await response.Content.ReadAsStreamAsync();
        using var reader = new StreamReader(stream);

        Assert.Equal(": connected", await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal("retry: 1000", await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal(string.Empty, await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.StartsWith(": heartbeat ", await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.Equal(string.Empty, await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.StartsWith(": heartbeat ", await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(3)));
    }

    [Fact]
    public async Task EventStream_RejectsExcessConcurrentSubscribersAndProvidesRetryHint()
    {
        _eventStore.EmitOnSubscribe = false;
        _eventStore.CompleteOnSubscribe = false;
        var firstRequest = CreateStreamRequest("/api/v2/events/stream");
        var secondRequest = CreateStreamRequest("/api/v2/events/stream");
        using var firstResponse = await _client.SendAsync(firstRequest, HttpCompletionOption.ResponseHeadersRead);
        using var secondResponse = await _client.SendAsync(secondRequest, HttpCompletionOption.ResponseHeadersRead);
        using var thirdRequest = CreateStreamRequest("/api/v2/events/stream");
        using var thirdResponse = await _client.SendAsync(thirdRequest, HttpCompletionOption.ResponseHeadersRead);

        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, thirdResponse.StatusCode);
        Assert.Equal("1", thirdResponse.Headers.RetryAfter?.Delta?.TotalSeconds.ToString(CultureInfo.InvariantCulture));

        firstResponse.Dispose();
        secondResponse.Dispose();
        firstRequest.Dispose();
        secondRequest.Dispose();
    }

    [Fact]
    public async Task EventStream_ClientDisconnectReleasesSubscriberSlot()
    {
        _eventStore.EmitOnSubscribe = false;
        _eventStore.CompleteOnSubscribe = false;
        using var request = CreateStreamRequest("/api/v2/events/stream");
        using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        Assert.Equal(1, _eventStore.ActiveSubscriberCount);

        response.Dispose();
        request.Dispose();
        for (var attempt = 0; attempt < 50 && _eventStore.ActiveSubscriberCount != 0; attempt++)
        {
            await Task.Delay(10);
        }

        Assert.Equal(0, _eventStore.ActiveSubscriberCount);
    }

    [Fact]
    public async Task AdministratorEndpoints_RejectAnonymousAndNonAdministrators_AndSucceedForAdministrators()
    {
        var cases = new[]
        {
            (HttpMethod.Get, "/api/configuration", (string?)null),
            (HttpMethod.Get, "/metrics", (string?)null),
            (HttpMethod.Get, "/api/iis/status", (string?)null),
            (HttpMethod.Post, "/api/iis/deny-list/preview", $$"""{"siteName":"Example Site","clientIp":"{{ClientIp}}","evidence":["multiple indicators"]}"""),
            (HttpMethod.Get, "/api/ban-counts", (string?)null),
            (HttpMethod.Get, "/api/incidents?limit=500", (string?)null),
            (HttpMethod.Put, $"/api/incidents/{ClientIp}", """{"status":"acknowledged","note":"Reviewed"}"""),
            (HttpMethod.Get, "/api/notifications?limit=50", (string?)null),
            (HttpMethod.Get, "/api/notifications/status", (string?)null),
            (HttpMethod.Post, $"/api/notifications/{FakeNotificationQueue.NotificationId}/acknowledge", (string?)null),
            (HttpMethod.Get, "/api/iis/sites", (string?)null),
            (HttpMethod.Get, "/api/iis/sites/Example%20Site/deny-list", (string?)null),
            (HttpMethod.Get, "/api/export/findings", (string?)null),
            (HttpMethod.Get, "/api/export/events?format=csv", (string?)null),
            (HttpMethod.Put, $"/api/ban-counts/{ClientIp}?domain=example.test", """{"banCount":4}"""),
            (HttpMethod.Post, "/api/iis/sites/Example%20Site/deny-list", $$"""{"clientIp":"{{ClientIp}}"}"""),
            (HttpMethod.Post, "/api/iis/deny-list", $$"""{"clientIp":"{{ClientIp}}"}"""),
            (HttpMethod.Delete, $"/api/iis/sites/Example%20Site/deny-list/{ClientIp}", """{"reason":"Manual deny-list removal"}""")
        };

        foreach (var (method, path, body) in cases)
        {
            using var anonymousResponse = await SendAsync(method, path, body);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);

            using var nonAdministratorResponse = await SendAsync(method, path, body, "user");
            Assert.Equal(HttpStatusCode.Forbidden, nonAdministratorResponse.StatusCode);
            if (path == "/api/configuration")
            {
                using var unauthorizedBody = JsonDocument.Parse(await anonymousResponse.Content.ReadAsStringAsync());
                using var forbiddenBody = JsonDocument.Parse(await nonAdministratorResponse.Content.ReadAsStringAsync());
                Assert.Equal("Unauthorized", unauthorizedBody.RootElement.GetProperty("error").GetString());
                Assert.Equal("Forbidden", forbiddenBody.RootElement.GetProperty("error").GetString());
            }

            using var administratorResponse = await SendAsync(method, path, body, "administrator");
            Assert.Equal(HttpStatusCode.OK, administratorResponse.StatusCode);
        }

        Assert.Equal(1, _denyListService.AddCalls);
        Assert.Equal(1, _denyListService.AddToDomainsCalls);
        Assert.Equal(1, _denyListService.RemoveCalls);
        Assert.Equal(2, _banCountService.IncrementCalls);
        Assert.Equal(1, _incidentStore.SaveCalls);

        _denyListService.BulkAddedSites = [];
        using var duplicateBulkDeny = await SendAsync(
            HttpMethod.Post,
            "/api/iis/deny-list",
            $$"""{"clientIp":"{{ClientIp}}"}""",
            "administrator");
        Assert.Equal(HttpStatusCode.OK, duplicateBulkDeny.StatusCode);
        using var duplicateBulkBody = JsonDocument.Parse(await duplicateBulkDeny.Content.ReadAsStringAsync());
        Assert.Contains("Example Site", duplicateBulkBody.RootElement.GetProperty("alreadyPresentSites").EnumerateArray().Select(site => site.GetString()));
        Assert.Equal(2, _banCountService.IncrementCalls);

        _denyListService.RemovalStatus = DenyListRemovalStatus.NotServiceOwned;
        using var unmanagedRemoval = await SendAsync(
            HttpMethod.Delete,
            $"/api/iis/sites/Example%20Site/deny-list/{ClientIp}",
            "{\"reason\":\"Manual deny-list removal\"}",
            "administrator");
        Assert.Equal(HttpStatusCode.Conflict, unmanagedRemoval.StatusCode);

        _allowList.Matches = true;
        using var blockedSiteDeny = await SendAsync(
            HttpMethod.Post,
            "/api/iis/sites/Example%20Site/deny-list",
            $$"""{"clientIp":"{{ClientIp}}"}""",
            "administrator");
        using var blockedBulkDeny = await SendAsync(
            HttpMethod.Post,
            "/api/iis/deny-list",
            $$"""{"clientIp":"{{ClientIp}}"}""",
            "administrator");
        Assert.Equal(HttpStatusCode.Forbidden, blockedSiteDeny.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, blockedBulkDeny.StatusCode);
        Assert.Equal(2, _denyListService.AddCalls);
        Assert.Equal(3, _denyListService.AddToDomainsCalls);
    }

    [Fact]
    public async Task BackendConfigurationUpdate_RequiresAdministratorAndReportsRestartRequired()
    {
        const string body = """{"settings":{},"expectedRevision":"revision-1"}""";
        using var anonymousResponse = await SendAsync(HttpMethod.Patch, "/api/configuration", body);
        using var nonAdministratorResponse = await SendAsync(HttpMethod.Patch, "/api/configuration", body, "user");
        using var administratorResponse = await SendAsync(HttpMethod.Patch, "/api/configuration", body, "administrator");

        Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, nonAdministratorResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, administratorResponse.StatusCode);
        using var result = JsonDocument.Parse(await administratorResponse.Content.ReadAsStringAsync());
        Assert.True(result.RootElement.GetProperty("restartRequired").GetBoolean());
    }

    [Fact]
    public async Task LoopbackDashboard_RemainsViewableButManagementRequiresAdministrator()
    {
        using var publicView = await SendAsync(HttpMethod.Get, "/api/events", body: null, role: "user", remoteIp: "127.0.0.1");
        using var deniedWrite = await SendAsync(HttpMethod.Patch, "/api/configuration", """{"settings":{}}""",
            remoteIp: "127.0.0.1");
        using var deniedRead = await SendAsync(HttpMethod.Get, "/api/ban-counts", body: null, remoteIp: "127.0.0.1");
        using var deniedIisMutation = await SendAsync(HttpMethod.Post, "/api/iis/deny-list",
            $$"""{"clientIp":"{{ClientIp}}"}""", remoteIp: "127.0.0.1");

        Assert.Equal(HttpStatusCode.OK, publicView.StatusCode);
        Assert.Equal("DENY", publicView.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("frame-ancestors 'none'", publicView.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("nosniff", publicView.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", publicView.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal(HttpStatusCode.Unauthorized, deniedWrite.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, deniedRead.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, deniedIisMutation.StatusCode);
        using var authorizationError = JsonDocument.Parse(await deniedWrite.Content.ReadAsStringAsync());
        Assert.Equal("Unauthorized", authorizationError.RootElement.GetProperty("error").GetString());
        Assert.Equal(0, _denyListService.AddToDomainsCalls);
        Assert.Equal(0, _banCountService.IncrementCalls);
    }

    [Fact]
    public async Task RemoteAccess_RequiresHttpsAndWindowsAuthentication()
    {
        using var httpResponse = await SendAsync(HttpMethod.Get, "/api/findings", body: null, scheme: "http");
        using var anonymousHttpsResponse = await SendAsync(HttpMethod.Get, "/api/findings", body: null);
        using var authenticatedHttpsResponse = await SendAsync(HttpMethod.Get, "/api/findings", body: null, role: "user");
        using var customHostResponse = await SendAsync(HttpMethod.Get, "/api/findings", body: null, role: "user",
            host: "dashboard.example", origin: "https://dashboard.example");

        Assert.Equal(HttpStatusCode.Forbidden, httpResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousHttpsResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, authenticatedHttpsResponse.StatusCode);
        Assert.Contains("max-age=31536000", authenticatedHttpsResponse.Headers.GetValues("Strict-Transport-Security").Single());
        Assert.False(httpResponse.Headers.Contains("Strict-Transport-Security"));
        Assert.Equal(HttpStatusCode.OK, customHostResponse.StatusCode);
    }

    [Fact]
    public async Task UnsafeRequests_RejectCrossOriginAndHostileHostBeforeMutation()
    {
        using var crossOrigin = await SendAsync(HttpMethod.Post, "/api/iis/deny-list",
            $$"""{"clientIp":"{{ClientIp}}"}""", role: "administrator", origin: "https://attacker.example");
        using var hostileHost = await SendAsync(HttpMethod.Patch, "/api/configuration", """{"settings":{}}""",
            role: "administrator", host: "attacker.example", origin: "https://attacker.example");
        using var missingOrigin = await SendAsync(HttpMethod.Patch, "/api/configuration", """{"settings":{}}""",
            role: "administrator", origin: null);

        Assert.Equal(HttpStatusCode.Forbidden, crossOrigin.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, hostileHost.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, missingOrigin.StatusCode);
        Assert.Equal(0, _denyListService.AddToDomainsCalls);
        Assert.Equal(0, _banCountService.IncrementCalls);
        Assert.Equal(0, _configurationStore.SaveCalls);
    }

    [Fact]
    public async Task ExportEndpoints_ReturnJsonAndCsvDownloads_AndRejectUnknownFormats()
    {
        using var findingsResponse = await SendAsync(
            HttpMethod.Get,
            "/api/export/findings",
            body: null,
            role: "administrator");
        Assert.Equal(HttpStatusCode.OK, findingsResponse.StatusCode);
        Assert.Equal("application/json", findingsResponse.Content.Headers.ContentType?.MediaType);
        Assert.Equal("findings.json", findingsResponse.Content.Headers.ContentDisposition?.FileName?.Trim('"'));
        using var findings = JsonDocument.Parse(await findingsResponse.Content.ReadAsStringAsync());
        Assert.Equal(ClientIp, findings.RootElement[0].GetProperty("clientIp").GetString());

        using var eventsResponse = await SendAsync(
            HttpMethod.Get,
            "/api/export/events?format=csv",
            body: null,
            role: "administrator");
        Assert.Equal(HttpStatusCode.OK, eventsResponse.StatusCode);
        Assert.Equal("text/csv", eventsResponse.Content.Headers.ContentType?.MediaType);
        var csv = await eventsResponse.Content.ReadAsStringAsync();
        Assert.Contains("\"eventId\"", csv);
        Assert.Contains($"\"{ClientIp}\"", csv);

        using var invalidFormatResponse = await SendAsync(
            HttpMethod.Get,
            "/api/export/events?format=xml",
            body: null,
            role: "administrator");
        Assert.Equal(HttpStatusCode.BadRequest, invalidFormatResponse.StatusCode);
    }

    private Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        string? body,
        string? role = null,
        string? origin = "https://localhost",
        string remoteIp = "198.51.100.50",
        string host = "localhost",
        string scheme = "https")
    {
        var request = new HttpRequestMessage(method, $"{scheme}://localhost{path}");
        request.Headers.Host = host;
        request.Headers.Add("X-Test-Remote-IP", remoteIp);
        if (method != HttpMethod.Get && method != HttpMethod.Head && method != HttpMethod.Options)
        {
            if (origin is not null)
            {
                request.Headers.TryAddWithoutValidation("Origin", origin);
                request.Headers.TryAddWithoutValidation("Sec-Fetch-Site",
                    string.Equals(origin, $"{scheme}://{host}", StringComparison.OrdinalIgnoreCase) ? "same-origin" : "cross-site");
            }
        }

        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        if (role is not null)
        {
            request.Headers.Add(TestAuthenticationHandler.RoleHeader, role);
        }

        return _client.SendAsync(request);
    }

    private static HttpRequestMessage CreateStreamRequest(string path)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add(TestAuthenticationHandler.RoleHeader, "user");
        return request;
    }

    private sealed class TestAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string SchemeName = "test";
        public const string RoleHeader = "X-Test-Role";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(RoleHeader, out var role))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var claims = new List<Claim> { new(ClaimTypes.Name, "test-user") };
            if (string.Equals(role.ToString(), "administrator", StringComparison.OrdinalIgnoreCase))
            {
                claims.Add(new Claim(ClaimTypes.Role, "administrator"));
            }

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }

    private sealed class FakeEventStore : IEventStore, IReplayableEventStore
    {
        private readonly object _sync = new();
        private readonly List<StoredSecurityEvent> _events;
        private readonly Dictionary<Guid, Channel<SecurityEvent>> _subscribers = [];
        private long _nextSequenceId = 2;

        public FakeEventStore()
        {
            _events = [ToStored(_event, 1)];
        }

        public bool EmitOnSubscribe { get; set; } = true;
        public bool CompleteOnSubscribe { get; set; } = true;
        public bool PublishDuringSubscribe { get; set; }
        public bool PruneAllEvents { get; set; }
        public int MaximumSubscribers { get; set; } = 2;
        public long PrunedThroughSequence { get; set; }
        public int ActiveSubscriberCount
        {
            get { lock (_sync) return _subscribers.Count; }
        }

        private readonly SecurityEvent _event = new(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/test",
            ClientIp,
            404,
            "test-agent",
            new Dictionary<string, string>(),
            IsSuspicious: true,
            DetectionReason: "test detection",
            RiskScore: 9,
            RiskSeverity: "Critical",
            RiskIndicators: ["test-indicator"]);

        public IReadOnlyList<SecurityEvent> GetRecent(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
        {
            lock (_sync)
            {
                return FilterEvents(clientIp, domain, suspiciousOnly)
                    .Reverse()
                    .Take(limit)
                    .Select(webEvent => webEvent.ToSecurityEvent())
                    .ToArray();
            }
        }

        public EventPage<StoredSecurityEvent> GetLatestPage(int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
        {
            lock (_sync)
            {
                var matching = FilterEvents(clientIp, domain, suspiciousOnly).ToArray();
                var items = matching.TakeLast(limit).ToArray();
                return CreatePage(items, matching.Length > limit, false);
            }
        }

        public EventPage<StoredSecurityEvent> GetPageAfter(long afterSequence, int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
        {
            lock (_sync)
            {
                var matching = FilterEvents(clientIp, domain, suspiciousOnly).Where(webEvent => webEvent.SequenceId > afterSequence).Take(limit + 1).ToArray();
                var hasMore = matching.Length > limit;
                if (hasMore) matching = matching[..limit];
                return CreatePage(matching, hasMore, afterSequence < PrunedThroughSequence);
            }
        }

        public EventPage<StoredSecurityEvent> GetPageBefore(long beforeSequence, int limit, string? clientIp = null, string? domain = null, bool suspiciousOnly = false)
        {
            lock (_sync)
            {
                var matching = FilterEvents(clientIp, domain, suspiciousOnly)
                    .Where(webEvent => webEvent.SequenceId < beforeSequence)
                    .TakeLast(limit + 1)
                    .ToArray();
                var hasMore = matching.Length > limit;
                if (hasMore) matching = matching[1..];
                return CreatePage(matching, hasMore, false);
            }
        }

        public void Publish(SecurityEvent webEvent)
        {
            lock (_sync)
            {
                var stored = ToStored(webEvent, _nextSequenceId++);
                _events.Add(stored);
                foreach (var channel in _subscribers.Values)
                {
                    channel.Writer.TryWrite(stored.ToSecurityEvent());
                }
            }
        }

        public ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken)
            => SubscribeWithCursor(cancellationToken).Reader;

        public EventStreamSubscription SubscribeWithCursor(CancellationToken cancellationToken)
        {
            lock (_sync)
            {
                if (_subscribers.Count >= MaximumSubscribers)
                {
                    throw new EventStreamSubscriberLimitException();
                }

                var id = Guid.NewGuid();
                var channel = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(8)
                {
                    FullMode = BoundedChannelFullMode.Wait,
                    SingleReader = true,
                    SingleWriter = false
                });
                _subscribers[id] = channel;
                if (EmitOnSubscribe)
                {
                    foreach (var webEvent in _events)
                    {
                        channel.Writer.TryWrite(webEvent.ToSecurityEvent());
                    }
                }

                var initialCursor = Math.Max(_events.Count == 0 ? 0 : _events[^1].SequenceId, PrunedThroughSequence);
                if (PublishDuringSubscribe)
                {
                    Publish(_event with { Id = Guid.NewGuid().ToString("N"), Path = "/during-replay" });
                }

                if (CompleteOnSubscribe)
                {
                    channel.Writer.TryComplete();
                    _subscribers.Remove(id);
                }
                else
                {
                    cancellationToken.Register(() => RemoveSubscriber(id));
                }

                return new EventStreamSubscription(channel.Reader, initialCursor);
            }
        }

        private IEnumerable<StoredSecurityEvent> FilterEvents(string? clientIp, string? domain, bool suspiciousOnly)
        {
            if (PruneAllEvents) return Enumerable.Empty<StoredSecurityEvent>();
            return _events
                .Where(webEvent => clientIp is null || string.Equals(webEvent.ClientIp, clientIp, StringComparison.OrdinalIgnoreCase))
                .Where(webEvent => domain is null || string.Equals(webEvent.Domain, domain, StringComparison.OrdinalIgnoreCase))
                .Where(webEvent => !suspiciousOnly || webEvent.IsSuspicious);
        }

        private EventPage<StoredSecurityEvent> CreatePage(StoredSecurityEvent[] items, bool hasMore, bool gapDetected)
            => new(
                items,
                items.Length == 0 ? null : items[0].SequenceId,
                items.Length == 0 ? null : items[^1].SequenceId,
                Math.Max(_events.Count == 0 ? 0 : _events[^1].SequenceId, PrunedThroughSequence),
                hasMore,
                gapDetected,
                _events.Count == 0 || PruneAllEvents ? null : _events[0].SequenceId,
                PrunedThroughSequence);

        private void RemoveSubscriber(Guid id)
        {
            lock (_sync)
            {
                if (_subscribers.Remove(id, out var channel)) channel.Writer.TryComplete();
            }
        }

        private static StoredSecurityEvent ToStored(SecurityEvent webEvent, long sequenceId)
            => new(
                sequenceId,
                webEvent.Id,
                webEvent.Timestamp,
                webEvent.Server,
                webEvent.Domain,
                webEvent.Method,
                webEvent.Path,
                webEvent.ClientIp,
                webEvent.StatusCode,
                webEvent.UserAgent,
                webEvent.Properties,
                webEvent.IsSuspicious,
                webEvent.DetectionReason,
                webEvent.RiskScore,
                webEvent.RiskSeverity,
                webEvent.RiskIndicators ?? []);
    }

    private sealed class FakeAnalystIncidentStore : IAnalystIncidentStore
    {
        public int SaveCalls { get; private set; }

        public IReadOnlyList<AnalystIncidentRecord> List(int limit = 500) => [];

        public AnalystIncidentRecord? Get(string clientIp) => null;

        public AnalystIncidentRecord Save(string clientIp, string status, string note, string updatedBy)
        {
            SaveCalls++;
            return new AnalystIncidentRecord(clientIp, status, note, DateTimeOffset.UtcNow, updatedBy);
        }
    }

    private sealed class FakeNotificationQueue : INotificationQueue
    {
        public const string NotificationId = "00000000000000000000000000000001";
        private NotificationIncident? _incident = new(
            NotificationId,
            ClientIp,
            "example.test",
            "High suspicious activity",
            8,
            "High",
            DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch,
            [],
            "delivered",
            1,
            null,
            DateTimeOffset.UnixEpoch,
            null,
            null,
            null);

        public NotificationEnqueueResult Enqueue(SecurityEvent webEvent, SqliteConnection connection, SqliteTransaction transaction)
            => NotificationEnqueueResult.NotEligible;

        public IReadOnlyList<NotificationIncident> List(int limit = 250)
            => _incident is null ? [] : [_incident];

        public IReadOnlyList<NotificationIncident> GetDue(DateTimeOffset now, int limit = 25) => [];

        public NotificationQueueStatus GetStatus() => new(0, 0, 1, 0, 0, 0);

        public int PruneExpired(DateTimeOffset olderThanUtc) => 0;

        public void RecordDelivered(string id, DateTimeOffset attemptedAtUtc) { }

        public void RecordFailure(string id, DateTimeOffset attemptedAtUtc, string failureType) { }

        public NotificationIncident? Acknowledge(string id, DateTimeOffset acknowledgedAtUtc, string acknowledgedBy)
        {
            if (_incident?.Id != id) return null;
            _incident = _incident with { Status = "acknowledged", AcknowledgedAtUtc = acknowledgedAtUtc, AcknowledgedBy = acknowledgedBy };
            return _incident;
        }
    }

    private sealed class FakeBackendConfigurationStore : IBackendConfigurationStore
    {
        private static readonly JsonElement Settings = JsonDocument
            .Parse("""{"Urls":"http://127.0.0.1:5080"}""")
            .RootElement
            .Clone();
        public int SaveCalls { get; private set; }

        public Task<JsonElement> GetSettingsAsync(CancellationToken cancellationToken)
            => Task.FromResult(Settings);

        public Task<BackendConfigurationSnapshot> GetConfigurationSnapshotAsync(CancellationToken cancellationToken)
            => Task.FromResult(new BackendConfigurationSnapshot(Settings, "revision-1"));

        public Task<BackendConfigurationSaveResult> SaveSettingsAsync(
            JsonElement settings,
            CancellationToken cancellationToken)
        {
            SaveCalls++;
            return Task.FromResult(new BackendConfigurationSaveResult(true, new Dictionary<string, string[]>()));
        }

        public Task<BackendConfigurationSaveResult> SaveSettingsAsync(
            JsonElement settings,
            string expectedRevision,
            CancellationToken cancellationToken)
        {
            SaveCalls++;
            return Task.FromResult(new BackendConfigurationSaveResult(true, new Dictionary<string, string[]>(), "revision-2"));
        }
    }

    private sealed class FakeAggregationService : IIpAggregationService
    {
        private readonly IpFinding _finding = new(
            ClientIp,
            12,
            4,
            9,
            "Critical",
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow,
            ["example.test"],
            ["test detection"],
            ["test-indicator"]);

        public IReadOnlyList<IpFinding> GetFindings(int limit, string? domain = null)
            => new[] { _finding }
                .Where(finding => domain is null || finding.Domains.Contains(domain, StringComparer.OrdinalIgnoreCase))
                .Take(limit)
                .ToArray();

        public IpFinding? GetFinding(string clientIp, string? domain = null)
            => string.Equals(clientIp, ClientIp, StringComparison.OrdinalIgnoreCase) &&
               (domain is null || _finding.Domains.Contains(domain, StringComparer.OrdinalIgnoreCase))
                ? _finding
                : null;
    }

    private sealed class FakeBanCountService : IBanCountService
    {
        public int IncrementCalls { get; private set; }

        public IReadOnlyList<BanCountRecord> GetBanCounts(int limit, string? domain = null)
            => [new BanCountRecord(ClientIp, 2, DateTimeOffset.UtcNow)];

        public IReadOnlyDictionary<string, BanCountRecord> GetBanCounts(IEnumerable<string> clientIps, string? domain = null)
            => clientIps.Distinct(StringComparer.OrdinalIgnoreCase)
                .ToDictionary(ip => ip, ip => new BanCountRecord(ip, 2, DateTimeOffset.UtcNow), StringComparer.OrdinalIgnoreCase);

        public BanCountRecord GetBanCount(string clientIp, string? domain = null)
            => new(clientIp, 2, DateTimeOffset.UtcNow);

        public BanCountRecord SetBanCount(string clientIp, int banCount, string? domain = null)
            => new(clientIp, banCount, DateTimeOffset.UtcNow);

        public void IncrementBanCounts(string clientIp, IEnumerable<string> domains)
            => IncrementCalls++;
    }

    private sealed class FakeSiteDiscoveryService : IIisSiteDiscoveryService
    {
        private readonly IisSiteInfo _site = new(1, "Example Site", "Started", [], ["example.test"]);

        public IReadOnlyList<IisSiteInfo> GetSites() => [_site];
        public IisSiteInfo? FindSiteByDomain(string domain) => _site;
    }

    private sealed class FakeDenyListService : IIisDenyListService
    {
        public int AddCalls { get; private set; }
        public int AddToDomainsCalls { get; private set; }
        public int RemoveCalls { get; private set; }
        public IReadOnlyList<string> BulkAddedSites { get; set; } = ["Example Site"];
        public DenyListRemovalStatus RemovalStatus { get; set; } = DenyListRemovalStatus.Removed;

        public IReadOnlyList<string> GetDeniedIps(string siteName) => [ClientIp];
        public DenyListPreview? PreviewDeniedIp(DenyListPreviewRequest request, string actor = "manual")
            => new(request.SiteName, request.ClientIp, $"ipAddress={request.ClientIp}; allowed=false", null,
                "Enforce", false, true, "missing", request.Evidence ?? [], [], [], []);

        public bool AddDeniedIp(
            string siteName,
            string clientIp,
            string actor = "manual",
            string reason = "Manual deny-list request",
            SecurityEvent? securityEvent = null,
            string? domain = null)
        {
            AddCalls++;
            return true;
        }

        public IReadOnlyList<string> AddDeniedIpToDomains(
            string clientIp,
            IEnumerable<string> domains,
            string actor = "manual",
            string reason = "Manual deny-list request",
            SecurityEvent? securityEvent = null)
        {
            AddToDomainsCalls++;
            return BulkAddedSites;
        }

        public bool RemoveDeniedIp(string siteName, string clientIp, string actor = "manual", string reason = "Manual deny-list removal")
        {
            RemoveCalls++;
            return RemovalStatus == DenyListRemovalStatus.Removed;
        }

        public DenyListRemovalStatus RemoveDeniedIpWithStatus(
            string siteName,
            string clientIp,
            string actor = "manual",
            string reason = "Manual deny-list removal")
        {
            RemoveCalls++;
            return RemovalStatus;
        }

        public bool RemoveExpiredDeniedIp(TemporaryDenyListEntry entry) => true;
        public void ReconcilePendingManagedDenies() { }
    }

    private sealed class FakeDenyListStore : IDenyListStore
    {
        public IDisposable AcquireMutationLock() => new NoopDisposable();
        public long BeginAudit(DenyListAuditRecord record) => 1;
        public long RecordAudit(DenyListAuditRecord record) => 1;
        public void CompleteAudit(long auditId, string outcome) { }
        public void SetAuditExpiry(long auditId, DateTimeOffset? expiresAt) { }
        public IReadOnlyList<DenyListAuditRecord> GetRecentAudit(int limit) => [];
        public DenyListAuditRecord? GetLastAutoDeny() => null;
        public DateTimeOffset? GetExpiry(string siteName, string clientIp) => null;
        public void SetExpiry(string siteName, string clientIp, DateTimeOffset expiresAt) { }
        public void RemoveExpiry(string siteName, string clientIp) { }
        public ManagedDenyListEntry? GetManagedDeny(string siteName, string clientIp) => null;
        public IReadOnlyList<ManagedDenyListEntry> GetPendingManagedDenies(int limit) => [];
        public bool TryPrepareManagedDeny(ManagedDenyListEntry entry) => true;
        public bool CompleteManagedDeny(string siteName, string clientIp, DateTimeOffset? expiresAt, long auditId) => true;
        public bool TryTransitionManagedDeny(string siteName, string clientIp, string expectedState, long expectedAuditId, string state, long auditId) => true;
        public bool TryRemoveManagedDeny(string siteName, string clientIp, string expectedState, long expectedAuditId) => true;
        public IReadOnlyList<TemporaryDenyListEntry> GetExpired(DateTimeOffset now, int limit, TemporaryDenyListEntry? after = null) => [];

        private sealed class NoopDisposable : IDisposable
        {
            public void Dispose() { }
        }
    }

    private sealed class NonMatchingAllowList : IIpAllowList
    {
        public bool Matches { get; set; }
        public bool Contains(string? clientIp) => Matches && clientIp is not null;
    }
}
