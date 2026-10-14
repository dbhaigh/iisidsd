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
        builder.Services.AddSingleton<IisObservability>();
        builder.Services.AddSingleton<SqliteHealthProbe>();
        builder.Services.AddSingleton<IEventStore>(_eventStore);
        builder.Services.AddSingleton<IIpAggregationService>(_aggregationService);
        builder.Services.AddSingleton<IBanCountService>(_banCountService);
        builder.Services.AddSingleton<IIisSiteDiscoveryService>(_siteDiscoveryService);
        builder.Services.AddSingleton<IIisDenyListService>(_denyListService);
        builder.Services.AddSingleton<IDenyListStore>(_denyListStore);
        builder.Services.AddSingleton<IIpAllowList>(_allowList);

        _app = builder.Build();
        _app.Use(async (context, next) =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.50");
            await next();
        });
        _app.UseAuthentication();
        _app.UseDashboardAccessPolicy(remoteAccessEnabled: true);
        _app.UseAuthorization();
        _app.MapDashboardEndpoints(new JsonSerializerOptions(JsonSerializerDefaults.Web));
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
            "/metrics",
            "/api/events",
            "/api/findings",
            $"/api/findings/{ClientIp}",
            $"/api/findings/{ClientIp}/events",
            "/api/ban-counts",
            "/api/iis/sites",
            "/api/iis/sites/Example%20Site/deny-list",
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
        Assert.True(health.RootElement.GetProperty("sqliteConnectionHealthy").GetBoolean());
        Assert.False(health.RootElement.GetProperty("dryRun").GetBoolean());
        Assert.Equal(JsonValueKind.Null, health.RootElement.GetProperty("lastAutoDeny").ValueKind);

        using var streamResponse = await SendAsync(HttpMethod.Get, "/api/events/stream", body: null, role: "user");
        var streamContent = await streamResponse.Content.ReadAsStringAsync();
        Assert.Contains("event: etw", streamContent);
        Assert.Contains(ClientIp, streamContent);
    }

    [Fact]
    public async Task AdministratorEndpoints_RejectAnonymousAndNonAdministrators_AndSucceedForAdministrators()
    {
        var cases = new[]
        {
            (HttpMethod.Get, "/api/iis/status", (string?)null),
            (HttpMethod.Get, "/api/export/findings", (string?)null),
            (HttpMethod.Get, "/api/export/events?format=csv", (string?)null),
            (HttpMethod.Put, $"/api/ban-counts/{ClientIp}?domain=example.test", """{"banCount":4}"""),
            (HttpMethod.Post, "/api/iis/sites/Example%20Site/deny-list", $$"""{"clientIp":"{{ClientIp}}"}"""),
            (HttpMethod.Post, "/api/iis/deny-list", $$"""{"clientIp":"{{ClientIp}}"}"""),
            (HttpMethod.Delete, $"/api/iis/sites/Example%20Site/deny-list/{ClientIp}", (string?)null)
        };

        foreach (var (method, path, body) in cases)
        {
            using var anonymousResponse = await SendAsync(method, path, body);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);

            using var nonAdministratorResponse = await SendAsync(method, path, body, "user");
            Assert.Equal(HttpStatusCode.Forbidden, nonAdministratorResponse.StatusCode);

            using var administratorResponse = await SendAsync(method, path, body, "administrator");
            Assert.Equal(HttpStatusCode.OK, administratorResponse.StatusCode);
        }

        Assert.Equal(1, _denyListService.AddCalls);
        Assert.Equal(1, _denyListService.AddToDomainsCalls);
        Assert.Equal(1, _denyListService.RemoveCalls);
        Assert.Equal(2, _banCountService.IncrementCalls);

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
        Assert.Equal(1, _denyListService.AddCalls);
        Assert.Equal(1, _denyListService.AddToDomainsCalls);
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

    private Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string? body, string? role = null)
    {
        var request = new HttpRequestMessage(method, path);
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

    private sealed class FakeEventStore : IEventStore
    {
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
            => new[] { _event }
                .Where(webEvent => clientIp is null || string.Equals(webEvent.ClientIp, clientIp, StringComparison.OrdinalIgnoreCase))
                .Where(webEvent => domain is null || string.Equals(webEvent.Domain, domain, StringComparison.OrdinalIgnoreCase))
                .Where(webEvent => !suspiciousOnly || webEvent.IsSuspicious)
                .Take(limit)
                .ToArray();

        public void Publish(SecurityEvent webEvent) => throw new NotSupportedException();

        public ChannelReader<SecurityEvent> Subscribe(CancellationToken cancellationToken)
        {
            var channel = Channel.CreateUnbounded<SecurityEvent>();
            channel.Writer.TryWrite(_event);
            channel.Writer.TryComplete();
            return channel.Reader;
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

        public IReadOnlyList<string> GetDeniedIps(string siteName) => [ClientIp];

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
            return ["Example Site"];
        }

        public bool RemoveDeniedIp(string siteName, string clientIp, string actor = "manual", string reason = "Manual deny-list removal")
        {
            RemoveCalls++;
            return true;
        }

        public bool RemoveExpiredDeniedIp(TemporaryDenyListEntry entry) => true;
    }

    private sealed class FakeDenyListStore : IDenyListStore
    {
        public long BeginAudit(DenyListAuditRecord record) => 1;
        public void CompleteAudit(long auditId, string outcome) { }
        public void SetAuditExpiry(long auditId, DateTimeOffset? expiresAt) { }
        public IReadOnlyList<DenyListAuditRecord> GetRecentAudit(int limit) => [];
        public DenyListAuditRecord? GetLastAutoDeny() => null;
        public DateTimeOffset? GetExpiry(string siteName, string clientIp) => null;
        public void SetExpiry(string siteName, string clientIp, DateTimeOffset expiresAt) { }
        public void RemoveExpiry(string siteName, string clientIp) { }
        public IReadOnlyList<TemporaryDenyListEntry> GetExpired(DateTimeOffset now, int limit, TemporaryDenyListEntry? after = null) => [];
    }

    private sealed class NonMatchingAllowList : IIpAllowList
    {
        public bool Matches { get; set; }
        public bool Contains(string? clientIp) => Matches && clientIp is not null;
    }
}
