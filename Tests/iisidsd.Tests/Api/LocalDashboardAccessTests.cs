using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using iisidsd.Api;
using iisidsd.Runtime;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Api;

public sealed class LocalDashboardAccessTests
{
    [Fact]
    public async Task DefaultLoopbackMode_AllowsViewingButRejectsUnauthenticatedAndForgedAdministratorWrites()
    {
        var builder = WebApplication.CreateBuilder();
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
                policy.RequireAuthenticatedUser()
                    .RequireAssertion(context => DashboardAccessPolicy.CanAccessAdministratorFeatures(context.User))));

        var mutationCount = 0;
        var app = builder.Build();
        app.Use(async (context, next) =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Loopback;
            await next();
        });
        app.UseAuthentication();
        app.UseDashboardAccessPolicy(remoteAccessEnabled: false, ["localhost"]);
        app.UseAuthorization();
        app.MapGet("/api/events", () => Results.Ok(new { status = "viewable" }));
        app.MapPost("/api/management", () =>
        {
            mutationCount++;
            return Results.Ok();
        }).RequireAuthorization("DashboardAdministrator");

        await app.StartAsync();
        try
        {
            var client = app.GetTestClient();
            client.BaseAddress = new Uri("http://localhost");
            using var publicView = await client.GetAsync("/api/events");
            using var anonymousWrite = await SendWriteAsync(client, role: null);
            using var forgedAdministratorWrite = await SendWriteAsync(client, role: "administrator");

            Assert.Equal(HttpStatusCode.OK, publicView.StatusCode);
            Assert.Equal("nosniff", publicView.Headers.GetValues("X-Content-Type-Options").Single());
            Assert.Equal("DENY", publicView.Headers.GetValues("X-Frame-Options").Single());
            Assert.Equal("no-referrer", publicView.Headers.GetValues("Referrer-Policy").Single());
            Assert.False(publicView.Headers.Contains("Strict-Transport-Security"));
            Assert.Equal(HttpStatusCode.Unauthorized, anonymousWrite.StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, forgedAdministratorWrite.StatusCode);
            Assert.Equal(0, mutationCount);
        }
        finally
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }

    private static Task<HttpResponseMessage> SendWriteAsync(HttpClient client, string? role)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/management")
        {
            Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation("Origin", "http://localhost");
        if (role is not null)
        {
            request.Headers.Add(TestAuthenticationHandler.RoleHeader, role);
        }

        return client.SendAsync(request);
    }

    private sealed class TestAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string SchemeName = "local-test";
        public const string RoleHeader = "X-Test-Role";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(RoleHeader, out var role))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity(
                [new Claim(ClaimTypes.Role, role.ToString())],
                Scheme.Name);
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
        }
    }
}
