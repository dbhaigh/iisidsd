using Microsoft.AspNetCore.Authentication;
using iisidsd.Runtime;
using iisidsd.Networking;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace iisidsd.Api;

public static class DashboardAccessPolicyMiddlewareExtensions
{
    public static IApplicationBuilder UseDashboardAccessPolicy(
        this IApplicationBuilder app,
        bool remoteAccessEnabled,
        IReadOnlyCollection<string>? allowedHosts = null)
        => app.Use(async (context, next) =>
        {
            context.Response.OnStarting(() =>
            {
                context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
                context.Response.Headers["X-Content-Type-Options"] = "nosniff";
                context.Response.Headers["X-Frame-Options"] = "DENY";
                context.Response.Headers["Referrer-Policy"] = "no-referrer";
                if (remoteAccessEnabled && context.Request.IsHttps)
                {
                    context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000";
                }

                return Task.CompletedTask;
            });

            if (!IsAllowedHost(context.Request.Host.Host, allowedHosts ?? DefaultAllowedHosts))
            {
                await WriteAuthorizationErrorAsync(context, StatusCodes.Status400BadRequest, "Bad Request");
                return;
            }

            if (!HttpMethods.IsGet(context.Request.Method) &&
                !HttpMethods.IsHead(context.Request.Method) &&
                !HttpMethods.IsOptions(context.Request.Method) &&
                !HasSameOrigin(context))
            {
                await WriteAuthorizationErrorAsync(context, StatusCodes.Status403Forbidden, "Forbidden");
                return;
            }

            var localRequest = DashboardAccessPolicy.IsLocalRequest(context.Connection.RemoteIpAddress);
            var accessDecision = DashboardAccessPolicy.Evaluate(
                remoteAccessEnabled,
                localRequest,
                context.Request.IsHttps);
            if (accessDecision == DashboardAccessDecision.Forbidden)
            {
                await WriteAuthorizationErrorAsync(context, StatusCodes.Status403Forbidden, "Forbidden");
                return;
            }

            if (accessDecision == DashboardAccessDecision.AuthenticationRequired &&
                context.User.Identity?.IsAuthenticated != true)
            {
                await context.ChallengeAsync();
                if (!context.Response.HasStarted)
                {
                    await WriteAuthorizationErrorAsync(context, StatusCodes.Status401Unauthorized, "Unauthorized");
                }

                return;
            }

            await next();
            if (!context.Response.HasStarted &&
                context.Response.ContentLength is null &&
                context.Response.StatusCode is StatusCodes.Status401Unauthorized or StatusCodes.Status403Forbidden)
            {
                var error = context.Response.StatusCode == StatusCodes.Status401Unauthorized ? "Unauthorized" : "Forbidden";
                await WriteAuthorizationErrorAsync(context, context.Response.StatusCode, error);
            }
        });

    private static readonly string[] DefaultAllowedHosts = ["localhost", "127.0.0.1", "::1"];

    private static bool IsAllowedHost(string? requestHost, IReadOnlyCollection<string> allowedHosts)
    {
        if (!SiteIdentityNormalizer.TryNormalizeHost(requestHost, out var normalizedRequestHost))
        {
            return false;
        }

        return allowedHosts.Any(allowedHost =>
            SiteIdentityNormalizer.TryNormalizeHost(allowedHost, out var normalizedAllowedHost) &&
            string.Equals(normalizedRequestHost, normalizedAllowedHost, StringComparison.OrdinalIgnoreCase));
    }

    private static bool HasSameOrigin(HttpContext context)
    {
        if (context.Request.Headers.TryGetValue("Sec-Fetch-Site", out var fetchSite) &&
            !string.Equals(fetchSite.ToString(), "same-origin", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var origin = context.Request.Headers.Origin;
        var referer = context.Request.Headers.Referer;
        if (origin.Count == 1 && Uri.TryCreate(origin[0], UriKind.Absolute, out var originUri))
        {
            if (originUri.AbsolutePath != "/" || originUri.Query.Length != 0 || originUri.Fragment.Length != 0)
            {
                return false;
            }

            return MatchesRequestOrigin(context, originUri);
        }

        if (origin.Count != 0 || referer.Count != 1 || !Uri.TryCreate(referer[0], UriKind.Absolute, out var refererUri))
        {
            return false;
        }

        return MatchesRequestOrigin(context, refererUri);
    }

    private static bool MatchesRequestOrigin(HttpContext context, Uri uri)
    {
        if (!string.IsNullOrEmpty(uri.UserInfo) ||
            !string.Equals(uri.Scheme, context.Request.Scheme, StringComparison.OrdinalIgnoreCase) ||
            !SiteIdentityNormalizer.TryNormalizeHost(uri.IdnHost, out var originHost) ||
            !SiteIdentityNormalizer.TryNormalizeHost(context.Request.Host.Host, out var requestHost))
        {
            return false;
        }

        var requestPort = context.Request.Host.Port ?? (context.Request.IsHttps ? 443 : 80);
        return string.Equals(originHost, requestHost, StringComparison.OrdinalIgnoreCase) && uri.Port == requestPort;
    }

    private static async Task WriteAuthorizationErrorAsync(HttpContext context, int statusCode, string error)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json; charset=utf-8";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.WriteAsJsonAsync(new { error });
    }
}
