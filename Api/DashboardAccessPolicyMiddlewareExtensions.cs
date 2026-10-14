using System.Net;
using Microsoft.AspNetCore.Authentication;
using iisidsd.Runtime;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace iisidsd.Api;

public static class DashboardAccessPolicyMiddlewareExtensions
{
    public static IApplicationBuilder UseDashboardAccessPolicy(
        this IApplicationBuilder app,
        bool remoteAccessEnabled)
        => app.Use(async (context, next) =>
        {
            var localRequest = IsLocalRequest(context);
            var localHealthCheck = localRequest &&
                string.Equals(context.Request.Path.Value, "/health", StringComparison.OrdinalIgnoreCase);
            var accessDecision = DashboardAccessPolicy.Evaluate(
                remoteAccessEnabled,
                localRequest,
                context.Request.IsHttps,
                localHealthCheck);
            if (accessDecision == DashboardAccessDecision.Forbidden)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }

            if (accessDecision == DashboardAccessDecision.AuthenticationRequired &&
                context.User.Identity?.IsAuthenticated != true)
            {
                await context.ChallengeAsync();
                return;
            }

            await next();
        });

    private static bool IsLocalRequest(HttpContext context)
    {
        var remoteAddress = context.Connection.RemoteIpAddress;
        if (remoteAddress is null)
        {
            return false;
        }

        return remoteAddress.IsIPv4MappedToIPv6
            ? IPAddress.IsLoopback(remoteAddress.MapToIPv4())
            : IPAddress.IsLoopback(remoteAddress);
    }
}
