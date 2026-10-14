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
            var localRequest = DashboardAccessPolicy.IsLocalRequest(context.Connection.RemoteIpAddress);
            var accessDecision = DashboardAccessPolicy.Evaluate(
                remoteAccessEnabled,
                localRequest,
                context.Request.IsHttps);
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
}
