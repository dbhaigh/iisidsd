using System.Security.Principal;
using System.Security.Claims;

namespace iisidsd.Runtime;

public enum DashboardAccessDecision
{
    Allowed,
    Forbidden,
    AuthenticationRequired
}

public static class DashboardAccessPolicy
{
    public static DashboardAccessDecision Evaluate(
        bool remoteAccessEnabled,
        bool isLocalRequest,
        bool isHttps,
        bool isLocalHealthCheck)
    {
        if (!remoteAccessEnabled && !isLocalRequest)
        {
            return DashboardAccessDecision.Forbidden;
        }

        if (remoteAccessEnabled && !isLocalRequest && !isHttps)
        {
            return DashboardAccessDecision.Forbidden;
        }

        if (remoteAccessEnabled && !(isLocalRequest && isLocalHealthCheck))
        {
            return DashboardAccessDecision.AuthenticationRequired;
        }

        return DashboardAccessDecision.Allowed;
    }

    public static bool IsWindowsAdministrator(ClaimsPrincipal principal)
        => principal.Identity is WindowsIdentity identity &&
            new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
}
