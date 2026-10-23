using System.Security.Principal;
using System.Security.Claims;
using System.Net;

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
        bool isHttps)
    {
        if (!remoteAccessEnabled && !isLocalRequest)
        {
            return DashboardAccessDecision.Forbidden;
        }

        if (remoteAccessEnabled && !isHttps)
        {
            return DashboardAccessDecision.Forbidden;
        }

        if (remoteAccessEnabled)
        {
            return DashboardAccessDecision.AuthenticationRequired;
        }

        return DashboardAccessDecision.Allowed;
    }

    public static bool IsWindowsAdministrator(ClaimsPrincipal principal)
        => principal.Identity is WindowsIdentity identity &&
            new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

    public static bool CanAccessAdministratorFeatures(ClaimsPrincipal principal, bool isLocalRequest = false)
    {
        if (IsWindowsAdministrator(principal))
        {
            return true;
        }

        return isLocalRequest &&
            principal.Identity is WindowsIdentity identity &&
            identity.IsAuthenticated &&
            identity.Claims.Any(claim =>
                claim.Type == ClaimTypes.DenyOnlySid &&
                claim.Value == "S-1-5-32-544");
    }

    public static bool IsLocalRequest(IPAddress? remoteAddress)
    {
        if (remoteAddress is null)
        {
            return false;
        }

        return remoteAddress.IsIPv4MappedToIPv6
            ? IPAddress.IsLoopback(remoteAddress.MapToIPv4())
            : IPAddress.IsLoopback(remoteAddress);
    }
}
