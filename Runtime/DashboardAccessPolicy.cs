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

        if (remoteAccessEnabled && !isLocalRequest && !isHttps)
        {
            return DashboardAccessDecision.Forbidden;
        }

        if (remoteAccessEnabled && !isLocalRequest)
        {
            return DashboardAccessDecision.AuthenticationRequired;
        }

        return DashboardAccessDecision.Allowed;
    }

    public static bool IsWindowsAdministrator(ClaimsPrincipal principal)
        => principal.Identity is WindowsIdentity identity &&
            new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

    public static bool IsCurrentProcessAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static bool CanAccessAdministratorFeatures(
        ClaimsPrincipal principal,
        bool isLocalRequest,
        bool hostIsAdministrator)
        => IsWindowsAdministrator(principal) || (isLocalRequest && hostIsAdministrator);

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
