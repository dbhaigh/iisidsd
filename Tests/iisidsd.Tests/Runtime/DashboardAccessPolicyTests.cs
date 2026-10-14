using System.Security.Claims;
using iisidsd.Runtime;

namespace iisidsd.Tests.Runtime;

public sealed class DashboardAccessPolicyTests
{
    [Theory]
    [InlineData(false, true, false, DashboardAccessDecision.Allowed)]
    [InlineData(false, false, false, DashboardAccessDecision.Forbidden)]
    [InlineData(true, false, false, DashboardAccessDecision.Forbidden)]
    [InlineData(true, false, true, DashboardAccessDecision.AuthenticationRequired)]
    [InlineData(true, true, false, DashboardAccessDecision.Allowed)]
    [InlineData(true, true, true, DashboardAccessDecision.Allowed)]
    public void Evaluate_ReturnsExpectedAccessDecision(
        bool remoteAccessEnabled,
        bool isLocalRequest,
        bool isHttps,
        DashboardAccessDecision expected)
    {
        var decision = DashboardAccessPolicy.Evaluate(remoteAccessEnabled, isLocalRequest, isHttps);

        Assert.Equal(expected, decision);
    }

    [Fact]
    public void IsWindowsAdministrator_RejectsRoleClaimsFromNonWindowsIdentity()
    {
        var identity = new ClaimsIdentity(
            [new Claim(ClaimsIdentity.DefaultRoleClaimType, "Administrators")],
            authenticationType: "test");
        var principal = new ClaimsPrincipal(identity);

        Assert.False(DashboardAccessPolicy.IsWindowsAdministrator(principal));
    }

    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    public void CanAccessAdministratorFeatures_UsesElevatedHostOnlyForLocalRequests(
        bool isLocalRequest,
        bool hostIsAdministrator,
        bool expected)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        var canAccess = DashboardAccessPolicy.CanAccessAdministratorFeatures(
            principal,
            isLocalRequest,
            hostIsAdministrator);

        Assert.Equal(expected, canAccess);
    }
}
