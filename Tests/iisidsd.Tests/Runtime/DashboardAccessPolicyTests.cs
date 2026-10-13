using System.Security.Claims;
using iisidsd.Runtime;

namespace iisidsd.Tests.Runtime;

public sealed class DashboardAccessPolicyTests
{
    [Theory]
    [InlineData(false, true, false, false, DashboardAccessDecision.Allowed)]
    [InlineData(false, false, false, false, DashboardAccessDecision.Forbidden)]
    [InlineData(true, false, false, false, DashboardAccessDecision.Forbidden)]
    [InlineData(true, false, true, false, DashboardAccessDecision.AuthenticationRequired)]
    [InlineData(true, true, false, false, DashboardAccessDecision.AuthenticationRequired)]
    [InlineData(true, true, false, true, DashboardAccessDecision.Allowed)]
    public void Evaluate_ReturnsExpectedAccessDecision(
        bool remoteAccessEnabled,
        bool isLocalRequest,
        bool isHttps,
        bool isLocalHealthCheck,
        DashboardAccessDecision expected)
    {
        var decision = DashboardAccessPolicy.Evaluate(remoteAccessEnabled, isLocalRequest, isHttps, isLocalHealthCheck);

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
}
