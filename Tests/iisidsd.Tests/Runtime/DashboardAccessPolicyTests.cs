using System.Security.Claims;
using System.Security.Principal;
using iisidsd.Runtime;

namespace iisidsd.Tests.Runtime;

public sealed class DashboardAccessPolicyTests
{
    [Theory]
    [InlineData(false, true, false, DashboardAccessDecision.Allowed)]
    [InlineData(false, false, false, DashboardAccessDecision.Forbidden)]
    [InlineData(true, false, false, DashboardAccessDecision.Forbidden)]
    [InlineData(true, false, true, DashboardAccessDecision.AuthenticationRequired)]
    [InlineData(true, true, false, DashboardAccessDecision.Forbidden)]
    [InlineData(true, true, true, DashboardAccessDecision.AuthenticationRequired)]
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

    [Fact]
    public void CanAccessAdministratorFeatures_DoesNotInferCallerTrustFromAnAdministratorRoleClaim()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimsIdentity.DefaultRoleClaimType, "Administrators")],
            authenticationType: "test"));

        Assert.False(DashboardAccessPolicy.CanAccessAdministratorFeatures(principal));
    }

    [Fact]
    public void CanAccessAdministratorFeatures_RejectsDenyOnlySidClaimsFromNonWindowsIdentities()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.DenyOnlySid, "S-1-5-32-544")],
            authenticationType: "test"));

        Assert.False(DashboardAccessPolicy.CanAccessAdministratorFeatures(principal, isLocalRequest: true));
    }

    [Fact]
    public void CanAccessAdministratorFeatures_RecognizesFilteredAdministratorMembershipOnlyForLocalRequests()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new ClaimsPrincipal(identity);
        var hasEnabledAdministratorRole = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        var hasFilteredAdministratorSid = identity.Claims.Any(claim =>
            claim.Type == ClaimTypes.DenyOnlySid && claim.Value == "S-1-5-32-544");

        Assert.Equal(
            hasEnabledAdministratorRole || hasFilteredAdministratorSid,
            DashboardAccessPolicy.CanAccessAdministratorFeatures(principal, isLocalRequest: true));
        Assert.Equal(
            hasEnabledAdministratorRole,
            DashboardAccessPolicy.CanAccessAdministratorFeatures(principal, isLocalRequest: false));
    }
}
