namespace iisidsd.Iis;

public interface IIisDenyListWriter
{
    IisDenyListInspection Inspect(string siteName, string clientIp);
    IisDenyListMutationResult EnsureDenied(string siteName, string clientIp, Action prepareNewEntry);
    IisDenyListMutationResult RemoveDenied(string siteName, string clientIp);
}

public sealed record IisDenyListInspection(
    string SiteName,
    string ClientIp,
    string RuleState,
    IReadOnlyList<string> ApplicationPools,
    IReadOnlyList<string> OtherSitesSharingPools);

public enum IisDenyListMutationStatus
{
    Added,
    AlreadyDenied,
    ExistingAllowRule,
    Removed,
    NotFound,
    Failed
}

public sealed record IisDenyListMutationResult(IisDenyListMutationStatus Status, Exception? Exception = null);
