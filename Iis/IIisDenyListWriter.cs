namespace iisidsd.Iis;

public interface IIisDenyListWriter
{
    IisDenyListMutationResult EnsureDenied(string siteName, string clientIp, Action prepareNewEntry);
    IisDenyListMutationResult RemoveDenied(string siteName, string clientIp, bool deniedRulesOnly = false);
}

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
