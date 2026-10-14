namespace iisidsd.Iis;

public interface IIisDenyListWriter
{
    IisDenyListWriteResult EnsureDenied(string siteName, string clientIp, Action prepareNewEntry);
}

public enum IisDenyListWriteStatus
{
    Added,
    AlreadyDenied,
    ExistingAllowRule,
    Failed
}

public sealed record IisDenyListWriteResult(IisDenyListWriteStatus Status, Exception? Exception = null);
