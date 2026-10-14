namespace iisidsd.Iis;

public interface IIpAllowList
{
    bool Contains(string? clientIp);
}
