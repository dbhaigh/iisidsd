namespace iisidsd.Models;

public sealed record BanCountRecord(
    string ClientIp,
    int BanCount,
    DateTimeOffset LastUpdated);
