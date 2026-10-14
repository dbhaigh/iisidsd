using iisidsd.Models;

namespace iisidsd.Storage;

public interface IDenyListStore
{
    long BeginAudit(DenyListAuditRecord record);
    void CompleteAudit(long auditId, string outcome);
    void SetAuditExpiry(long auditId, DateTimeOffset? expiresAt);
    IReadOnlyList<DenyListAuditRecord> GetRecentAudit(int limit);
    DenyListAuditRecord? GetLastAutoDeny();
    DateTimeOffset? GetExpiry(string siteName, string clientIp);
    void SetExpiry(string siteName, string clientIp, DateTimeOffset expiresAt);
    void RemoveExpiry(string siteName, string clientIp);
    IReadOnlyList<TemporaryDenyListEntry> GetExpired(
        DateTimeOffset now,
        int limit,
        TemporaryDenyListEntry? after = null);
}
