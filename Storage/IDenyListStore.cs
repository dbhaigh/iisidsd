using iisidsd.Models;

namespace iisidsd.Storage;

public interface IDenyListStore
{
    IDisposable AcquireMutationLock();
    long BeginAudit(DenyListAuditRecord record);
    long RecordAudit(DenyListAuditRecord record);
    void CompleteAudit(long auditId, string outcome);
    void SetAuditExpiry(long auditId, DateTimeOffset? expiresAt);
    IReadOnlyList<DenyListAuditRecord> GetRecentAudit(int limit);
    DenyListAuditRecord? GetLastAutoDeny();
    DateTimeOffset? GetExpiry(string siteName, string clientIp);
    void SetExpiry(string siteName, string clientIp, DateTimeOffset expiresAt);
    void RemoveExpiry(string siteName, string clientIp);
    ManagedDenyListEntry? GetManagedDeny(string siteName, string clientIp);
    IReadOnlyList<ManagedDenyListEntry> GetPendingManagedDenies(int limit);
    bool TryPrepareManagedDeny(ManagedDenyListEntry entry);
    bool CompleteManagedDeny(string siteName, string clientIp, DateTimeOffset? expiresAt, long auditId);
    bool TryTransitionManagedDeny(
        string siteName,
        string clientIp,
        string expectedState,
        long expectedAuditId,
        string state,
        long auditId);
    bool TryRemoveManagedDeny(string siteName, string clientIp, string expectedState, long expectedAuditId);
    IReadOnlyList<TemporaryDenyListEntry> GetExpired(
        DateTimeOffset now,
        int limit,
        TemporaryDenyListEntry? after = null);
}
