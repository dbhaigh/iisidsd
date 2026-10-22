using iisidsd.Models;

namespace iisidsd.Storage;

public interface IAnalystIncidentStore
{
    IReadOnlyList<AnalystIncidentRecord> List(int limit = 500);
    AnalystIncidentRecord? Get(string clientIp);
    AnalystIncidentRecord Save(string clientIp, string status, string note, string updatedBy);
}