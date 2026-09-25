using iisidsd.Configuration;
using iisidsd.Models;
using iisidsd.Storage;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Storage;

public sealed class SqliteEventStoreTests : IDisposable
{
    private readonly string _rootPath = Path.Combine(Path.GetTempPath(), "iisidsd-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Publish_StoresAndPrunesEventsByRetentionLimit()
    {
        Directory.CreateDirectory(_rootPath);
        var environment = new TestHostEnvironment(_rootPath);
        var storageOptions = Options.Create(new StorageOptions
        {
            DatabasePath = "data/test.sqlite3",
            EventRetentionLimit = 1
        });
        var etwOptions = Options.Create(new IisEtwOptions
        {
            RetentionLimit = 10,
            SubscriptionBufferSize = 8
        });

        var initializer = new EventDbInitializer(storageOptions, environment, NullLogger<EventDbInitializer>.Instance);
        await initializer.StartAsync(CancellationToken.None);

        var store = new SqliteEventStore(etwOptions, storageOptions, environment);
        store.Publish(new SecurityEvent(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            "server01",
            "example.test",
            "GET",
            "/first",
            "203.0.113.10",
            200,
            "agent-a",
            new Dictionary<string, string>())
        {
            Id = "first"
        });
        store.Publish(new SecurityEvent(
            DateTimeOffset.UtcNow,
            "server01",
            "example.test",
            "GET",
            "/second",
            "203.0.113.10",
            200,
            "agent-a",
            new Dictionary<string, string>(),
            RiskScore: 10,
            RiskSeverity: "Low",
            RiskIndicators: ["test-indicator"])
        {
            Id = "second"
        });

        var events = store.GetRecent(10);
        var webEvent = Assert.Single(events);
        Assert.Equal("second", webEvent.Id);
        Assert.Equal("/second", webEvent.Path);
        Assert.Contains("test-indicator", webEvent.RiskIndicators ?? []);
    }

    public void Dispose()
    {
        if (!Directory.Exists(_rootPath))
        {
            return;
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();

        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Directory.Delete(_rootPath, recursive: true);
                return;
            }
            catch (IOException)
            {
                if (attempt == 4)
                {
                    return;
                }

                Thread.Sleep(100);
            }
            catch (UnauthorizedAccessException)
            {
                if (attempt == 4)
                {
                    return;
                }

                Thread.Sleep(100);
            }
        }
    }

    private sealed class TestHostEnvironment(string contentRootPath) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "iisidsd.Tests";
        public string ContentRootPath { get; set; } = contentRootPath;
        public IFileProvider ContentRootFileProvider { get; set; } = new PhysicalFileProvider(contentRootPath);
    }
}
