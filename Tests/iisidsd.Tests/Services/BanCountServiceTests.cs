using iisidsd.Configuration;
using iisidsd.Services;
using iisidsd.Storage;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace iisidsd.Tests.Services;

public sealed class BanCountServiceTests
{
    [Fact]
    public async Task IncrementBanCounts_TracksCountsPerDomainAndAggregatesByIp()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), $"iisidsd-ban-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(rootPath);

        try
        {
            var storageOptions = Options.Create(new StorageOptions { DatabasePath = "data/test.sqlite3" });
            var environment = new TestHostEnvironment(rootPath);
            var initializer = new EventDbInitializer(storageOptions, environment, NullLogger<EventDbInitializer>.Instance);
            await initializer.StartAsync(CancellationToken.None);

            var service = new BanCountService(storageOptions, environment);
            service.IncrementBanCounts("198.51.100.24", ["alpha.test", "beta.test", "alpha.test"]);

            Assert.Equal(2, service.GetBanCount("198.51.100.24").BanCount);
            Assert.Equal(1, service.GetBanCount("198.51.100.24", "alpha.test").BanCount);
            Assert.Equal(1, service.GetBanCount("198.51.100.24", "beta.test").BanCount);
        }
        finally
        {
            try
            {
                Directory.Delete(rootPath, recursive: true);
            }
            catch
            {
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
