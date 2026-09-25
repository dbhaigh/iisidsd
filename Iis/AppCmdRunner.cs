using System.Diagnostics;
using System.Text;

namespace iisidsd.Iis;

internal sealed class AppCmdRunner(ILogger logger)
{
    private readonly string _appCmdPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "inetsrv", "appcmd.exe");
    private readonly ILogger _logger = logger;

    public bool IsAvailable() => File.Exists(_appCmdPath);

    public (bool Success, string Output, string Error) Run(params string[] arguments)
    {
        if (!IsAvailable())
        {
            return (false, string.Empty, $"appcmd.exe was not found at '{_appCmdPath}'.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = _appCmdPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            return (false, string.Empty, "Failed to start appcmd.exe.");
        }

        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            _logger.LogWarning("appcmd exited with code {ExitCode}. Args: {Args}. Error: {Error}", process.ExitCode, string.Join(' ', arguments), error);
            return (false, output, error);
        }

        return (true, output, error);
    }
}
