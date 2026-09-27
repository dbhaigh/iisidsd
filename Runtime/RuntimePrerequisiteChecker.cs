using System.Diagnostics;
using System.Runtime.Versioning;
using System.Windows.Forms;

namespace iisidsd.Runtime;

[SupportedOSPlatform("windows")]
internal static class RuntimePrerequisiteChecker
{
    private const int RequiredMajorVersion = 10;
    private const string RuntimeDownloadUrl = "https://dotnet.microsoft.com/download/dotnet/10.0";

    public static bool EnsureRuntimeAvailable()
    {
        var markerPath = GetMarkerPath();
        if (File.Exists(markerPath))
        {
            return true;
        }

        var runtimeVersion = Environment.Version;
        if (runtimeVersion.Major < RequiredMajorVersion)
        {
            if (Environment.UserInteractive)
            {
                var result = MessageBox.Show(
                    $"iisidsd requires .NET {RequiredMajorVersion} runtime or later.\n\nDetected: {runtimeVersion}\n\nOpen the download page now?",
                    "Missing .NET Runtime",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);

                if (result == DialogResult.Yes)
                {
                    OpenRuntimeDownloadPage();
                }
            }

            return false;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(markerPath)!);
        File.WriteAllText(markerPath, runtimeVersion.ToString());
        return true;
    }

    private static string GetMarkerPath()
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "iisidsd");
        return Path.Combine(root, "runtime-check.ok");
    }

    private static void OpenRuntimeDownloadPage()
    {
        var processStartInfo = new ProcessStartInfo
        {
            FileName = RuntimeDownloadUrl,
            UseShellExecute = true
        };

        Process.Start(processStartInfo);
    }
}
