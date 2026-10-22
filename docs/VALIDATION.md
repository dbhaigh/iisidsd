# Local validation

Run these commands from the repository root in PowerShell on Windows. The build requires the .NET 10 SDK and `Microsoft.Web.Administration.dll` from IIS under `%WINDIR%\System32\inetsrv`.

```powershell
dotnet restore iisidsd.slnx -p:NuGetAuditLevel=low -warnaserror
dotnet build iisidsd.slnx --no-restore --configuration Release -warnaserror
dotnet test Tests/iisidsd.Tests/iisidsd.Tests.csproj --no-build --no-restore --configuration Release --logger "trx;LogFileName=tests.trx" --results-directory "$env:TEMP\iisidsd-test-results"
dotnet list iisidsd.slnx package --vulnerable --include-transitive

$publishDir = Join-Path $env:TEMP 'iisidsd-publish'
dotnet restore iisidsd.csproj -p:RuntimeIdentifier=win-x64 -p:NuGetAuditLevel=low -warnaserror
dotnet publish iisidsd.csproj --no-restore --configuration Release -p:PublishProfile=StandaloneWinX64 "-p:PublishDir=$publishDir\" -warnaserror
```

Restore treats NuGet audit findings at low severity or higher as errors. The package-list command provides a readable direct and transitive vulnerability report. The RID-specific restore prepares the standalone publish target. The publish command overrides the profile output path to avoid overwriting checked-in or locally retained release artifacts.

The CI workflow also scans full Git history with Gitleaks 8.30.1. To run that gate locally, install the same Gitleaks version and run:

```powershell
gitleaks git --redact .
```