param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [string]$PreviousPackageDirectory
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'StandaloneRelease.psm1') -Force
$packagePath = (Resolve-Path -LiteralPath $PackageDirectory).Path
$null = Get-IisidsdStandalonePayload -Path $packagePath -IncludeSettings -RequireReleaseDefaults
$previousPath = if ([string]::IsNullOrWhiteSpace($PreviousPackageDirectory)) {
    $packagePath
}
else {
    (Resolve-Path -LiteralPath $PreviousPackageDirectory).Path
}
$testRoot = Join-Path $env:TEMP "iisidsd-upgrade-test-$([Guid]::NewGuid().ToString('N'))"
$installPath = Join-Path $testRoot 'install'
$rollbackPath = Join-Path $testRoot 'rollback'

try {
    New-Item -ItemType Directory -Path $installPath, $rollbackPath -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $previousPath 'iisidsd.exe') -Destination $installPath
    Copy-Item -LiteralPath (Join-Path $previousPath 'appsettings.json') -Destination $installPath
    Copy-Item -LiteralPath (Join-Path $previousPath 'wwwroot') -Destination $installPath -Recurse

    $settingsPath = Join-Path $installPath 'appsettings.json'
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    $settings.Logging.LogLevel.Default = 'Warning'
    $settings | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $settingsPath -Encoding utf8
    $dataPath = Join-Path $installPath 'data'
    New-Item -ItemType Directory -Path $dataPath -Force | Out-Null
    $databasePath = Join-Path $dataPath 'iisidsd.sqlite3'
    $auditPath = Join-Path $dataPath 'iisidsd.sqlite3.etw-diagnostics.json'
    [IO.File]::WriteAllText($databasePath, 'upgrade-test-database-state')
    [IO.File]::WriteAllText($auditPath, 'upgrade-test-audit-state')
    $settingsBeforeUpgrade = (Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash
    $databaseBeforeUpgrade = (Get-FileHash -LiteralPath $databasePath -Algorithm SHA256).Hash
    $auditBeforeUpgrade = (Get-FileHash -LiteralPath $auditPath -Algorithm SHA256).Hash

    $installedExecutable = Join-Path $installPath 'iisidsd.exe'
    $oldWebRoot = Join-Path $installPath 'wwwroot'
    Copy-Item -LiteralPath $installedExecutable -Destination (Join-Path $rollbackPath 'iisidsd.exe')
    Copy-Item -LiteralPath $oldWebRoot -Destination $rollbackPath -Recurse

    Copy-Item -LiteralPath (Join-Path $packagePath 'iisidsd.exe') -Destination $installedExecutable -Force
    Remove-Item -LiteralPath $oldWebRoot -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $packagePath 'wwwroot') -Destination $installPath -Recurse

    if ((Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath (Join-Path $packagePath 'iisidsd.exe') -Algorithm SHA256).Hash) {
        throw 'Upgrade did not install the release executable.'
    }
    if ((Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash -ne $settingsBeforeUpgrade -or
        (Get-FileHash -LiteralPath $databasePath -Algorithm SHA256).Hash -ne $databaseBeforeUpgrade -or
        (Get-FileHash -LiteralPath $auditPath -Algorithm SHA256).Hash -ne $auditBeforeUpgrade) {
        throw 'Upgrade modified operator configuration, SQLite data, or the diagnostics sidecar.'
    }

    Copy-Item -LiteralPath (Join-Path $rollbackPath 'iisidsd.exe') -Destination $installedExecutable -Force
    Remove-Item -LiteralPath $oldWebRoot -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $rollbackPath 'wwwroot') -Destination $installPath -Recurse -Force
    if ((Get-FileHash -LiteralPath (Join-Path $rollbackPath 'iisidsd.exe') -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash -or
        (Get-FileHash -LiteralPath (Join-Path $rollbackPath 'wwwroot/index.html') -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath (Join-Path $oldWebRoot 'index.html') -Algorithm SHA256).Hash) {
        throw 'Rollback did not restore the previous dashboard assets.'
    }
    if ((Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash -ne $settingsBeforeUpgrade -or
        (Get-FileHash -LiteralPath $databasePath -Algorithm SHA256).Hash -ne $databaseBeforeUpgrade -or
        (Get-FileHash -LiteralPath $auditPath -Algorithm SHA256).Hash -ne $auditBeforeUpgrade) {
        throw 'Rollback modified operator configuration, SQLite data, or the diagnostics sidecar.'
    }

    "Standalone upgrade from '$([IO.Path]::GetFileName($previousPath))', state preservation, and rollback staging checks passed."
}
finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}