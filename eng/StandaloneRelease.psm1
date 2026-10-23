Set-StrictMode -Version Latest

$script:StandaloneAssets = @(
    'iisidsd.exe',
    'wwwroot/app.js',
    'wwwroot/dashboard-model.js',
    'wwwroot/favicon.ico',
    'wwwroot/index.html',
    'wwwroot/site.css'
)

function Get-IisidsdStandalonePayload {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$IncludeSettings,
        [switch]$RequireSafeDefaults,
        [switch]$AllowBuildOutputExtras
    )

    $root = (Resolve-Path -LiteralPath $Path).Path
    $expected = @($script:StandaloneAssets)
    if ($IncludeSettings) { $expected += 'appsettings.json' }
    $expected = @($expected | Sort-Object)

    $items = @(Get-ChildItem -LiteralPath $root -Force -Recurse)
    if (@($items | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -gt 0) {
        throw 'Standalone payload must not contain symbolic links or reparse points.'
    }

    $files = @($items | Where-Object { -not $_.PSIsContainer })
    $actual = @($files | ForEach-Object {
        [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
    } | Sort-Object)
    $assetMismatch = if ($AllowBuildOutputExtras) {
        @($expected | Where-Object { $_ -cnotin $actual }).Count -gt 0
    }
    else {
        ($actual -join "`n") -cne ($expected -join "`n")
    }
    if ($assetMismatch) {
        throw "Standalone payload file allowlist mismatch. Expected: $($expected -join ', '). Actual: $($actual -join ', ')."
    }

    $directories = @($items | Where-Object { $_.PSIsContainer } | ForEach-Object {
        [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
    } | Sort-Object)
    if (-not $AllowBuildOutputExtras -and ($directories -join "`n") -cne 'wwwroot') {
        throw "Standalone payload directory allowlist mismatch. Actual: $($directories -join ', ')."
    }

    if ($RequireSafeDefaults) {
        if (-not $IncludeSettings) { throw 'Safe-default validation requires appsettings.json.' }
        $settings = Get-Content -LiteralPath (Join-Path $root 'appsettings.json') -Raw | ConvertFrom-Json
        $allowedLoopbackUrls = @('http://127.0.0.1:5080', 'http://localhost:5080')
        if ($settings.Urls -cnotin $allowedLoopbackUrls -or
            $settings.Dashboard.RemoteAccessEnabled -ne $false -or
            $settings.IisAdmin.EnableDenyListChanges -ne $false -or
            $settings.IisAdmin.DryRun -ne $true) {
            throw 'Release settings must retain loopback-only access, disabled IIS writes, and dry-run defaults.'
        }

        Assert-NoStandaloneSecrets -Value $settings
    }

    return @($files | Where-Object {
        [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/') -cin $expected
    } | Sort-Object FullName)
}

function Assert-NoStandaloneSecrets {
    param([Parameter(Mandatory)][object]$Value)

    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        foreach ($property in $Value.PSObject.Properties) {
            if ($property.Name -match '(?i)(password|secret|api[-_]?key|access[-_]?token|private[-_]?key)' -and
                -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                throw "Release settings contain a non-empty secret-like value at '$($property.Name)'."
            }
            if ($null -ne $property.Value) { Assert-NoStandaloneSecrets -Value $property.Value }
        }
    }
    elseif ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        foreach ($item in $Value) {
            if ($null -ne $item) { Assert-NoStandaloneSecrets -Value $item }
        }
    }
}

Export-ModuleMember -Function Get-IisidsdStandalonePayload