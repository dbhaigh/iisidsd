param(
    [Parameter(Mandatory)][string]$PublishDirectory,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$ProjectFile = (Join-Path $PSScriptRoot '..\iisidsd.csproj')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'StandaloneRelease.psm1') -Force

$publishPath = (Resolve-Path -LiteralPath $PublishDirectory).Path
$payload = @(Get-IisidsdStandalonePayload -Path $publishPath -IncludeSettings -RequireSafeDefaults -AllowBuildOutputExtras)
[xml]$project = Get-Content -LiteralPath $ProjectFile -Raw
$version = [string]($project.Project.PropertyGroup | Where-Object { $_.Version } | Select-Object -First 1 -ExpandProperty Version)
if ($version -notmatch '^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$') {
    throw "Invalid project release version '$version'."
}

$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
$bundleName = "iisidsd-$version-standalone-win-x64"
$bundlePath = Join-Path $outputPath $bundleName
$archivePath = Join-Path $outputPath "$bundleName.zip"
if ((Test-Path -LiteralPath $bundlePath) -or (Test-Path -LiteralPath $archivePath)) {
    throw "Release output already exists; use a fresh output directory: $outputPath"
}

New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $bundlePath 'wwwroot') -Force | Out-Null
foreach ($file in $payload) {
    $relativePath = [IO.Path]::GetRelativePath($publishPath, $file.FullName)
    $destination = Join-Path $bundlePath $relativePath
    $destinationDirectory = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $destinationDirectory)) {
        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    }
    Copy-Item -LiteralPath $file.FullName -Destination $destination
}

Add-Type -AssemblyName System.IO.Compression
$archiveStream = [IO.File]::Open($archivePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
$zip = [IO.Compression.ZipArchive]::new($archiveStream, [IO.Compression.ZipArchiveMode]::Create, $false)
try {
    foreach ($file in Get-ChildItem -LiteralPath $bundlePath -File -Recurse | Sort-Object FullName) {
        $relativePath = [IO.Path]::GetRelativePath($bundlePath, $file.FullName).Replace('\', '/')
        $entry = $zip.CreateEntry("$bundleName/$relativePath", [IO.Compression.CompressionLevel]::Optimal)
        $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
        $inputStream = [IO.File]::OpenRead($file.FullName)
        $entryStream = $entry.Open()
        try { $inputStream.CopyTo($entryStream) }
        finally {
            $entryStream.Dispose()
            $inputStream.Dispose()
        }
    }
}
finally {
    $zip.Dispose()
}

$hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash *$(Split-Path -Leaf $archivePath)" | Set-Content -LiteralPath "$archivePath.sha256" -Encoding ascii
[pscustomobject]@{
    Version = $version
    Package = $archivePath
    Sha256File = "$archivePath.sha256"
    Sha256 = $hash
    ExpandedDirectory = $bundlePath
}

$null = Get-IisidsdStandalonePayload -Path $bundlePath -IncludeSettings -RequireSafeDefaults

$zipCheck = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    $expectedEntries = @($payload | ForEach-Object {
        $relativePath = [IO.Path]::GetRelativePath($publishPath, $_.FullName).Replace('\', '/')
        "$bundleName/$relativePath"
    } | Sort-Object)
    $actualEntries = @($zipCheck.Entries | ForEach-Object { $_.FullName } | Sort-Object)
    if (($actualEntries -join "`n") -cne ($expectedEntries -join "`n")) {
        throw 'Release archive entries do not match the exact standalone payload allowlist.'
    }
}
finally {
    $zipCheck.Dispose()
}