[CmdletBinding()]
param(
    [string]$Root
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = $PSScriptRoot }
$resolvedRoot = (Resolve-Path -LiteralPath $Root).Path
function Get-PortableRelativePath {
    param([string]$BasePath, [string]$FullPath)
    $baseUri = [Uri]($BasePath.TrimEnd('\') + '\')
    $fileUri = [Uri]$FullPath
    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($fileUri).ToString())
}
$manifestPath = Join-Path $resolvedRoot 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    Write-Output '{"result":"FAIL","reason":"manifest.json missing"}'
    exit 1
}

$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$receiptPath = [IO.Path]::GetFullPath((Join-Path $resolvedRoot '..\..\..\receipts\toolchains.json'))
$manifestAnchor = 'UNAVAILABLE_OUTSIDE_PROJECT'
$manifestAnchorMatch = $true
if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
    $receipts = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    $receipt = @($receipts.tools | Where-Object { $_.tool -eq 'NSIS' }) | Select-Object -First 1
    if ($null -eq $receipt -or [string]::IsNullOrWhiteSpace([string]$receipt.manifest_sha256)) {
        $manifestAnchor = 'MISSING_IN_TOOLCHAIN_RECEIPT'
        $manifestAnchorMatch = $false
    } else {
        $manifestAnchor = 'TOOLS_RECEIPT_SHA256'
        $manifestAnchorMatch = $manifestHash -eq ([string]$receipt.manifest_sha256).ToLowerInvariant()
    }
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$expected = @{}
foreach ($entry in $manifest.files) {
    $relative = ([string]$entry.path).Replace('\', '/')
    if (-not $relative -or $relative -eq 'manifest.json' -or $expected.ContainsKey($relative)) {
        Write-Output '{"result":"FAIL","reason":"invalid or duplicate manifest path"}'
        exit 1
    }
    $expected[$relative] = $entry
}

$actual = @{}
foreach ($file in Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse) {
    $relative = Get-PortableRelativePath -BasePath $resolvedRoot -FullPath $file.FullName
    $actual[$relative] = $file
}

$missing = @($expected.Keys | Where-Object { -not $actual.ContainsKey($_) } | Sort-Object)
$extra = @($actual.Keys | Where-Object { $_ -ne 'manifest.json' -and -not $expected.ContainsKey($_) } | Sort-Object)
$changed = @()
foreach ($relative in ($expected.Keys | Sort-Object)) {
    if (-not $actual.ContainsKey($relative)) { continue }
    $file = $actual[$relative]
    $entry = $expected[$relative]
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne ([string]$entry.sha256).ToLowerInvariant() -or [int64]$file.Length -ne [int64]$entry.size) {
        $changed += [pscustomobject]@{
            path = $relative
            expected_sha256 = $entry.sha256
            actual_sha256 = $hash
            expected_size = $entry.size
            actual_size = $file.Length
        }
    }
}

$mandatory = @(
    'Bin/makensis.exe',
    'Bin/zlib1.dll',
    'Stubs/lzma-x86-unicode',
    'Stubs/zlib-x86-unicode',
    'Plugins/x86-unicode/nsDialogs.dll',
    'Plugins/x86-unicode/System.dll',
    'COPYING',
    'BUILD_PROVENANCE.json'
)
$mandatoryMissing = @($mandatory | Where-Object { -not $actual.ContainsKey($_) } | Sort-Object)
$pass = $manifestAnchorMatch -and $missing.Count -eq 0 -and $extra.Count -eq 0 -and $changed.Count -eq 0 -and $mandatoryMissing.Count -eq 0
$result = [ordered]@{
    schema_version = '1.0'
    tool = 'NSIS'
    version = '3.12'
    root = $resolvedRoot
    policy = 'CLOSED_SET_NO_AUTO_REPAIR'
    manifest_sha256 = $manifestHash
    manifest_anchor = $manifestAnchor
    manifest_anchor_match = $manifestAnchorMatch
    expected_files_excluding_manifest = $expected.Count
    actual_files_including_manifest = $actual.Count
    missing = $missing
    extra = $extra
    changed = $changed
    mandatory_missing = $mandatoryMissing
    result = if ($pass) { 'PASS' } else { 'FAIL' }
}
$result | ConvertTo-Json -Depth 6
if (-not $pass) { exit 1 }
