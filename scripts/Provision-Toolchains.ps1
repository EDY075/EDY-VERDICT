param(
    [switch]$ExplicitProjectLocalProvisioning
)

# Explicitly authorized project-local Level -1C provisioning. No engines/installers.
$ErrorActionPreference = 'Stop'
if (-not $ExplicitProjectLocalProvisioning) {
    throw 'PROJECT_LOCAL_PROVISIONING_DENIED: explicit provisioning authorization is required'
}
$ProjectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Enter-Project.ps1')
& (Join-Path $PSScriptRoot 'Assert-ProjectRustEnvironment.ps1') `
    -WorkingDirectory $ProjectRoot `
    -CandidateRustupHome $env:RUSTUP_HOME `
    -CandidateCargoHome $env:CARGO_HOME | Out-Null
$Toolchains = Join-Path $ProjectRoot '.local/toolchains'
$Downloads = Join-Path $ProjectRoot '.local/downloads'
New-Item -ItemType Directory -Path $Toolchains,$Downloads -Force | Out-Null
$NodeZip = Join-Path $Downloads 'node-v24.20.0-win-x64.zip'
$ExpectedNodeHash = '6cac9ffbca8f6a47091e4b5c772e0606049c3871cb67d900c0cedde630e545ba'
if (!(Test-Path -LiteralPath $NodeZip)) {
    Invoke-WebRequest 'https://nodejs.org/dist/v24.20.0/node-v24.20.0-win-x64.zip' -OutFile $NodeZip
}
if ((Get-FileHash -LiteralPath $NodeZip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedNodeHash) { throw 'Node checksum mismatch' }
$NodeExe = Join-Path $Toolchains 'node-v24.20.0-win-x64/node.exe'
if (!(Test-Path -LiteralPath $NodeExe)) { Expand-Archive -LiteralPath $NodeZip -DestinationPath $Toolchains }
$NodeSignature = Get-AuthenticodeSignature -LiteralPath $NodeExe
if ($NodeSignature.Status -ne 'Valid') { throw 'Node Authenticode validation failed' }
$PnpmTar = Join-Path $Downloads 'pnpm-11.25.0.tgz'
if (!(Test-Path -LiteralPath $PnpmTar)) { Invoke-WebRequest 'https://registry.npmjs.org/pnpm/-/pnpm-11.25.0.tgz' -OutFile $PnpmTar }
$ActualPnpmIntegrity = 'sha512-' + [Convert]::ToBase64String([Security.Cryptography.SHA512]::HashData([IO.File]::ReadAllBytes($PnpmTar)))
$ExpectedPnpmIntegrity = 'sha512-XN6SW08HX3Jetx+64YpC/+eEUkeJ8ZthxzHLhyHsKKruFg4BqNWvT+2ypCzb8wDv4j2zVrDUoXtNY+EfirfJVg=='
if ($ActualPnpmIntegrity -ne $ExpectedPnpmIntegrity) { throw 'pnpm integrity mismatch' }
$PnpmDir = Join-Path $Toolchains 'pnpm-11.25.0'
if (!(Test-Path -LiteralPath (Join-Path $PnpmDir 'package/bin/pnpm.cjs'))) {
    New-Item -ItemType Directory -Path $PnpmDir -Force | Out-Null
    $Entries = & tar -tzf $PnpmTar
    if ($LASTEXITCODE -ne 0 -or ($Entries | Where-Object { $_ -notmatch '^package/' -or $_ -match '(^|/)\.\.(/|$)|:|\\' })) { throw 'Unsafe pnpm archive path' }
    & tar -xzf $PnpmTar -C $PnpmDir
    if ($LASTEXITCODE -ne 0) { throw 'pnpm extraction failed' }
}
& $NodeExe --version
pnpm --version
& (Join-Path $PSScriptRoot 'Invoke-ProjectRust.ps1') -Action ProvisionPinnedToolchain -ExplicitProjectLocalProvisioning
if ($LASTEXITCODE -ne 0) { throw 'Rust provisioning failed' }
& (Join-Path $PSScriptRoot 'Invoke-ProjectRust.ps1') -Action RustcVersion
& (Join-Path $PSScriptRoot 'Invoke-ProjectRust.ps1') -Action CargoVersion
Write-Output ('Node SHA256 verified; Authenticode: '+$NodeSignature.Status+'; signer: '+$NodeSignature.SignerCertificate.Subject)
Write-Output 'pnpm registry SHA512 verified. No lifecycle script executed.'
