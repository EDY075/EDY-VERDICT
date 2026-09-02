param(
    [Parameter(Mandatory)]
    [switch]$ExplicitGlobalInventory,
    [switch]$ValidateOnly,
    [string]$WorkingDirectory = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\','/')
$Candidate = [IO.Path]::GetFullPath($WorkingDirectory).TrimEnd('\','/')
$Prefix = $ProjectRoot + [IO.Path]::DirectorySeparatorChar
if ($Candidate.Equals($ProjectRoot,[StringComparison]::OrdinalIgnoreCase) -or
    $Candidate.StartsWith($Prefix,[StringComparison]::OrdinalIgnoreCase)) {
    throw 'GLOBAL_RUST_INVENTORY_DENIED: working directory must be neutral'
}
if (-not $ExplicitGlobalInventory) { throw 'GLOBAL_RUST_INVENTORY_DENIED: explicit global context is required' }
if ($env:RUSTUP_HOME -or $env:CARGO_HOME) {
    throw 'GLOBAL_RUST_INVENTORY_DENIED: inherited Rust homes are forbidden'
}
Write-Output 'GLOBAL_RUST_INVENTORY_CONTEXT=PASS_NEUTRAL_EXPLICIT'
if ($ValidateOnly) { return }
$Rustup = (Get-Command rustup.exe -ErrorAction Stop).Source
Push-Location -LiteralPath $Candidate
try { & $Rustup toolchain list } finally { Pop-Location }
exit $LASTEXITCODE
