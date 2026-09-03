param(
    [Parameter(Mandatory)]
    [switch]$ExplicitGlobalInventory,
    [switch]$ValidateOnly,
    [string]$WorkingDirectory = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\','/')
$Candidate = [IO.Path]::GetFullPath($WorkingDirectory).TrimEnd('\','/')
$CurrentDirectory = [IO.Path]::GetFullPath((Get-Location).Path).TrimEnd('\','/')
$Prefix = $ProjectRoot + [IO.Path]::DirectorySeparatorChar
function Test-InProjectTree([string]$Path) {
    return $Path.Equals($ProjectRoot,[StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Prefix,[StringComparison]::OrdinalIgnoreCase)
}
if ((Test-InProjectTree $CurrentDirectory) -or (Test-InProjectTree $Candidate)) {
    throw 'GLOBAL_RUST_INVENTORY_DENIED: working directory must be neutral'
}
if (-not $CurrentDirectory.Equals($Candidate,[StringComparison]::OrdinalIgnoreCase)) {
    throw 'GLOBAL_RUST_INVENTORY_DENIED: requested working directory must equal the current neutral directory'
}
if (-not (Test-Path -LiteralPath $Candidate -PathType Container)) {
    throw 'GLOBAL_RUST_INVENTORY_DENIED: neutral working directory does not exist'
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
