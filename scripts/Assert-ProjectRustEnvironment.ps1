param(
    [string]$WorkingDirectory = (Get-Location).Path,
    [AllowEmptyString()]
    [string]$CandidateRustupHome = $env:RUSTUP_HOME,
    [AllowEmptyString()]
    [string]$CandidateCargoHome = $env:CARGO_HOME
)

$ErrorActionPreference = 'Stop'
$GuardProjectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\', '/')
$GuardWorkingDirectory = [IO.Path]::GetFullPath($WorkingDirectory).TrimEnd('\', '/')
$GuardProjectPrefix = $GuardProjectRoot + [IO.Path]::DirectorySeparatorChar
$GuardInsideRepository =
    $GuardWorkingDirectory.Equals($GuardProjectRoot, [StringComparison]::OrdinalIgnoreCase) -or
    $GuardWorkingDirectory.StartsWith($GuardProjectPrefix, [StringComparison]::OrdinalIgnoreCase)

if (-not $GuardInsideRepository) {
    Write-Output 'PROJECT_RUST_ENVIRONMENT_GATE=NOT_APPLICABLE_NEUTRAL_DIRECTORY'
    return
}

if ([string]::IsNullOrWhiteSpace($CandidateRustupHome) -or
    [string]::IsNullOrWhiteSpace($CandidateCargoHome)) {
    throw 'PROJECT_RUST_ENVIRONMENT_DENIED: repository Rust commands require explicit project-local RUSTUP_HOME and CARGO_HOME'
}

$GuardExpectedRustup = [IO.Path]::GetFullPath((Join-Path $GuardProjectRoot '.local\rustup')).TrimEnd('\', '/')
$GuardExpectedCargo = [IO.Path]::GetFullPath((Join-Path $GuardProjectRoot '.local\cargo')).TrimEnd('\', '/')
$GuardActualRustup = [IO.Path]::GetFullPath($CandidateRustupHome).TrimEnd('\', '/')
$GuardActualCargo = [IO.Path]::GetFullPath($CandidateCargoHome).TrimEnd('\', '/')

if (-not $GuardActualRustup.Equals($GuardExpectedRustup, [StringComparison]::OrdinalIgnoreCase) -or
    -not $GuardActualCargo.Equals($GuardExpectedCargo, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'PROJECT_RUST_ENVIRONMENT_DENIED: global or foreign Rustup/Cargo context detected inside repository'
}

Write-Output 'PROJECT_RUST_ENVIRONMENT_GATE=PASS_PROJECT_LOCAL'
