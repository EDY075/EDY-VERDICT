$ErrorActionPreference = 'Stop'
$TestProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$TestGuard = Join-Path $TestProjectRoot 'scripts\Assert-ProjectRustEnvironment.ps1'
$TestGlobalInventory = Join-Path $TestProjectRoot 'scripts\Invoke-GlobalRustInventory.ps1'
$TestProjectRustup = Join-Path $TestProjectRoot '.local\rustup'
$TestProjectCargo = Join-Path $TestProjectRoot '.local\cargo'
$TestDriveRoot = [IO.Path]::GetPathRoot($TestProjectRoot)
$TestGlobalRustup = Join-Path $TestDriveRoot 'foreign-global-rustup'
$TestGlobalCargo = Join-Path $TestDriveRoot 'foreign-global-cargo'
$TestPassed = 0

function Assert-GuardDenied {
    param(
        [string]$Case,
        [AllowEmptyString()][string]$RustupHome,
        [AllowEmptyString()][string]$CargoHome
    )
    try {
        & $TestGuard -WorkingDirectory $TestProjectRoot -CandidateRustupHome $RustupHome -CandidateCargoHome $CargoHome | Out-Null
    } catch {
        if ($_.Exception.Message -notlike 'PROJECT_RUST_ENVIRONMENT_DENIED:*') {
            throw "$Case returned an unexpected error: $($_.Exception.Message)"
        }
        $script:TestPassed++
        return
    }
    throw "$Case failed open"
}

Assert-GuardDenied -Case 'repo unset context' -RustupHome '' -CargoHome ''
Assert-GuardDenied -Case 'repo global context' -RustupHome (Join-Path $env:USERPROFILE '.rustup') -CargoHome (Join-Path $env:USERPROFILE '.cargo')
Assert-GuardDenied -Case 'repo foreign context' -RustupHome $TestGlobalRustup -CargoHome $TestGlobalCargo

$TestAllowed = & $TestGuard -WorkingDirectory $TestProjectRoot -CandidateRustupHome $TestProjectRustup -CandidateCargoHome $TestProjectCargo
if ($TestAllowed -ne 'PROJECT_RUST_ENVIRONMENT_GATE=PASS_PROJECT_LOCAL') {
    throw 'project-local context was not accepted'
}
$TestPassed++

$TestNested = Join-Path $TestProjectRoot 'crates\edy-core'
$NestedAllowed = & $TestGuard -WorkingDirectory $TestNested -CandidateRustupHome $TestProjectRustup -CandidateCargoHome $TestProjectCargo
if ($NestedAllowed -ne 'PROJECT_RUST_ENVIRONMENT_GATE=PASS_PROJECT_LOCAL') { throw 'nested project-local context was not accepted' }
$TestPassed++

$TestNeutralRoot = [IO.Path]::GetPathRoot($env:SystemRoot)
$OriginalRustup = $env:RUSTUP_HOME
$OriginalCargo = $env:CARGO_HOME
try {
    $env:RUSTUP_HOME = $TestProjectRustup
    $env:CARGO_HOME = $TestProjectCargo
    $Child = & pwsh -NoProfile -NonInteractive -Command '[Console]::Write($env:RUSTUP_HOME+"|"+$env:CARGO_HOME)'
    if ($Child -ne "$TestProjectRustup|$TestProjectCargo") { throw 'child process did not preserve local homes' }
    $TestPassed++
} finally {
    $env:RUSTUP_HOME = $OriginalRustup
    $env:CARGO_HOME = $OriginalCargo
}

$OriginalRustup = $env:RUSTUP_HOME
$OriginalCargo = $env:CARGO_HOME
try {
    Remove-Item Env:RUSTUP_HOME -ErrorAction SilentlyContinue
    Remove-Item Env:CARGO_HOME -ErrorAction SilentlyContinue
    $NeutralResult = & $TestGlobalInventory -ExplicitGlobalInventory -ValidateOnly -WorkingDirectory $TestNeutralRoot
    if ($NeutralResult -ne 'GLOBAL_RUST_INVENTORY_CONTEXT=PASS_NEUTRAL_EXPLICIT') { throw 'neutral explicit inventory context failed' }
    $TestPassed++
} finally {
    $env:RUSTUP_HOME = $OriginalRustup
    $env:CARGO_HOME = $OriginalCargo
}

Write-Output "PROJECT_RUST_ENVIRONMENT_TESTS=PASS ($TestPassed/7)"
