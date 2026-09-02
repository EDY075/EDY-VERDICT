$ErrorActionPreference = 'Stop'
$TestProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$TestGuard = Join-Path $TestProjectRoot 'scripts\Assert-ProjectRustEnvironment.ps1'
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

Assert-GuardDenied -Case 'unset context' -RustupHome '' -CargoHome ''
Assert-GuardDenied -Case 'global context' -RustupHome $TestGlobalRustup -CargoHome $TestGlobalCargo

$TestAllowed = & $TestGuard -WorkingDirectory $TestProjectRoot -CandidateRustupHome $TestProjectRustup -CandidateCargoHome $TestProjectCargo
if ($TestAllowed -ne 'PROJECT_RUST_ENVIRONMENT_GATE=PASS_PROJECT_LOCAL') {
    throw 'project-local context was not accepted'
}
$TestPassed++

$TestNeutralRoot = [IO.Path]::GetPathRoot($env:SystemRoot)
$TestNeutral = & $TestGuard -WorkingDirectory $TestNeutralRoot -CandidateRustupHome '' -CandidateCargoHome ''
if ($TestNeutral -ne 'PROJECT_RUST_ENVIRONMENT_GATE=NOT_APPLICABLE_NEUTRAL_DIRECTORY') {
    throw 'neutral global inventory context was not accepted'
}
$TestPassed++

Write-Output "PROJECT_RUST_ENVIRONMENT_TESTS=PASS ($TestPassed/4)"
