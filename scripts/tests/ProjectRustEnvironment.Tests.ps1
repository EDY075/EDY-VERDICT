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
        [string]$WorkingDirectory,
        [AllowEmptyString()][string]$RustupHome,
        [AllowEmptyString()][string]$CargoHome
    )
    try {
        & $TestGuard -WorkingDirectory $WorkingDirectory -CandidateRustupHome $RustupHome -CandidateCargoHome $CargoHome | Out-Null
    } catch {
        if ($_.Exception.Message -notlike 'PROJECT_RUST_ENVIRONMENT_DENIED:*') {
            throw "$Case returned an unexpected error: $($_.Exception.Message)"
        }
        $script:TestPassed++
        return
    }
    throw "$Case failed open"
}

$TestNested = Join-Path $TestProjectRoot 'crates\edy-core'
$TestGlobalUserRustup = Join-Path $env:USERPROFILE '.rustup'
$TestGlobalUserCargo = Join-Path $env:USERPROFILE '.cargo'

Assert-GuardDenied -Case 'repo root unset context' -WorkingDirectory $TestProjectRoot -RustupHome '' -CargoHome ''
Assert-GuardDenied -Case 'repo child unset context' -WorkingDirectory $TestNested -RustupHome '' -CargoHome ''
Assert-GuardDenied -Case 'repo root global context' -WorkingDirectory $TestProjectRoot -RustupHome $TestGlobalUserRustup -CargoHome $TestGlobalUserCargo
Assert-GuardDenied -Case 'repo child global context' -WorkingDirectory $TestNested -RustupHome $TestGlobalUserRustup -CargoHome $TestGlobalUserCargo
Assert-GuardDenied -Case 'repo root foreign context' -WorkingDirectory $TestProjectRoot -RustupHome $TestGlobalRustup -CargoHome $TestGlobalCargo
Assert-GuardDenied -Case 'repo child foreign context' -WorkingDirectory $TestNested -RustupHome $TestGlobalRustup -CargoHome $TestGlobalCargo

$TestAllowed = & $TestGuard -WorkingDirectory $TestProjectRoot -CandidateRustupHome $TestProjectRustup -CandidateCargoHome $TestProjectCargo
if ($TestAllowed -ne 'PROJECT_RUST_ENVIRONMENT_GATE=PASS_PROJECT_LOCAL') {
    throw 'project-local context was not accepted'
}
$TestPassed++

$NestedAllowed = & $TestGuard -WorkingDirectory $TestNested -CandidateRustupHome $TestProjectRustup -CandidateCargoHome $TestProjectCargo
if ($NestedAllowed -ne 'PROJECT_RUST_ENVIRONMENT_GATE=PASS_PROJECT_LOCAL') { throw 'nested project-local context was not accepted' }
$TestPassed++

function Assert-ChildInheritance {
    param([string]$Case)
    $OriginalRustup = $env:RUSTUP_HOME
    $OriginalCargo = $env:CARGO_HOME
    try {
        $env:RUSTUP_HOME = $TestProjectRustup
        $env:CARGO_HOME = $TestProjectCargo
        $Child = & pwsh -NoProfile -NonInteractive -File $TestGuard `
            -WorkingDirectory $TestNested `
            -CandidateRustupHome $env:RUSTUP_HOME `
            -CandidateCargoHome $env:CARGO_HOME
        if ($Child -ne 'PROJECT_RUST_ENVIRONMENT_GATE=PASS_PROJECT_LOCAL') {
            throw "$Case child process did not preserve approved homes"
        }
        $script:TestPassed++
    } finally {
        $env:RUSTUP_HOME = $OriginalRustup
        $env:CARGO_HOME = $OriginalCargo
    }
}

Assert-ChildInheritance -Case 'E2E'
Assert-ChildInheritance -Case 'QA'

$TestNeutralRoot = [IO.Path]::GetPathRoot($env:SystemRoot)
$OriginalRustup = $env:RUSTUP_HOME
$OriginalCargo = $env:CARGO_HOME
try {
    Remove-Item Env:RUSTUP_HOME -ErrorAction SilentlyContinue
    Remove-Item Env:CARGO_HOME -ErrorAction SilentlyContinue
    Push-Location -LiteralPath $TestNeutralRoot
    try {
        $NeutralResult = & $TestGlobalInventory -ExplicitGlobalInventory -ValidateOnly -WorkingDirectory $TestNeutralRoot
    } finally {
        Pop-Location
    }
    if ($NeutralResult -ne 'GLOBAL_RUST_INVENTORY_CONTEXT=PASS_NEUTRAL_EXPLICIT') {
        throw 'neutral explicit inventory context failed'
    }
    $TestPassed++
} finally {
    $env:RUSTUP_HOME = $OriginalRustup
    $env:CARGO_HOME = $OriginalCargo
}

try {
    & $TestGlobalInventory -ExplicitGlobalInventory -ValidateOnly -WorkingDirectory $TestProjectRoot | Out-Null
    throw 'repository global inventory test failed open'
} catch {
    if ($_.Exception.Message -notlike 'GLOBAL_RUST_INVENTORY_DENIED:*') { throw }
    $TestPassed++
}

# Dedicated regression: the historical incident supplied a neutral target while the
# shell itself remained in the repository. This must fail before rustup is resolved.
try {
    & $TestGlobalInventory -ExplicitGlobalInventory -ValidateOnly -WorkingDirectory $TestNeutralRoot | Out-Null
    throw 'historical repo-to-neutral bypass regression failed open'
} catch {
    if ($_.Exception.Message -notlike 'GLOBAL_RUST_INVENTORY_DENIED:*') { throw }
    $TestPassed++
}

$GlobalInventorySource = Get-Content -LiteralPath $TestGlobalInventory -Raw
if ($GlobalInventorySource -match '(?im)\btoolchain\s+(install|update|uninstall|remove)\b|\bdefault\b|\bself\s+update\b') {
    throw 'global inventory helper contains a mutating rustup operation'
}
if ($GlobalInventorySource -notmatch '(?im)&\s+\$Rustup\s+toolchain\s+list\b') {
    throw 'global inventory helper is not restricted to the approved inventory operation'
}
$ProvisionSource = Get-Content -LiteralPath (Join-Path $TestProjectRoot 'scripts\Provision-Toolchains.ps1') -Raw
if ($ProvisionSource -notmatch 'ExplicitProjectLocalProvisioning' -or
    $ProvisionSource.IndexOf('Enter-Project.ps1',[StringComparison]::Ordinal) -gt
    $ProvisionSource.IndexOf('Get-Command rustup.exe',[StringComparison]::Ordinal)) {
    throw 'project-local provisioning is not explicitly gated before rustup resolution'
}
$TestPassed++

Write-Output "PROJECT_RUST_ENVIRONMENT_TESTS=PASS ($TestPassed/14)"
Write-Output 'RUSTUP_PREVENTION_REGRESSION=PASS'
Write-Output 'GLOBAL_AUTO_PROVISION_PATHS_KNOWN=0'
