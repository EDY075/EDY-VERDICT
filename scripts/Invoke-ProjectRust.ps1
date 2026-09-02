param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'WorkspaceTest','WorkspaceClippy','FmtWrite','FmtCheck','CredentialFakeTest',
        'CargoAudit','CargoAuditJson','CargoDeny','CargoDenyJson',
        'RustcVersion','CargoVersion','RustfmtVersion','ClippyVersion',
        'CargoAuditVersion','CargoDenyVersion'
    )]
    [string]$Action
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
& (Join-Path $PSScriptRoot 'Assert-ProjectRustEnvironment.ps1') `
    -WorkingDirectory (Get-Location).Path `
    -CandidateRustupHome $env:RUSTUP_HOME `
    -CandidateCargoHome $env:CARGO_HOME | Out-Null

$ExpectedToolchain = Join-Path $ProjectRoot '.local\rustup\toolchains\1.98.0-x86_64-pc-windows-msvc\bin'
$Cargo = Join-Path $ExpectedToolchain 'cargo.exe'
$Rustc = Join-Path $ExpectedToolchain 'rustc.exe'
$Rustfmt = Join-Path $ExpectedToolchain 'rustfmt.exe'
$Audit = Join-Path $ProjectRoot '.local\audit-tools\bin\cargo-audit.exe'
$Deny = Join-Path $ProjectRoot '.local\audit-tools\bin\cargo-deny.exe'
foreach ($Executable in @($Cargo,$Rustc,$Rustfmt,$Audit,$Deny)) {
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        throw "PROJECT_RUST_EXECUTION_DENIED: approved executable is unavailable"
    }
}

$Executable = $null
$Arguments = @()
switch ($Action) {
    'WorkspaceTest' { $Executable=$Cargo; $Arguments=@('test','--workspace','--locked') }
    'WorkspaceClippy' { $Executable=$Cargo; $Arguments=@('clippy','--workspace','--all-targets','--locked','--','-D','warnings') }
    'FmtWrite' { $Executable=$Cargo; $Arguments=@('fmt','--all') }
    'FmtCheck' { $Executable=$Cargo; $Arguments=@('fmt','--all','--','--check') }
    'CredentialFakeTest' { $Executable=$Cargo; $Arguments=@('test','-p','edy-storage','--locked','secrets::tests','--','--ignored','--test-threads=1') }
    'CargoAudit' { $Executable=$Audit }
    'CargoAuditJson' { $Executable=$Audit; $Arguments=@('--json') }
    'CargoDeny' { $Executable=$Deny; $Arguments=@('check') }
    'CargoDenyJson' { $Executable=$Deny; $Arguments=@('--format','json','check') }
    'RustcVersion' { $Executable=$Rustc; $Arguments=@('--version') }
    'CargoVersion' { $Executable=$Cargo; $Arguments=@('--version') }
    'RustfmtVersion' { $Executable=$Rustfmt; $Arguments=@('--version') }
    'ClippyVersion' { $Executable=$Cargo; $Arguments=@('clippy','--version') }
    'CargoAuditVersion' { $Executable=$Audit; $Arguments=@('--version') }
    'CargoDenyVersion' { $Executable=$Deny; $Arguments=@('--version') }
    default { throw 'PROJECT_RUST_EXECUTION_DENIED: action is not allowlisted' }
}

& $Executable @Arguments
exit $LASTEXITCODE
