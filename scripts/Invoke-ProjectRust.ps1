param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'WorkspaceTest','WorkspaceClippy','WorkspaceBuildRelease','GenerateLockOffline','FmtWrite','FmtCheck','CredentialFakeTest',
        'CargoAudit','CargoAuditJson','CargoDeny','CargoDenyJson','CargoDenyAdvisories','CargoDenyPolicy',
        'MetadataWorkspace','MetadataWindows','DesktopProductionTree','DesktopNativeBuild','DesktopNativeTest',
        'ProvisionPinnedToolchain','RemediationTest','RemediationForbiddenRelease','DesktopForbiddenRelease','RemediationProductionRegression',
        'RustcVersion','RustcSysroot','CargoVersion','RustfmtVersion','ClippyVersion',
        'CargoAuditVersion','CargoDenyVersion'
    )]
    [string]$Action,
    [switch]$ExplicitProjectLocalProvisioning
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$ExecutionDirectory = [IO.Path]::GetFullPath((Get-Location).Path).TrimEnd('\','/')
if (-not ($ExecutionDirectory.Equals($ProjectRoot,[StringComparison]::OrdinalIgnoreCase) -or
    $ExecutionDirectory.StartsWith($ProjectRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase))) {
    throw 'PROJECT_RUST_EXECUTION_DENIED: wrapper requires the project working tree'
}
& (Join-Path $PSScriptRoot 'Assert-ProjectRustEnvironment.ps1') `
    -WorkingDirectory (Get-Location).Path `
    -CandidateRustupHome $env:RUSTUP_HOME `
    -CandidateCargoHome $env:CARGO_HOME | Out-Null

$GateNode = Join-Path $ProjectRoot '.local\toolchains\node-v24.20.0-win-x64\node.exe'
& $GateNode (Join-Path $ProjectRoot 'scripts\direct-rust-gate.mjs') --quiet
if ($LASTEXITCODE -ne 0) { throw 'PROJECT_RUST_EXECUTION_DENIED: direct invocation regression gate failed' }

# Only this wrapper resolves Rust executables. Children never inherit global shims
# through RUSTC/RUSTDOC or PATH; these are process-local environment assignments.
if ($Action -eq 'ProvisionPinnedToolchain') {
    if (-not $ExplicitProjectLocalProvisioning) { throw 'PROJECT_LOCAL_PROVISIONING_DENIED: explicit authorization required' }
    $RustupExe = (Get-Command rustup.exe -ErrorAction Stop).Source
    & $RustupExe toolchain install 1.98.0 --profile minimal --component rustfmt --component clippy --target x86_64-pc-windows-msvc --no-self-update
    exit $LASTEXITCODE
}

$ExpectedToolchain = Join-Path $ProjectRoot '.local\rustup\toolchains\1.98.0-x86_64-pc-windows-msvc\bin'
$Cargo = Join-Path $ExpectedToolchain 'cargo.exe'
$Rustc = Join-Path $ExpectedToolchain 'rustc.exe'
$Rustfmt = Join-Path $ExpectedToolchain 'rustfmt.exe'
$env:RUSTC = $Rustc
$env:RUSTDOC = Join-Path $ExpectedToolchain 'rustdoc.exe'
$env:PATH = "$ExpectedToolchain;$env:PATH"
$env:CARGO_TARGET_DIR = Join-Path $ProjectRoot 'target'
$env:TEMP = Join-Path $ProjectRoot '.local\tmp'
$env:TMP = $env:TEMP
$env:RUSTUP_AUTO_INSTALL = '0'
$env:RUSTUP_TOOLCHAIN = '1.98.0-x86_64-pc-windows-msvc'
$Audit = Join-Path $ProjectRoot '.local\audit-tools\bin\cargo-audit.exe'
$Deny = Join-Path $ProjectRoot '.local\audit-tools\bin\cargo-deny.exe'
foreach ($Executable in @($Cargo,$Rustc,$Rustfmt,$Audit,$Deny)) {
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        throw "PROJECT_RUST_EXECUTION_DENIED: approved executable is unavailable"
    }
    if ((Get-Item -LiteralPath $Executable).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'PROJECT_RUST_EXECUTION_DENIED: executable is a reparse point'
    }
}

$Executable = $null
$Arguments = @()
switch ($Action) {
    'WorkspaceTest' { $Executable=$Cargo; $Arguments=@('test','--workspace','--locked') }
    'WorkspaceClippy' { $Executable=$Cargo; $Arguments=@('clippy','--workspace','--all-targets','--locked','--','-D','warnings') }
    'WorkspaceBuildRelease' { $Executable=$Cargo; $Arguments=@('build','--workspace','--release','--locked') }
    'GenerateLockOffline' { $Executable=$Cargo; $Arguments=@('generate-lockfile','--offline') }
    'FmtWrite' { $Executable=$Cargo; $Arguments=@('fmt','--all') }
    'FmtCheck' { $Executable=$Cargo; $Arguments=@('fmt','--all','--','--check') }
    'CredentialFakeTest' { $Executable=$Cargo; $Arguments=@('test','-p','edy-storage','--locked','secrets::tests','--','--ignored','--test-threads=1') }
    'CargoAudit' { $Executable=$Audit; $Arguments=@('audit') }
    'CargoAuditJson' { $Executable=$Audit; $Arguments=@('audit','--json') }
    'CargoDeny' { $Executable=$Deny; $Arguments=@('check') }
    'CargoDenyJson' { $Executable=$Deny; $Arguments=@('--format','json','check') }
    'CargoDenyAdvisories' { $Executable=$Deny; $Arguments=@('check','advisories') }
    'CargoDenyPolicy' { $Executable=$Deny; $Arguments=@('--log-level','error','check','licenses','sources','bans') }
    'MetadataWorkspace' { $Executable=$Cargo; $Arguments=@('metadata','--no-deps','--locked','--format-version','1') }
    'MetadataWindows' { $Executable=$Cargo; $Arguments=@('metadata','--locked','--format-version','1','--filter-platform','x86_64-pc-windows-msvc') }
    'DesktopProductionTree' { $Executable=$Cargo; $Arguments=@('tree','-p','edy-desktop','--locked','--edges','normal','--prefix','none') }
    'DesktopNativeBuild' { $Executable=$Cargo; $Arguments=@('build','-p','edy-desktop','--features','native-e2e','--locked') }
    'DesktopNativeTest' { $Executable=$Cargo; $Arguments=@('test','-p','edy-desktop','--features','native-e2e','--locked') }
    'RemediationTest' { $Executable=$Cargo; $Arguments=@('test','-p','edy-remediation','-p','edy-storage','-p','edy-desktop','--locked') }
    'RemediationForbiddenRelease' { $Executable=$Cargo; $Arguments=@('check','-p','edy-remediation','--release','--features','test-remediation-executor','--locked') }
    'DesktopForbiddenRelease' { $Executable=$Cargo; $Arguments=@('check','-p','edy-desktop','--release','--features','test-remediation-executor','--locked') }
    'RemediationProductionRegression' { $Executable=$Cargo; $Arguments=@('test','-p','edy-remediation','--release','--test','production_policy','--locked') }
    'RustcVersion' { $Executable=$Rustc; $Arguments=@('--version') }
    'RustcSysroot' { $Executable=$Rustc; $Arguments=@('--print','sysroot') }
    'CargoVersion' { $Executable=$Cargo; $Arguments=@('--version') }
    'RustfmtVersion' { $Executable=$Rustfmt; $Arguments=@('--version') }
    'ClippyVersion' { $Executable=$Cargo; $Arguments=@('clippy','--version') }
    'CargoAuditVersion' { $Executable=$Audit; $Arguments=@('--version') }
    'CargoDenyVersion' { $Executable=$Deny; $Arguments=@('--version') }
    default { throw 'PROJECT_RUST_EXECUTION_DENIED: action is not allowlisted' }
}

& $Executable @Arguments
exit $LASTEXITCODE
