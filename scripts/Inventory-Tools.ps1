$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Enter-Project.ps1')
$Receipt=Join-Path $ProjectRoot 'tools/receipts/toolchains.json'
$Tools=[Collections.Generic.List[object]]::new()
function Add-Tool([string]$Name,[string]$Requested,[string]$Version,[string]$File,[string]$Source,[string]$License,[string]$Status) {
    $Digest=if($File -and (Test-Path -LiteralPath $File)){(Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
    $Location=if($File -and $File.StartsWith($ProjectRoot,[StringComparison]::OrdinalIgnoreCase)){[IO.Path]::GetRelativePath($ProjectRoot,$File).Replace('\','/')}elseif($File){'existing-host-tool-discovered-at-runtime'}else{$null}
    $Tools.Add([pscustomobject]@{tool=$Name;requested_version=$Requested;installed_version=$Version;source=$Source;license=$License;status=$Status;location=$Location;sha256=$Digest})
}
$RustBin=Join-Path $env:RUSTUP_HOME 'toolchains/1.98.0-x86_64-pc-windows-msvc/bin'
Add-Tool 'Rust' '1.98.0' (& scripts/Invoke-ProjectRust.ps1 -Action RustcVersion) (Join-Path $RustBin 'rustc.exe') 'https://static.rust-lang.org/dist/channel-rust-1.98.0.toml' 'MIT OR Apache-2.0' 'READY_PROJECT_LOCAL'
Add-Tool 'Cargo' '1.98.0' (& scripts/Invoke-ProjectRust.ps1 -Action CargoVersion) (Join-Path $RustBin 'cargo.exe') 'https://static.rust-lang.org/' 'MIT OR Apache-2.0' 'READY_PROJECT_LOCAL'
Add-Tool 'rustfmt' 'component of Rust 1.98.0' (& scripts/Invoke-ProjectRust.ps1 -Action RustfmtVersion) (Join-Path $RustBin 'rustfmt.exe') 'https://static.rust-lang.org/' 'MIT OR Apache-2.0' 'READY_PROJECT_LOCAL'
Add-Tool 'clippy' 'component of Rust 1.98.0' (& scripts/Invoke-ProjectRust.ps1 -Action ClippyVersion) (Join-Path $RustBin 'cargo-clippy.exe') 'https://static.rust-lang.org/' 'MIT OR Apache-2.0' 'READY_PROJECT_LOCAL'
Add-Tool 'Node' '24.20.0' (& node --version) (Join-Path $ProjectRoot '.local/toolchains/node-v24.20.0-win-x64/node.exe') 'https://nodejs.org/dist/v24.20.0/' 'MIT and bundled notices' 'READY_DEV_ONLY_AUTHENTICODE_VALID'
Add-Tool 'pnpm' '11.25.0' (& pnpm --version) (Join-Path $ProjectRoot '.local/downloads/pnpm-11.25.0.tgz') 'https://registry.npmjs.org/pnpm/11.25.0' 'MIT' 'READY_PROJECT_LOCAL_SHA512_VERIFIED'
Add-Tool 'cargo-audit' '0.22.2' (& scripts/Invoke-ProjectRust.ps1 -Action CargoAuditVersion) (Join-Path $ProjectRoot '.local/audit-tools/bin/cargo-audit.exe') 'https://crates.io/crates/cargo-audit/0.22.2' 'Apache-2.0 OR MIT' 'READY_DEV_ONLY_SOURCE_BUILD_LOCKED'
Add-Tool 'cargo-deny' '0.20.2' (& scripts/Invoke-ProjectRust.ps1 -Action CargoDenyVersion) (Join-Path $ProjectRoot '.local/audit-tools/bin/cargo-deny.exe') 'https://crates.io/crates/cargo-deny/0.20.2' 'MIT OR Apache-2.0' 'READY_DEV_ONLY_SOURCE_BUILD_LOCKED'
$Compiler=(Get-Command cl.exe).Source
Add-Tool 'MSVC' 'existing compatible MSVC x64' (Get-Item -LiteralPath $Compiler).VersionInfo.FileVersion $Compiler 'https://visualstudio.microsoft.com/visual-cpp-build-tools/' 'Microsoft license' 'REUSED_NO_INSTALL'
Add-Tool 'Git' 'existing' (& git --version) (Get-Command git.exe).Source 'https://git-scm.com/' 'GPL-2.0-only' 'REUSED_NO_INSTALL'
$WebViewVersion=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -Name pv).pv
Add-Tool 'WebView2 Evergreen' 'existing stable' $WebViewVersion '' 'https://developer.microsoft.com/microsoft-edge/webview2/' 'Microsoft runtime redistribution terms' 'EXISTING_RUNTIME_NOT_SMOKE_TESTED'
$OperatingSystem=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName,DisplayVersion,CurrentBuildNumber,UBR,EditionID
$ReceiptData=[ordered]@{recorded_at_utc=[DateTime]::UtcNow.ToString('o');target='x86_64-pc-windows-msvc';operating_system=[ordered]@{product=$OperatingSystem.ProductName;release=$OperatingSystem.DisplayVersion;build=($OperatingSystem.CurrentBuildNumber+'.'+$OperatingSystem.UBR);edition=$OperatingSystem.EditionID};global_installs_modified=$false;tools=$Tools;node_archive_sha256='6cac9ffbca8f6a47091e4b5c772e0606049c3871cb67d900c0cedde630e545ba';pnpm_archive_integrity='sha512-XN6SW08HX3Jetx+64YpC/+eEUkeJ8ZthxzHLhyHsKKruFg4BqNWvT+2ypCzb8wDv4j2zVrDUoXtNY+EfirfJVg==';rust_verification='rustup official distribution manifests/checksums; no independent reproducible-build attestation claimed'}
$ReceiptData.Remove('global_installs_modified')
$ReceiptData['final_global_toolchains_unchanged']=$true
$ReceiptData['provisioning_incident']='A version check without project environment triggered a duplicate Rust 1.98.0 in the user-global rustup home. Only that newly created duplicate was removed; stable 1.97.1 and Node 24.17.0 remained unchanged. See docs/security/provisioning-incident.md.'
$ReceiptData | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $Receipt -Encoding utf8
$Tools | Select-Object tool,installed_version,status | Format-Table -AutoSize
