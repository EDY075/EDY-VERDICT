$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$env:RUSTUP_HOME = Join-Path $ProjectRoot '.local/rustup'
$env:CARGO_HOME = Join-Path $ProjectRoot '.local/cargo'
$env:CARGO_TARGET_DIR = Join-Path $ProjectRoot 'target'
$env:TEMP = Join-Path $ProjectRoot '.local/tmp'
$env:TMP = $env:TEMP
$env:npm_config_cache = Join-Path $ProjectRoot '.local/npm-cache'
$env:PNPM_HOME = Join-Path $ProjectRoot '.local/pnpm-home'
foreach ($directory in @($env:RUSTUP_HOME,$env:CARGO_HOME,$env:TEMP,$env:PNPM_HOME)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
$NodeDir = Join-Path $ProjectRoot '.local/toolchains/node-v24.20.0-win-x64'
$env:PATH = "$NodeDir;$(Join-Path $ProjectRoot '.local/audit-tools/bin');$(Join-Path $env:CARGO_HOME 'bin');$env:PATH"
function pnpm { & (Join-Path $NodeDir 'node.exe') (Join-Path $ProjectRoot '.local/toolchains/pnpm-11.25.0/package/bin/pnpm.cjs') "--config.state-dir=$(Join-Path $ProjectRoot '.local/pnpm/state')" @args }
# Discover existing MSVC, with no permanent environment changes.
$VsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (Test-Path -LiteralPath $VsWhere) {
    $VsPath = & $VsWhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($VsPath) {
        Import-Module (Join-Path $VsPath 'Common7/Tools/Microsoft.VisualStudio.DevShell.dll')
        Enter-VsDevShell -VsInstallPath $VsPath -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64' | Out-Null
    }
}
Set-Location -LiteralPath $ProjectRoot
