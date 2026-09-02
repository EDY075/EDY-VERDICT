# Repeatable evidence collection. Does NOT run the Tauri application or package it.
param([switch]$RunAuthorizedFakeCredentialTest)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Enter-Project.ps1')
$Evidence = Join-Path $ProjectRoot 'docs/security/evidence'
New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
$Results = [Collections.Generic.List[object]]::new()
function Gate([string]$Name,[scriptblock]$Command) {
    $global:LASTEXITCODE = 0
    & $Command 2>&1 | Out-File -LiteralPath (Join-Path $Evidence "$Name.log") -Encoding utf8
    $code = $LASTEXITCODE
    $Results.Add([pscustomobject]@{check=$Name;exit_code=$code;result=if($code -eq 0){'PASS'}else{'FAIL'}})
    Write-Output "$Name exit=$code"
}
Gate 'rust-tests-infrastructure' { cargo test --workspace --exclude edy-desktop --locked }
Gate 'rust-clippy-infrastructure' { cargo clippy --workspace --exclude edy-desktop --all-targets --locked -- -D warnings }
Gate 'rust-fmt-all' { cargo fmt --all -- --check }
if ($RunAuthorizedFakeCredentialTest) { Gate 'credential-fake-only' { cargo test -p edy-storage --locked secrets::tests -- --ignored --test-threads=1 } }
Gate 'cargo-audit' { cargo audit }
& cargo audit --json 2> (Join-Path $Evidence 'cargo-audit-json.stderr.log') | Out-File -LiteralPath (Join-Path $Evidence 'cargo-audit.json') -Encoding utf8
Gate 'cargo-deny' { cargo deny check }
& cargo deny --format json check 2>&1 | Out-File -LiteralPath (Join-Path $Evidence 'cargo-deny.jsonl') -Encoding utf8
Gate 'pnpm-install-frozen' { pnpm install --frozen-lockfile }
Gate 'pnpm-typecheck' { pnpm typecheck }
Gate 'pnpm-lint' { pnpm lint }
Gate 'pnpm-test' { pnpm test }
Gate 'pnpm-build' { pnpm build }
Gate 'pnpm-audit' { pnpm audit --audit-level=high }
Gate 'supply-chain-generation' { node scripts/supply-chain.mjs }
Gate 'secret-scan' { node scripts/secret-scan.mjs }
$Results.Add([pscustomobject]@{check='rust-workspace-including-desktop';exit_code=$null;result='BLOCKED';reason='Relevant Windows unmaintained advisories; no automatic exception'})
$Results.Add([pscustomobject]@{check='tauri-native-build-and-runtime-smoke';exit_code=$null;result='NOT TESTED';reason='Promotion gate failed; user conditional authorization not satisfied'})
$Results | ConvertTo-Json -Depth 6 | Out-File -LiteralPath (Join-Path $Evidence 'gate-results.json') -Encoding utf8
$Audit = Get-Content -LiteralPath (Join-Path $Evidence 'cargo-audit.json') -Raw | ConvertFrom-Json
Write-Output ('Cargo audit vulnerabilities: '+$Audit.vulnerabilities.count+'; informational warnings retained')
if ($Results.result -contains 'FAIL') { exit 1 }
