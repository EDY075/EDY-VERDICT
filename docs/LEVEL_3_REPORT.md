# EDY VERDICT — Level 3: Installed Application Security

Date: 2026-09-02. Scope is Level 3 only. No application was installed, updated,
removed or remediated; no engine was executed; no host inventory was sent to any
provider; Level 4 was not started.

## Implemented contract

- read-only 64/32-bit HKLM and HKCU uninstall registry views via Win32 APIs;
- current-user MSIX enumeration via WinRT, with other users explicitly out of scope;
- deterministic normalization, conservative exact/strong deduplication and raw plus
  normalized versions (`sem_ver`, dotted numeric, vendor-specific, unknown);
- versioned curated alias dataset, CPE 2.3 parser, PURL support and six identity states;
- inclusive/exclusive numeric affected-range evaluation without lexical comparison;
- one `INSTALLED_APP_VULNERABILITY_V1` finding per application/version/CVE/scope;
- NVD CVSS enrichment, CISA KEV and EPSS priority enrichment with separate semantics;
- SQLite schema v4, three local report kinds, typed IPC and Installed Apps UI;
- optional bounded DisplayIcon/Authenticode enrichment reusing Level 2 offline logic.

## Inventory coverage

| Source | Coverage |
|---|---|
| HKLM 64-bit uninstall | Supported, read-only |
| HKLM 32-bit uninstall | Supported, read-only alternate view |
| HKCU 64-bit uninstall | Supported, read-only |
| HKCU 32-bit uninstall | Supported, read-only alternate view |
| MSIX current user | Supported through WinRT |
| Other users | Not covered; no elevation |
| Portable applications | Not covered |
| Filesystem crawling | Forbidden |
| `Win32_Product` | Forbidden |

The real-host smoke returned only aggregate evidence: 355 raw records and all four
registry views plus current-user MSIX available. No names, publishers, versions,
paths or raw registry data were written to evidence or transmitted.

## Public provider contract

| Provider | Scope | Key | Mandatory cost | Cache/freshness |
|---|---|---|---:|---|
| NVD API 2.0 | Fixed `CVE-2021-44228` development query only | Optional BYOK, not configured | R$0 | validated SHA-256, 24 h |
| CISA KEV | Complete official JSON catalog | None | R$0 | validated SHA-256, 24 h |
| FIRST EPSS | Complete official daily gzip CSV | None | R$0 | validated SHA-256, 48 h |

The 2026-09-02 live smoke used no credential and returned NVD 373 CPE records,
CISA KEV catalog `2026.09.02` with 1,694 entries, and EPSS with 367,327 entries.
Hashes and counts are retained in the external Level 3 evidence ledger. Network
failure preserves the previous validated pair as stale; tampered or mismatched
current data cannot be READY.

KEV means a validated CVE is known exploited in the wild, not that this host was
exploited. EPSS influences priority only, never CVSS severity. A documented fixed
version does not prove an update is available on this host.

## Acceptance evidence

| Gate | Result |
|---|---|
| Core normalization/identity/version/range/correlation | PASS |
| Registry/MSIX real read-only aggregate smoke | PASS |
| Provider parsers, bounds, origin and cache tamper tests | PASS |
| Storage fresh + Level 0/1/2 migration preservation | PASS |
| Reports JSON/HTML determinism and escaping | PASS |
| IPC + Isolation exact allow/deny contracts | PASS |
| Frontend typecheck/lint/unit/build | PASS using already-present binaries |
| Native Tauri/WebView2/React/IPC/SQLite/report E2E | PASS, three resolutions / 22 semantic screens |
| Native cancellation | PASS, three resolutions; persisted `cancelled`, zero findings, no verdict |
| Native stale/unavailable provider state | PASS; explicit incomplete coverage |
| Native safe error state | PASS; rejected reuse of single-use authorization |
| Rust workspace tests / Clippy warnings-as-errors / fmt | PASS |
| Cargo deny licenses/sources/bans | PASS |
| Cargo deny advisories | expected FAIL: five pre-existing `unic-*` advisories via pinned Tauri |
| Real engines / reputation / remediation | Not run by policy |

The project-local Node 24.20.0 and pnpm 11.25.0 entrypoints executed typecheck, lint,
tests and the production frontend build successfully. Because the already-present
`node_modules` metadata is older than the frozen lockfile, QA disabled pnpm's
pre-run synchronization check for these commands only; no install, update, lockfile
change or package resolution was performed.

The final native build caused Rustup to fetch the missing `rust-src` component into
the already-approved project-local 1.98.0 toolchain. No global toolchain, default or
PATH changed; this local prerequisite download did not install Windows software.

## Provider sources

- NVD API 2.0: <https://nvd.nist.gov/developers/vulnerabilities>
- CISA KEV catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- FIRST EPSS data: <https://www.first.org/epss/data>
- Win32 alternate registry views: <https://learn.microsoft.com/windows/win32/winprog64/accessing-an-alternate-registry-view>
- WinRT current-user packages: <https://learn.microsoft.com/uwp/api/windows.management.deployment.packagemanager.findpackagesforuser>

## Preserved constraints

`TAURI=2.11.5`, `tauri-utils=2.9.3`, `urlpattern=0.3.0` and all engine versions are
unchanged. `TAURI_UPSTREAM_GATE=WAITING_FOR_OFFICIAL_RELEASE`; `LEVEL-1C=FAIL /
WAITING UPSTREAM`. Defender remains optional/disabled, SMBIOS remains untrusted,
reputation remains disabled and real engine execution remains policy-blocked.

No push, PR, deploy, packaging, installer, release, host remediation, API-key
configuration, Windows/Defender/SMBIOS/PATH change or Level 4 work occurred.
