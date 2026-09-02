# EDY VERDICT — Level 3 security review

Date: 2026-09-02. Scope: Installed Application Security delta only. This is a
manual code review plus automated local tests, not an independent audit or a claim
that the host is safe.

## Trust boundaries

Registry and current-user MSIX metadata are attacker-controlled input. Values are
read directly through Win32 registry APIs and WinRT; `Win32_Product` is forbidden.
Uninstall commands are never collected. Other users, portable applications and
filesystem crawling are explicitly outside coverage.

The core owns normalization, identity confidence, exact version-range evaluation,
priority and correlation without registry, filesystem or HTTP access. Provider
adapters accept only fixed HTTPS origins. NVD receives one fixed development CVE
query; no application name, version, CPE, inventory or machine identifier is sent.
CISA KEV and EPSS are complete public datasets. Redirect count, origins, response
and decompression sizes are bounded. Cache promotion uses staging, retains a
previous pair, and revalidates source URL, size and SHA-256 before showing READY.

Only exact, curated or strong identity may reach automatic CVE evaluation.
Heuristic, unmapped and conflicting identities are review states. Only the exact
`affected` range result creates a vulnerability finding. Unknown, unparseable,
uncertain and unavailable states never become a positive or a clean result.

## DisplayIcon enrichment

Signature enrichment starts only after preview and explicit authorization. It
accepts one absolute local `.exe` or `.dll` candidate, with bounded `%VAR%`
expansion, optional quotes and numeric icon index. Relative, UNC/device, command,
malformed and non-PE inputs are rejected; there is no directory search or process
execution. The existing Level 2 secure-open, identity revalidation, bounded read and
offline Authenticode implementation is reused. Work is capped at eight unique
candidates of at most 16 MiB. Signature evidence never implies safety.

## IPC, persistence and reports

Seven Level 3 commands are purpose-specific. The Tauri manifest, local capability,
Isolation hook, Rust origin/window guard and TypeScript response parsers all enforce
closed shapes. There is no generic registry, filesystem, SQL, URL or provider IPC.
Preview and authorization are bounded and process-local; both are single-use.
The synthetic Level 3 worker is cancellable: cancellation is persisted before the
token is signalled, terminal snapshots cannot be resurrected by a late worker, and
a cancelled run retains zero findings and no final verdict.

SQLite schema v4 preserves earlier snapshots and stores deterministic Level 3
payloads with optimistic revisions and a SHA-256 corruption check. The digest is
not an authenticity boundary against same-user malware. Reports omit uninstall
commands, registry exports, API keys and credentials; they preserve provider state,
identity uncertainty, coverage limitations and the fixed-version availability
caveat.

## Findings

| Severity | Open | Resolution |
|---|---:|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 1 | Accepted: synchronous confirmed DisplayIcon enrichment may add bounded UI latency; cap is 8 × 16 MiB and no verdict is weakened. Move to a cancellable worker before expanding the cap. |
| Informational | 2 | Provider cache SHA-256 detects accidental/tamper divergence but is not a same-user authenticity boundary. NVD live validation is intentionally a fixed synthetic query, not host-wide enrichment. |

The E2E exposed and fixed integration defects before acceptance: the Isolation
hook had not yet admitted the seven structurally validated Level 3 commands. A
regression test now covers allowed and denied payloads. The original synchronous
synthetic scan also could not exercise Level 3 cancellation; it is now a persisted,
terminal-safe worker and is validated through the real Tauri/WebView2 UI at all
three required resolutions. A degraded native fixture separately verifies stale
and unavailable provider presentation.

## Security conclusion

`CRITICAL=0`, `HIGH=0`, `MEDIUM=0`. The accepted Low does not permit code execution,
external disclosure, false affected findings or a clean verdict. Tauri upstream
advisories remain the separate pre-existing Level -1C blocker and are not reclassified
as a Level 3 defect.
