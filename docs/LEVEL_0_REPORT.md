# EDY VERDICT — Level 0 completion report

Date: 2026-09-02
Branch: `work/level0-night-20260902-024254`
Start commit: `4cd53bb02d8f3d9ca325f07d7d65ba180484fa31`
Immutable foundation: `f4cdd8ec2af4b0ab5c6d80480524b930affcfc15`

## Result

`LEVEL 0 = COMPLETE WITH ACTIONS` for the explicitly authorized synthetic scope.

This result does not promote the application for production scanning, packaging or release.
`LEVEL -1C = FAIL / WAITING TAURI UPSTREAM` remains independently true.

## Implemented

- Dependency-injected `ScanService` with deterministic clock/events, cancellation and fail-closed
  persistence/correlation/reporting behavior.
- Project-local SQLite Level 0 snapshots with transactions, optimistic revision checks, bounds,
  reopen/reload and startup reconciliation.
- Engine integrity gate covering manifest/receipt/artifact-set/path/type/hash/rules/config/data
  checks plus Win32 suspended process creation, handle allowlist, Job Object and bounded I/O.
- Immutable deterministic report snapshots for executive, technical and developer JSON plus a
  standalone escaped HTML renderer with a restrictive CSP.
- Ten purpose-specific Tauri IPC commands, exact Isolation payload validation, native window/origin
  checks, typed/bounded requests and safe structured errors.
- React workflow for status, synthetic scan, progress/cancel, findings, history, engines and report
  viewing, with explicit empty/error/partial semantics.

## Tested

- Rust workspace: 147 passed, 0 failed, 2 ignored-by-default; the two ignored Credential Manager
  tests were separately authorized and passed with unique fake targets and confirmed cleanup.
- Frontend: 38 tests passed; TypeScript typecheck, ESLint and production build passed.
- Clippy with `-D warnings`, rustfmt check and `git diff --check` passed.
- Synthetic E2E covers full pipeline, incomplete coverage, partial failure, cancellation,
  persistence reload, startup reconciliation and report generation.
- Visual QA at 1366×768, 1920×1080 and 2560×1440 found no document overflow or clipping; the real
  browser-only backend-unavailable/empty state rendered fail-closed. Loading/partial/cancel races
  are covered by component/E2E tests without adding a production mock route.
- Codex Security diff scan reviewed 29/29 generated code/config items with complete coverage and
  zero reportable findings.
- Local heuristic secret scan reviewed 37 changed files. The only generic-pattern hit was the
  explicit `password=FAKE_VALUE` storage test; engine fixture markers use the documented
  `EDY_FAKE_TEST_TOKEN_` namespace. No real secret was found.

## Synthetic only

- `create_synthetic_scan` accepts only `synthetic-target-a`.
- Observations are fabricated in memory by the controlled executor; no target file is opened.
- No user file, repository, URL, installed application, malware sample or real credential is read.
- Synthetic E2E demonstrates contract behavior, not production scanning effectiveness.

## Engine status

| Engine | Approved payload | Runtime smoke |
|---|---:|---|
| YARA-X 1.20.0 | integrity ready | `SKIPPED_BY_POLICY` — deny-network is not enforced |
| Gitleaks 8.30.0 | integrity ready | `SKIPPED_BY_POLICY` — deny-network is not enforced |
| Trivy 0.74.0 | integrity ready | `SKIPPED_BY_POLICY` — no approved offline database |
| OSV-Scanner 2.5.1 | integrity ready | `SKIPPED_BY_POLICY` — no approved offline data |

An unavailable/skipped engine lowers coverage/confidence and never becomes a clean result.

## Security and quality gates

- Isolation, CSP, capability allowlist, IPC validation and navigation/origin policy: pass.
- Release devtools disabled; remote/CDN content blocked; frontend shell/filesystem/clipboard denied.
- `cargo deny`: licenses, sources and bans pass. Advisories fail only for the five known
  transitive `unic-*` unmaintained advisories: RUSTSEC-2025-0075, -0080, -0081, -0098 and -0100.
- New advisories introduced by Level 0: 0. No exception or ignore was added.
- SQLite snapshot SHA-256 is a corruption check stored beside its payload, not an authenticated
  trust anchor against same-user malware.
- Win32 Job Objects contain process lifetime/resources but are not filesystem or network sandboxes.

## Deferred

- Real engine adapters/callers and real target selection.
- Enforced deny-network execution boundary and approved offline Trivy/OSV data lifecycle.
- Live providers, API/BYOK workflows and production secret entry UI.
- Repository/file/application/URL scans (Level 1+).
- Installer, packaging, code signing, deploy and release.

## Upstream blocked

The official Tauri release listing still identifies `tauri 2.11.5` as latest. Pins remain
unchanged. The five known `unic-*` advisories keep `TAURI_UPSTREAM_GATE = WAITING_FOR_OFFICIAL_RELEASE`
and `LEVEL -1C = FAIL / WAITING UPSTREAM`.

## Next action

`LEVEL0_COMPLETE_WAIT_TAURI`
