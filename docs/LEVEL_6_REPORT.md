# EDY VERDICT — Level 6 COMPLETE

Completed on 03/09/2026 under the revised production policy: guidance, manual change
outside EDY VERDICT, explicit rescan-only authorization and fresh original-family
verification. Level 7 was not started.

## Security disposition

L6-S01 root cause: production file replacement could not prove sufficiently strong
concurrent-modification safety under the approved Windows 10 constraints. This is not a
general claim about Windows. The finding is
**CLOSED_BY_REMOVAL_OF_PRODUCTION_MUTATING_CAPABILITY**, not accepted or downgraded.

- Production mutating executor: DISABLED / POLICY_BLOCKED.
- Production apply and rollback IPC: ABSENT.
- Arbitrary/deterministic write, file deletion/quarantine and host changes: ABSENT.
- Historical reversible executor: TEST_ONLY, compile-time isolated.
- Release with mutating feature: DENIED by compile_error.
- Release executor, mutation IPC, recovery journal, fault injection and WebDriver exposure: 0.
- Critical: 0; High: 0; Medium: 0.
- Low: 2 documented limitations (finite redaction patterns; byte-string release audit is
  corroborating evidence rather than complete disassembly).
- Informational: the full cross-platform Cargo.lock audit has 0 vulnerabilities but reports
  16 unmaintained and 1 unsound inactive/informational dependency warnings. The approved
  Windows cargo-deny gate remains exactly five known unic-* advisories and zero new advisories.

The historical ReplaceFileW counterexamples remain unchanged in
`_intake/level6-final-remediation/`. The successful security pivot evidence is in
`_intake/level6-safety-pivot/`.

## Completed production workflow

The implemented flow is:

`Level 5 case/finding → remediation plan → guidance and sanitized suggested diff →
manual change outside EDY VERDICT → single-use rescan authorization → fresh original
scanner/check family → resolved / still present / inconclusive / regression / target
invalid / cancelled`.

The repository plan binds the actual source finding, real case membership, canonical local
root, read-only directory identity, original fingerprint, ecosystem, logical manifest paths
and baseline material findings. Frontend requests cannot provide a path, diff, replacement,
command or scan observation. A changed pre-scan hash is expected after manual work; root
identity and fresh snapshots must remain stable during the verification itself.

Resolved requires original finding absent, all required checks executed, sufficient coverage,
stable verification snapshots, no contradiction and no new material finding. Removal of the
manifest, provider/checker unavailability, errors and partial coverage cannot produce
resolution. The available repository family currently covers existing edy-inventory lockfile
presence and empty-lockfile checks; it does not claim full dependency vulnerability coverage.

## Storage, cases and restart

SQLite schema 8 stores bounded SHA-256-validated plans, guidance, authorization metadata,
results and timeline. It stores no raw authority. Revision CAS, authority consumption,
Level 5 membership and timeline updates occur in one transaction. One resolved finding does
not resolve other members; a case resolves only when every member has a current resolved
result and reopens on regression/reverification.

Startup turns pending/running verification into INTERRUPTED, consumes the prior authority
once and performs no target write or automatic rescan. The UI supports fresh explicit
verification/resume. Migration tests cover schema versions 0 through 7 into 8, foreign keys,
prior-data preservation, no orphan plans, revision conflict and all required restart states.

## Native and redaction proof

The real debug-only Tauri/WebView2 E2E uses React, typed Isolation IPC, the Rust backend,
actual edy-inventory rescans, SQLite and reports. External harness code alone creates/changes
synthetic fixture files. It passed three viewports (1366×768, 1920×1080, 2560×1440) and:

- create-before-plan, guidance and suggested diff;
- apply/rollback controls absent and raw mutation commands rejected;
- concurrent content and path changes preserved with zero EDY writes;
- still present, resolved, inconclusive, regression, cancellation and target invalid;
- planned, awaiting, pending/running→interrupted, resolved, regression, cancelled and
  inconclusive restart/rehydration;
- case membership/timeline persistence and read-only CLI output.

Five synthetic Level 6 sentinels were propagated through controlled inputs and checked across
plan, guidance, suggested diff, authorization metadata, results, case timeline, SQLite, logs,
CLI, IPC, JSON/HTML reports, React state and DOM. Plaintext occurrences outside intentional
source fixtures: 0. This finite matrix is not a universal secret-detection guarantee.

## QA

- Rust workspace: PASS, 302 tests, 0 failures (including compile-fail export proofs).
- Native-feature Rust: PASS.
- Clippy `-D warnings`: PASS.
- rustfmt check: PASS.
- Frontend: typecheck PASS, lint PASS, Node architecture/direct-call 15 PASS,
  Vitest 86 PASS, build PASS.
- Native Tauri/WebView2 E2E: PASS.
- Production release build: PASS.
- Release-profile L6-S01 regression: PASS.
- Production + mutating feature: DENIED for library and desktop.
- CLI schema-8 read-only matrix: PASS; database unchanged.
- pnpm audit: 0 unresolved vulnerabilities.
- cargo-deny: exactly five known unic-* upstream advisories; new advisories 0.
  Licenses/sources/bans PASS; no exception was added.
- Cargo archive integrity: 326/326; npm inventory: 351. Thirty-seven packages without a
  root license text remain a public-distribution review action, not a Level 6 runtime gate.
- Owned source/docs secret heuristic: 0 findings.
- Rustup prevention: 14/14 environment cases and 9/9 direct-call tests PASS; controlled
  direct calls 0.
- Global inventory: only stable; default and persistent PATH/settings hashes unchanged;
  global 1.98 absent; no new incident.

## Production policy matrix

| Capability | Production result |
|---|---|
| Automatic repository patch | POLICY_BLOCKED |
| Installed-app auto-remediation | POLICY_BLOCKED |
| File delete/quarantine | POLICY_BLOCKED |
| Web remote remediation | POLICY_BLOCKED |
| Secret rotation | MANUAL |
| Windows auto-fix | POLICY_BLOCKED |
| Remediation guidance | READY |
| Manual-change rescan | READY |
| Verification | READY |

## Remaining independent constraint

`TAURI_UPSTREAM_GATE = WAITING_FOR_OFFICIAL_RELEASE`. Tauri remains pinned; the five
known unic-* advisories are neither waived nor “fixed” here. This separate Level -1C gate
does not reopen L6-S01 or the completed Level 6 non-mutating workflow. No public release,
installer, push, host configuration change or Level 7 work occurred.
