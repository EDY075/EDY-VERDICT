# Level 6 production remediation safety policy

## Decision: remove automatic target mutation

Production automatic file mutation was removed because concurrent replacement safety
could not be demonstrated to the product's required standard under the approved
Windows 10 constraints. This is NOT a general claim that safe replacement is impossible
on Windows. L6-S01 is closed only through removal of the affected production capability,
not an accepted or downgraded Medium.

The historical reproduction and six diagnostic checks remain in
`_intake/level6-final-remediation/`. They are not reclassified as successful safety tests.
The pivot evidence is in `_intake/level6-safety-pivot/`.

## Production boundary

For repository, file/binary, installed application, Web/URL, Windows and secrets targets,
automatic apply and rollback are policy blocked. No frontend path, patch, replacement
text, command or generic filesystem/SQL/shell/HTTP access is accepted by Level 6 IPC.
The apply/rollback commands are absent from handlers, build command registry, capabilities
and the Isolation allowlist. UI exposes guidance and explicit manual-change verification.

Production classes: GUIDANCE_ONLY, MANUAL_CHANGE_VERIFIABLE, POLICY_BLOCKED, UNSUPPORTED.
TEST_ONLY_REVERSIBLE is a data label for the isolated historical test executor; production
ManualSnapshot validation refuses it, executable edits and rollback eligibility.

The executor and its service compile only under cfg(test) or test-remediation-executor.
Release plus that feature is a compile error. native-e2e does NOT enable the executor.
WebDriver and fixture loading remain debug-only. An archived backend source file is
unregistered and cannot be linked from either production entrypoint.

## Manual-change verification

A plan originates from actual persisted Level 5 run/case/finding membership. For an
available repository inventory origin, the plan binds the canonical authorized root,
read-only directory identity, logical manifest paths, ecosystem, original fingerprint
and baseline material findings. No frontend target or expected-content scanner exists.

VerificationAuthorization authorizes ONLY that original-family rescan. Its action,
finding, case, run, target identity, plan hash, verification plan hash, expiry (5 minutes)
and single use are checked. Only token SHA-256 is persisted. Raw rescan authority remains
inside the transient frontend request closure, not React state or reports.

Changed content before an explicitly requested verification is expected. During the run,
the original inventory is freshly executed and bracketed by inventory/root identity
checks. Removed logical manifests, insufficient coverage, skipped/reparse entries,
unavailable original checker, errors, cancellation and contradictory evidence cannot
resolve the finding. New material inventory findings produce regression.

The current available production rescan family is edy-inventory's existing lockfile
presence/empty-lockfile checks. It does not validate full lockfile semantics or establish
absence of dependency vulnerabilities. Other scanner origins remain guidance/unsupported
and verification is inconclusive; no missing provider is silently treated as passing.

## Persistence and recovery

Schema 8 stores bounded, hash-validated manual plans, guidance, rescan metadata, results
and append-only events. Revision CAS, consumed authority, real case membership and Level 5
timeline updates share one SQLite transaction. A case resolves only when every persisted
member has a current resolved result; regression/reverification reopens it as appropriate.
Accepted cancellation is serialized with final result publication.

Startup converts pending/running verification to interrupted and consumes old authority,
once. It never replays scans, target writes or rollback. Explicit resume obtains new
rescan authority. Existing schema-7 historical data is preserved, but write journals,
backups and rollback receipts are not loaded by the production manual backend or CLI.

## Evidence and limitations

Architecture tests, absent-export compile-fail tests, release-profile regression,
forbidden-feature builds, native IPC probes and release byte-string audit jointly
establish removal. String absence alone is not a disassembly proof. Native automation
uses a debug-only WebDriver but the same non-mutating production backend; external test
harnesses alone modify their synthetic fixtures.

Five seeded Level 6 secret markers are tested across metadata, persisted cases, SQL,
reports, CLI, IPC and rendered UI. Redaction heuristics and finite regression tests are
not universal guarantees of secret detection or complete system safety.

The five known unic-* advisories remain a separate blocked Tauri upstream release gate,
without exceptions. No public release, installer or host configuration change is authorized.

## Future research — not enabled

Windows FileRenameInfoEx / POSIX rename / oplock strategies may be investigated in a
separate authorized task. They are NOT production-enabled and are NOT a Level 7 blocker.
