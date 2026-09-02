# EDY VERDICT Level 0 core

Status: implemented and integrated for the controlled synthetic Level 0 workflow. This is not
a production scanner.

## Boundary

`edy-core` owns domain identities, validation, lifecycle rules, evidence/finding contracts,
correlation, verdict calculation, orchestration contracts and remediation/rescan state. It does
not know Tauri, WebView2, SQLite, HTTP, operating-system APIs, engine binaries or UI concepts.
Those concerns implement the ports exposed by the core.

The crate adds no dependency beyond the workspace `serde` contract. Consequently it validates
UUIDv7 strings but does not generate IDs, measures no wall-clock time, opens no files and starts
no processes. Callers supply IDs, normalized UTC timestamps and engine outcomes. This keeps core
tests deterministic and makes policy decisions auditable.

## Invariants

- All entity IDs are typed UUIDv7 values. Engine IDs are normalized lower-case tokens.
- Timestamps are normalized UTC seconds (`YYYY-MM-DDTHH:MM:SSZ`).
- Target kind and locator kind must agree; website locators require HTTPS.
- Evidence and findings expose read-only getters; state changes pass through lifecycle methods.
- Scan coverage is recorded per `(engine, target)`, so reusing one engine for many targets is not
  collapsed into a single check.
- Planned provider availability is part of coverage and cannot remain `complete` when a provider
  is unavailable, offline, rate-limited, unconfigured or policy-blocked.
- Failed, skipped or cancelled checks never become complete coverage.
- Risk and confidence are separately range-checked values.
- `NoKnownIndicators` means only that all planned checks completed and observed no indicators. It
  never means safe, harmless or guaranteed clean.
- Cancellation is successful only when the engine adapter confirms cleanup. Otherwise the job is
  failed and cleanup remains pending.

## Ports and ownership

`EngineTaskRunner` is the synchronous deterministic test seam for a real Engine Manager adapter.
The adapter, not the core, must enforce process containment, timeouts and descendant cleanup.
`FindingIdSource` lets an outer layer supply UUIDv7 IDs. `RemediationExecutor` is a contract only;
the core ships no host mutation.

Domain events are serializable integration messages, not a durable event store. Persistence must
write envelopes transactionally, preserve schema versions and reject invalid payloads before
reconstructing domain state. Public aggregate deserialization re-applies constructors and
cross-field invariants rather than trusting serialized private fields.

## Level 0 readiness

The domain is wired through dependency-injected orchestration, SQLite snapshots, typed Tauri IPC,
deterministic JSON/HTML reporting and the React workflow. The end-to-end path accepts only a
backend-owned synthetic fixture. Success, partial failure, unavailable coverage, cancellation,
startup reconciliation, storage reload and report generation have automated coverage.

The Engine Manager has an integrity/containment gate and process-level tests, but the desktop does
not call it in production. Real engine smoke is skipped by policy: Job Objects do not enforce
network denial, and Trivy/OSV offline data was not downloaded. Production readiness still requires
the later-level real-target authorization model, promoted adapters/data, operational recovery,
packaged runtime validation and the independent Tauri upstream gate.
