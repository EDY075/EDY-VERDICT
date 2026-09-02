# Foundation contract — JR owned

Frozen before specialist work. Only JR changes root manifests, lockfiles or core
shared contracts. Specialists deliver source plus evidence; JR reviews and runs
combined gates. Shared directory editing is disjoint, not parallel integration.

Allowed internal dependencies:
- edy-core: none; no Tauri/Tokio/SQLite/reqwest/WebView/frontend.
- edy-repository and edy-providers: edy-core only.
- edy-engine-manager: edy-core plus edy-repository; edy-storage: edy-core;
  edy-reporting: edy-core plus the Level 1/2 domain crates it renders.
- edy-cli and desktop Rust: the approved library crates, not each other.

All contracts are structural, snake_case serde enums, severity != confidence.
Unavailable != clean. Level 0 adds a documented, versioned numeric risk/confidence model;
providers remain closed contracts until their owning level. Level 3 adds read-only Windows
inventory plus fixed-origin NVD/CISA KEV/EPSS public-data adapters; the core still has no HTTP.
Wire envelope schema_version=1, producer_version, generated_at_utc, data.
The earlier infrastructure envelope keeps opaque strings for backward compatibility. Level 0
domain entities use fail-closed UUIDv7 IDs, normalized UTC timestamps and validated aggregate
deserialization; these do not silently change the infrastructure envelope schema.

Storage API required by desktop: `Storage::open(&Path) -> Result<Storage, ...>`.
It creates only infrastructure schema. `schema_version()` returns its version.
Secret adapter is native Windows Credential Manager, no frontend secret command.
Only fake credential target EDY-VERDICT-LEVEL1C-TEST is authorized for tests;
never overwrite a preexisting credential at that target. Cleanup even on failure.

The infrastructure status IPC has no arguments and returns
{core: "ready", storage: "ready", ipc: "restricted", schema_version: 1}.
These strings describe infrastructure, never safety of any analyzed target.
Native storage path: project .local/data for this development-only bootstrap.
There is no generic shell/filesystem/registry/SQL/HTTP IPC. Level 3 public refresh is a
confirmed closed-set operation and never accepts a URL, query, host inventory or credential.

Ownership: JR core/shared/config/docs/gates/providers/reporting/CLI;
Core specialist storage only; Engine specialist engine-manager + tools manifests;
UX specialist apps/desktop (own manifest changes only with JR agreement).
QA review returns defects to owner; JR integrates one delivery at a time.

## Engine Manifest Contract V2

The JR-owned engine contract is versioned independently from the core wire envelope,
SQLite schema and toolchain receipts. Manifest V1 is superseded; V2 is active. See
ADR 0002 and `tools/manifests/engine-manifest.schema.json`.

Manifest evidence and trust decisions are separate concepts. The Engine Manager
validates the structured observations and a policy computes acceptance. Receipt V2 is
an external integrity anchor; it does not self-authorize acquisition or execution.
Invalid manifest, missing receipt, hash divergence and unmet policy all deny execution.
Acquisition remains implemented by `DisabledAcquisition` for Level -1D.1.
