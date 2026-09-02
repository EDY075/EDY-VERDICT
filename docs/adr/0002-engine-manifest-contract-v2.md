# ADR 0002 — Engine Manifest Contract V2

Status: accepted and frozen for the Level -1D.1 contract gate.

## Context

Manifest V1 flattened identity, platform, provenance and limits. Its single
provenance enum could not represent multiple simultaneous evidence types, the receipt
contained only a promotion boolean, and the JSON Schema and Rust model could drift.
No real engine had been promoted, so compatibility with stored production manifests
was not required.

## Decision

Engine Manifest V1 is **SUPERSEDED**. V2 is **ACTIVE**. The V1 schema remains only as
historical documentation and a regression fixture. A V1 document produces the typed
`ManifestVersionUnsupported` error and is never converted implicitly.

V2 uses the following normalized objects:

```text
EngineManifest
├── schema_version
├── identity       # id, version, platform, architecture
├── source         # immutable upstream/release/asset identity
├── artifact       # entrypoint plus the complete closed file set
├── provenance     # structured observations; not a trust boolean
├── license        # SPDX declaration distinct from redistribution decision
├── extraction     # mandatory finite fail-closed limits
├── process        # no shell; bounded process and I/O
├── version_probe  # arguments only; the entrypoint is not user-selectable
└── review          # role and policy version
```

All object parsers deny unknown fields. Hashes are lowercase SHA-256. Contractual
paths use a deliberately ASCII-only subset, are relative `/`-separated paths, and
reject traversal, absolute/UNC/drive paths, ADS, reserved device names, case
collisions and duplicates. `closed_set=true` means the
entrypoint and every auxiliary record are the complete regular-file set; directories,
the external manifest and the external receipt are not members.

Provenance supports `verified`, `present_unverified`, `unavailable` and `failed`.
Only policy-selected `verified` records may satisfy a positive requirement. A failed
record is a valid observation but is policy-blocking. Checksum/attestation records are
semantically bound to the selected asset hash; Authenticode is bound to the entrypoint
hash. A signed source commit is not a binary attestation.

The manifest does not declare `trusted=true`. `EngineTrustPolicy` calculates a
decision. Authorization to download remains an external user decision.

## Canonicalization and hashes

V2 chooses **DETERMINISTIC_TYPED_JSON_V1**, not RFC 8785/JCS:

1. Reject malformed JSON and duplicate members before typed deserialization.
2. Validate schema V2 and all semantic invariants.
3. Serialize the Rust V2 structs as compact UTF-8 JSON in declared field order.
4. Sort set-like arrays first: auxiliary files by case-folded relative path,
   provenance by `(type, subject, source)`, formats by enum order, and exit codes
   numerically.
5. No map-valued contractual field is permitted.
6. `manifest_sha256` is lowercase SHA-256 of those exact bytes.

The artifact-set input is compact deterministic JSON of
`{"files":[{"relative_path", "sha256", "size"}, ...]}` with the entrypoint and all
auxiliary files sorted by case-folded relative path. `artifact_set_sha256` hashes those
exact UTF-8 bytes. Whitespace and property order in an accepted input do not affect
either hash; contractual value changes do.

This algorithm is versioned by the Contract V2 specification. Changing it requires a
new contract decision and invalidates prior receipts.

## Receipt V2 and fail-closed states

The external receipt pins engine/version, canonical manifest hash, entrypoint hash,
closed artifact-set hash, promotion time and state. `staged` requires a null promotion
time; all later states require a valid UTC timestamp. Execution readiness requires:

- valid V2 manifest;
- receipt present and in `ready` state;
- policy accepted;
- canonical manifest, entrypoint and observed artifact-set hashes all equal.

The derived failure states are `INVALID_MANIFEST`, `UNVERIFIED`, `TAMPERED` and
`POLICY_BLOCKED`; every one denies execution. A receipt is a tamper-detection anchor,
not a cryptographic trust root: an attacker able to rewrite engine, manifest and the
external receipt together is outside this V2 guarantee. A signed/embedded catalog or
protected ACL would be a separate future control.

`network_policy=deny` expresses authorization policy, not a claim that Windows Job
Objects provide network isolation. The Level -1D.1 readiness function therefore never
returns `READY`, even after integrity succeeds; it returns `POLICY_BLOCKED` until a
future authorized runner can provide the required enforcement.

## Consequences

- V1 and V2 are not concurrently active.
- No duplicate `id/engine_id`, URL or timeout semantics remain.
- Schema/Rust shape, enum and negative-corpus tests guard drift.
- Acquisition stays deliberately blocked pending a separate authorization.
- Tauri, React, pnpm, NSIS, storage, providers and Windows configuration are unchanged.
