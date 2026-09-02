# EDY VERDICT — Level 1 Repository Security

Status: implementation complete for authorized inventory and synthetic validation; production engine execution remains policy-blocked.

## Contract

Level 1 accepts only an `AuthorizedRepositoryTarget`. A raw frontend path can request authorization, but it cannot enter a scan plan. The backend canonicalizes the path, requires an existing directory on a local fixed disk, rejects broad/system roots and reparse points, applies immutable limits, and returns an inventory preview. A second explicit confirmation is required to create a scan.

The supported categories are `secret`, `vulnerable_dependency`, `misconfiguration`, `supply_chain`, `license`, and `suspicious_repository_artifact`. There is no generic `other` category.

## Implemented

- backend path authorization, fixed-disk check, broad-root denylist, ADS/UNC/device-prefix rejection, and reparse-point fail-closed handling;
- limits for file count, aggregate bytes, individual size, and depth;
- deterministic first-party `REPOSITORY_SNAPSHOT_V1` inventory;
- Rust, Node, Python, and Go manifest/lockfile recognition and deterministic routing;
- documented exclusions for `.git`, `node_modules`, `target`, `.local`, `dist`, `build`, `coverage`, `tools/.staging`, and payload directories;
- bounded Gitleaks, OSV-Scanner, and Trivy parsers accepting an authorized target only;
- `SECRET_FINDING_V1`, `VULNERABILITY_FINDING_V1`, and `MISCONFIG_FINDING_V1` fingerprints;
- secret omission, redacted preview, one-way digest, path containment, and deduplication;
- transactional Level 0 → Level 1 SQLite snapshot migration with integrity hashes;
- secret-safe Executive, Technical, Developer JSON and HTML reports;
- restricted IPC for authorization, inspection, confirmed scan creation, and inventory retrieval;
- repository preview/confirmation UI with explicit incomplete-coverage warning.

## Synthetically validated

`tests/fixtures/synthetic-repository-a` contains harmless manifests, one fake credential, one unsafe configuration, one safe file, and an excluded `node_modules` payload. Typed E2E validates authorization, preview, explicit confirmation, one secret, one vulnerable dependency, one misconfiguration, one unavailable operational check, persistence, and redacted reporting. No malware, external repository, network provider, or real credential is used.

## Real-target capable

The product can authorize and inventory a repository explicitly selected by the user, enforce limits/exclusions, and persist sanitized inventory. No automatic repository discovery exists. This capability was not run against a real user repository.

## Network-isolation capability spike

| Option | Admin | Persistent mutation | Guaranteed deny for arbitrary CLI | Windows 10 | Decision |
|---|---:|---:|---:|---:|---|
| AppContainer | commonly | possible | only with correctly provisioned profile/token | yes | not implemented; profile mutation prohibited |
| Restricted token | no | no | no | yes | insufficient |
| Low integrity | no | no | no | yes | insufficient |
| Windows Sandbox | yes/feature | yes | separate VM policy | Pro/Enterprise | prohibited |
| WFP | yes/driver or service | yes | yes when correctly enforced | yes | prohibited/outside dependencies |
| Windows Firewall rule | yes | yes until cleanup | yes when binding succeeds | yes | prohibited |
| Hyper-V isolation | yes/feature | yes | yes with VM policy | Pro | prohibited |

Result: `NETWORK_ISOLATION = UNAVAILABLE_WITH_CURRENT_POLICY`. Job Objects, restricted tokens, and low-integrity tokens are not network denial. No host mutation was performed.

## Policy-blocked

- real Gitleaks, Trivy, and OSV-Scanner process execution;
- Trivy DB acquisition/freshness and OSV offline-data provisioning;
- scans of real user repositories.

Unavailable checks lower coverage and force an inconclusive/partial result. The product never claims high-confidence clean from incomplete coverage.

## Upstream-blocked

Tauri remains pinned at `2.11.5`; the advisory gate still waits for an official release. No exception, override, update, patch, or git dependency was introduced.

## Deferred

- full Git-compatible `.gitignore` behavior (V1 deliberately uses built-in exclusions);
- persistent authorization across restart;
- separately authorized, verified network-denial boundary;
- live engines, providers, remediation, packaging, signing, and release.

`LEVEL 1 IMPLEMENTATION = COMPLETE` does not mean `LEVEL 1 PRODUCTION SCANNING READY`; that claim remains prohibited while real engine execution is policy-blocked.

## Final validation — 2026-09-02

- Rust workspace: 159 passed, 0 failed, 2 deliberately ignored native credential tests;
- Clippy `-D warnings`: pass;
- rustfmt check: pass;
- frontend: typecheck pass, lint pass, 38 tests pass, production build pass;
- Cargo deny: five known upstream `unic-*` advisories, zero new advisories; licenses, sources, and bans pass;
- visual QA: 1366×768, 1920×1080, and 2560×1440; no horizontal overflow, warning and repository authorization controls visible;
- exact full synthetic secret outside its authorized fixture: zero; persisted database/report/frontend payload occurrences: zero;
- production scans, downloads, packages, installers, deployments, pushes, and host changes: zero.
