# 10 - ROADMAP AND LEVEL GATES

## Level -1 - Technical Readiness

Stack validation, machine prerequisites, licenses, engine acquisition, keys, provider policies, signing/distribution plan, tool manifest, secret storage. **No feature implementation.**

## Level 0 - Product Contract & Architecture Freeze

Domain model, threat model, ADRs, repo skeleton, target/provider contracts, database model, UX information architecture, test architecture.

## Level 1 - Core Skeleton / Local Truth

Application launches; SQLite migrations; target intake; scan session lifecycle; provider status model; audit/logging foundation; no fake production data.

## Level 2 - Repository Security MVP

Local repositories/directories: Gitleaks + Trivy + OSV-Scanner; normalized findings; synthetic fixtures; Git-safe path handling.

## Level 3 - File Verification MVP

Hashing + file metadata + Authenticode + Defender capability + YARA-X; evidence correlation; no upload.

## Level 4 - Installed Software & Vulnerability Intelligence

Inventory strategy, package identity confidence, OSV/NVD/CISA KEV/EPSS correlation, fix availability where reliable.

## Level 5 - Passive Web Verification

DNS/TLS/redirect/header checks plus optional community reputation providers; strict request limits; no intrusive scanning.

## Level 6 - Finding Correlation & Case Lifecycle

Deduplication, evidence graph, confidence/coverage, cases/timeline, disagreement handling.

## Level 7 - Remediation & Verification

Manual plans first; safe automated actions only where narrowly scoped; before/after evidence and rescans.

## Level 8 - Reports

Executive + Technical + Developer Fix; HTML/JSON; PDF after HTML is stable; redaction/provenance.

## Level 9 - Evidence Workbench UX Polish

Keyboard flow, accessibility, empty/error/provider states, compare mode, first-run Engine Manager experience.

## Level 10 - CLI and CI Security Gate

`edy-verdict scan <target>` using same Application layer. GitHub CI integration for our own EDY projects; no dependency on gitleaks-action licensing.

## Level 11 - Hardening & Release Engineering

Supply-chain pinning, SAST/dependency audits, installer/updater decision, signing path, clean-machine tests, performance budgets.

## Level 12 - Public Release

Documentation, third-party notices, GitHub Release, checksums, release notes, safe synthetic demo, portfolio materials.

## Rule at every level

`4 prompts -> scored winner -> bounded execution -> specialist reviews -> JR integration -> full gate -> PASS/FAIL`.
