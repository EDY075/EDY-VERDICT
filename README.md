# EDY VERDICT

EDY VERDICT is a local-first Windows security workbench for repository, file, installed-application and passive URL analysis. Version `1.0.0-rc.1` targets Windows 10 Pro 22H2 x64 (build 19045) and uses Rust, Tauri 2, React and SQLite.

The application keeps unavailable coverage visible. A partial scan is never presented as clean, real engine execution remains policy-blocked, automatic remediation is absent from the production graph, and telemetry is disabled. Cloud/provider features are optional and require explicit user action.

## Current release boundary

This repository contains a locally testable unsigned release candidate. It is not approved for public distribution: Tauri `2.11.5` remains pinned while the upstream dependency gate waits for an official release, product code-signing is not configured, and the rights holder has not selected a root product license. No installer produced from this tree should be shared or executed as a release.

## Develop and validate

Open a fresh PowerShell in this directory and load `scripts/Enter-Project.ps1`. It binds Rust, Cargo, Node, pnpm, caches, temporary files and build output to the project. All Rust operations must use `scripts/Invoke-ProjectRust.ps1`; direct Rust tooling is intentionally rejected by the repository gate.

Typical validation consists of frontend type checking, linting, unit tests and build, followed by the wrapper actions `WorkspaceTest`, `WorkspaceClippy` and `FmtCheck`. Native E2E tests are bounded debug-only fixtures; they do not enable production engine execution. See `docs/release-checklist.md` for the complete candidate process.

## Documentation

Security, privacy, threat model, support, contribution and change history live in the corresponding root Markdown files. `docs/LEVEL_7_REPORT.md` records the exact Level 7 boundary; `THIRD_PARTY_NOTICES.md` and `docs/security/generated/sbom.cdx.json` provide dependency evidence.

Windows 11 migration is cancelled by project decision. Defender is optional and may remain disabled. SMBIOS data is treated as user-modified and untrusted.
