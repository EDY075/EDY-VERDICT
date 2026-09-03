# Threat model

Protected assets include user targets, credentials, redacted evidence, SQLite state, engine manifests/receipts, reports and verdict integrity. Untrusted inputs include paths, URLs/DNS, repositories, binaries, provider responses, engine output, installer input and WebView messages.

Trust boundaries are WebView to typed Rust IPC, authorized target to bounded reader, provider transport to validated parser/cache, engine payload to manifest/receipt gate, and local package to Windows installation.

- Traversal, UNC/device/reparse and target-swap: canonical fixed-drive policy, identity binding, revalidation and open handles.
- SSRF, redirects and DNS rebinding: public-address validation, pinned resolution, bounded redirects, TLS validation and passive methods.
- Secret leakage: value-free fingerprints, boundary redaction, bounded logs and hostile sentinels across DOM, IPC, reports and SQLite.
- WebView compromise: Isolation, CSP, local navigation/origin policy and denied shell/filesystem/clipboard frontend capabilities.
- False assurance: separate coverage, risk and confidence; unavailable checks cannot become a pass.
- Supply-chain substitution: exact locks, SBOM/notices, project-local verified tooling and manifest-bound engines.
- Unsafe remediation: production provides guidance and fresh verification only; apply and rollback are absent from the production graph.

Residual release risks are the pinned Tauri transitive advisories, unsigned local artifacts, absent product-license decision, untrusted SMBIOS and optional/disabled Defender state.
