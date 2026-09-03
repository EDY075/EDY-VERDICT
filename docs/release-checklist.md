# Release-candidate checklist

- [x] Version `1.0.0-rc.1` coherent in Cargo, frontend, Tauri, CLI and reports.
- [x] Windows 10 Pro 22H2 x64 build 19045 documented as the minimum.
- [x] Frontend and Rust quality gates pass through project-local tooling.
- [x] Native Level 7 matrix passes at 1366x768, 1920x1080 and 2560x1440.
- [x] SQLite schema 8 integrity and restart persistence pass.
- [x] Secret scan, npm audit and Cargo audit pass; SBOM/notices regenerated.
- [x] Unsigned local NSIS package built without execution or distribution.
- [ ] Tauri upstream gate closed by a verified official release.
- [x] Root MIT License explicitly selected by rights holder Edmilson Gomes.
- [ ] Product signing identity, timestamping and verification configured.
- [ ] Clean-machine install, upgrade and uninstall acceptance after those gates close.
- [x] Explicit authorization for public source publication and RC pre-release.

Unchecked items block public installer distribution and a stable `v1.0.0`; they do not block the authorized source-only RC pre-release.
