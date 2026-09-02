# Foundation security baseline

No scanner, providers, production verdict, telemetry, API key, installer or engine
download exists. The only native credential target used is the user-authorized fake
`EDY-VERDICT-LEVEL1C-TEST`; test values are not logged. Tests reject a preexisting
entry and clean on ordinary failure/unwind; abrupt OS/process termination cannot
be covered by a Rust destructor and must be checked before another test.

Rust unsafe is restricted to native adapters; edy-core forbids it. Process fixtures
are built in this project and hash-checked, never taken from user targets. Suspended
creation, inherited-handle allowlist, Job assignment before resume, empty environment,
closed stdin, bounded output, cancellation and Job termination are implemented.
The Job Object is not filesystem or network isolation. Only benign fixtures tested.

Secrets: Windows Credential Manager local persistence is per-user. No DPAPI fallback,
SQLite value, frontend getter or live key entry UI. Same-user malware/admin remains
a threat. Storage schema contains only migrations and synthetic infrastructure events.
No production scanning/storage concurrency service is implemented.

Tauri: sole foundation_status command, AppManifest allowlist, exact main capability,
local assets, Isolation hook, no generic plugins, no remote capability, no updater.
Configuration and parser tests are not proof of runtime CSP enforcement. Native
desktop compilation and WebView execution are blocked pending dependency review.

Package installs use exact approved direct pins, both lockfiles, frozen pnpm install,
ignoreScripts=true, ignorePnpmfile=true, verifyDepsBeforeRun=error, integrity checking.
pnpm 11.25.0 has a reproducible undefined currentPnpmfiles issue with ignorePnpmfile;
explicit `pnpmfile: []` resolves it without allowing hooks or relaxing the gate.
State path is passed using a process-local CLI option: project YAML cannot set it.

Cargo registry archive checksums verified for the Windows graph. Audit tools are
development-only, installed from pinned crates.io releases under .local/audit-tools.
Rust build scripts/compiler plugins are executable dependencies, not sandboxed;
tooling installation is distinct from promotion of the application baseline.

`cargo deny` never ignores advisories. Five Windows unic-* unmaintained advisories
block promotion; full lock also retains Linux GTK/glib warnings without claiming
those packages are Windows runtime dependencies. Reassess upstream, do not silently
patch Tauri or add exceptions. R$0 mandatory monthly services; release signing and
distribution costs are out of this gate and remain separate authorization.

Preliminary notices/SBOM inventory is not release license clearance: missing root
license texts and platform/build-tool scope are listed in generated artifacts.
MPL-2.0 components require notice/source review for any later distribution.
The workspace secret audit is a local heuristic, not Gitleaks. Gitleaks and all other
approved engines remain undownloaded as explicitly instructed.
