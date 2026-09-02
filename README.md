# EDY VERDICT — Level 0 synthetic validation workspace

The immutable Level -1C foundation now has a Level 0 implementation on the work branch:
typed orchestration, project-local SQLite persistence, deterministic correlation/reporting,
restricted Tauri IPC and a React UI for controlled synthetic validation. This is not a
production scanner. It cannot select or scan user files, directories, repositories, URLs or
installed applications, and it performs no live provider requests or engine downloads.
Windows 10 Pro 22H2 x64 remains fixed; Windows 11 migration is cancelled.

Read `docs/adr/0001-platform-stack.md` and `docs/architecture/foundation-contract.md`.
Use `scripts/Enter-Project.ps1` in a new PowerShell process before development commands.
Toolchains, caches, temporary files and build artifacts remain project-local.
Do not commit `.local`, `target`, `node_modules`, credentials or generated databases.
Never run Rust inventory or QA commands inside this repository with global or unset
`RUSTUP_HOME`/`CARGO_HOME`; `scripts/Assert-ProjectRustEnvironment.ps1` fails closed when it
detects that context. Global Rust inventory must run only from a verified neutral directory.

Current implementation result: **Level 0 COMPLETE WITH ACTIONS (synthetic scope)**.
Read `docs/LEVEL_0_REPORT.md` for the exact boundary. The independent release gate remains
**Level -1C FAIL / WAITING TAURI UPSTREAM** because five Windows transitive `unic-*`
advisories still block promotion.

Authorized foundation reproduction (PowerShell, from this directory):

```powershell
. ./scripts/Enter-Project.ps1
# Provision-Toolchains.ps1 is an explicit provisioning command, never a startup hook.
pnpm install --frozen-lockfile
pnpm build
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
pnpm typecheck
pnpm lint
pnpm test
cargo audit
cargo deny check
pnpm audit --audit-level=high
```

Pinned development auditors were built with `cargo install cargo-audit --version
0.22.2 --locked --root .local/audit-tools` and `cargo install cargo-deny --version
0.20.2 --locked --root .local/audit-tools`, always inside the project environment.
`Collect-Evidence.ps1` records gates without launching the application. Its
`-RunAuthorizedFakeCredentialTest` switch writes/deletes the documented fake target;
omit it unless that specific native test is authorized. Never use a real API key.

Both locks are tracked. No push, deploy, package or installer is authorized by Level 0.
