# EDY VERDICT — Level -1C foundation

Technical infrastructure only. No scanner, verdict algorithm, live provider, telemetry,
engine download, installer or product UI is implemented or authorized by this baseline.
Windows 10 Pro 22H2 x64 is fixed; Windows 11 migration is cancelled.

Read `docs/adr/0001-platform-stack.md` and `docs/architecture/foundation-contract.md`.
Use `scripts/Enter-Project.ps1` in a new PowerShell process before development commands.
Toolchains, caches, temporary files and build artifacts remain project-local.
Do not commit `.local`, `target`, `node_modules`, credentials or generated databases.

Level 0 requires separate user authorization even after all foundation gates pass.

Current result: **Level -1C FAIL**. Read `docs/LEVEL_MINUS_1C_REPORT.md` before
running any native desktop build. Five Windows transitive advisories block promotion.

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

Both locks are tracked in the local Git index. There is no remote or approval commit.
