# Controlled Rust execution

Before every Rust action, set process-local `RUSTUP_HOME` and `CARGO_HOME` to this
project's `.local/rustup` and `.local/cargo` and use `scripts/Invoke-ProjectRust.ps1`.
Its closed action list is the only project Rust executable resolver. Do not invoke
Rust binaries directly, including auditors, even by absolute project-local path.
The environment and static direct-command gates must pass first. For Node metadata
consumers use `scripts/project-rust.mjs`, not a child-process call to a Rust binary.

Use `. ./scripts/Enter-Project.ps1` for the existing process-local MSVC/Node setup;
then call the wrapper. Never run global inventory within this repository or nested
directories. `scripts/Invoke-GlobalRustInventory.ps1` is read-only and requires a
neutral actual working directory with explicit inventory intent.

No automatic global provisioning, default changes, PATH/profile/shim interception,
cache cleanup or global remediation is permitted. A manual command that bypasses
the wrappers remains an operational error; the static gate does not intercept it.
