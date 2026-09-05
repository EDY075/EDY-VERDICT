# Corrected provisioning side effect

On 2026-09-01 a final version check invoked `rustc --version` from the project
without first setting project-local RUSTUP_HOME/CARGO_HOME. rustup honored the
project pin and automatically installed a duplicate Rust 1.98.0 in the user-global
rustup directory. This was an unintended write outside the project's D: root.
The existing default stable toolchain was not replaced or changed.

JR disclosed the incident, verified the duplicate's exact path and creation time
(21:31 local), verified the separate approved D: installation existed, and removed
only the newly created global `1.98.0-x86_64-pc-windows-msvc` via rustup uninstall.
No other toolchain, old C: project, Windows setting or environment variable was removed.
The removed duplicate is recoverable by an explicitly authorized reinstall; the
approved project-local copy remains available.

Post-correction verification was run from the workspace parent, outside any project
toolchain override: only global stable remains, rustc 1.97.1; Node remains 24.17.0.
All project commands must first dot-source scripts/Enter-Project.ps1. No claim is
made that the transient side effect never happened; the report records remediation.

## Recurrence during Level -1D.1

On 2026-09-02 the first contract compile again invoked global `cargo` before
dot-sourcing `scripts/Enter-Project.ps1`. Rustup installed the pinned 1.98.0 toolchain
under the user-global C: rustup directory. JR detected this immediately, disclosed it
during the run, verified creation timestamps and the separate approved D: copy, and
removed only the newly created global 1.98.0 toolchain. Verification from `C:\Windows`
confirmed that only the pre-existing global stable toolchain remains.

Subsequent commands all loaded the project environment and used D:. The initial cargo
operation may also have populated entries in the pre-existing global Cargo registry
cache; those shared cache entries were not deleted because their prior ownership could
not be established safely. No engine, Windows setting or global environment variable
was installed or changed.

## Recurrence during the Level 0 final gate

On 2026-09-02 a global inventory command, `rustup toolchain list`, was invoked with
`<workspace>\EDY-VERDICT` as its working directory while process-local
`RUSTUP_HOME` and `CARGO_HOME` were unset. The global Rustup shim honored the repository
`rust-toolchain.toml` and automatically provisioned the pinned 1.98.0 toolchain under
`%USERPROFILE%\.rustup`. The project-local toolchain was not changed.

The user explicitly authorized one official uninstall from the verified neutral `C:\`
directory. Post-remediation checks confirmed that only global `stable` remained active and
default, settings/PATH hashes were unchanged, and the 168-file project-local manifest was
byte-identical before and after removal.

Rust inventory and QA commands must never execute inside the repository with a global or
unset Rustup/Cargo context. `scripts/Assert-ProjectRustEnvironment.ps1` enforces the approved
project-local homes for repository execution and permits global inventory only from a neutral
directory. `scripts/Enter-Project.ps1` invokes this gate after establishing the local context.

## Second recurrence — Level 1 final validation

The exact triggering command was `rustup toolchain list`, invoked by the final-validation
PowerShell command block after it removed `RUSTUP_HOME` and `CARGO_HOME`. Its parent was the
Codex `exec_command` PowerShell process, its working directory was the repository root, and
the environment source therefore fell back to the user-global Rustup defaults. The repository
`rust-toolchain.toml` override caused Rustup to provision `1.98.0-x86_64-pc-windows-msvc`
globally. The extra toolchain was removed with the official uninstall operation and `stable`
remained the default.

The permanent control is now executable rather than documentary: all routine project Rust QA
uses `scripts/Invoke-ProjectRust.ps1`, which accepts only a closed action list and resolves
project-local binaries by absolute path. Global inventory uses the separate
`scripts/Invoke-GlobalRustInventory.ps1`, which refuses repository or nested-repository working
directories and requires an explicit global-inventory flag with no inherited Rust homes.

## Level 6 recurrence and explicitly authorized cleanup — 2026-09-03

`INCIDENT ROOT CAUSE = DIRECT_UNWRAPPED_CARGO_DENY_EXECUTION`.
The agent invoked the project-local auditor directly from the repository without the
approved wrapper or explicit project Rust homes. Cargo metadata resolution could therefore
reach the global Rustup shim and honor the repository pin. The command record and the
extra toolchain creation time (00:46:04, America/Sao_Paulo) establish this operational cause;
the failure was not deliberately reproduced after cleanup.

The user explicitly authorized only the official removal of the global
`1.98.0-x86_64-pc-windows-msvc`. It was uninstalled from a neutral workspace-parent
working directory. No manual filesystem cleanup, update, default change, profile edit,
registry write or cache removal was performed. Before removal, 34 pending Level 6 files
were recorded with path/size/SHA-256 and were verified unchanged immediately afterwards.

Before/after content manifests matched for 65,674 files in global `stable` and 17,151 files
in the Cargo registry. Cargo git-cache absence and empty Rustup download cache were preserved.
The global default remained `stable-x86_64-pc-windows-msvc`, default host remained
`x86_64-pc-windows-msvc`, user/machine PATH digests matched, and settings SHA-256 remained
`AF11A5540001371324994ABAA9EA1E69D50FED1ACB1A87E4ABEF179E8816058F`.
Evidence is project-local under `.local/level6-closure/` and is not versioned.

The execution path now includes a read-only static regression gate before wrapper actions.
Architecture metadata and supply-chain generation use a closed-action Node-to-PowerShell
bridge. Provisioning delegates Rust execution to the wrapper and remains separately gated;
it was not run in this cleanup. The unwrapped desktop Tauri CLI shortcut was removed.
The wrapper pins child RUSTC/RUSTDOC, local Rust homes, toolchain and process-only PATH;
it does not modify the global shell or Rustup settings.

The new tests contain only inert command strings and detect direct rustup, cargo,
cargo-deny, rustc, rustfmt and clippy calls across PowerShell, batch/shell, package scripts,
Node E2E/audit tooling and runnable documentation snippets. Exceptions name the two
execution-owner wrappers and the detector/test files explicitly; there is no wildcard.
This is a static review control, not a security boundary against obfuscated hostile code.
Deliberate/manual calls outside these wrappers remain an operational responsibility.

Historical incident semantics are retained: incident occurred, was remediated, root cause
was identified, and prevention was improved. Completion of Level 6 still requires its
independent functional and consolidated security acceptance gates.
