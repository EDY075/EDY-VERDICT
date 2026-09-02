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
