# Contributing

Work only in a dedicated project checkout. Preserve local-first, fail-closed and non-mutating production policies. Load the project environment in a fresh PowerShell and use the closed-action Rust wrapper. Do not change global Rustup, PATH, Windows, Defender or SMBIOS state.

Use exact lockfiles, no broad dependency updates, no real secrets and no real engine/provider scans in tests. New IPC commands require strict typed requests, origin validation, bounded output and security tests. New UI claims must map to the canonical capability matrix. Missing coverage remains visible.

Before a local commit run frontend checks, workspace tests, Clippy, formatting, secret scan and the appropriate native fixture. Generated build, data and cache directories stay ignored. Pushes, pull requests and public release operations need separate authorization.
