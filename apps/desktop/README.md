# Desktop Level 0 host

This host exposes only the controlled Level 0 synthetic workflow. The React UI reads
foundation/engine status, starts the enumerated `synthetic-target-a` fixture, polls progress,
cancels an active synthetic run, lists scans/findings and renders deterministic reports. It
does not accept an arbitrary path, URL, command, query or provider request.

Ten purpose-specific IPC commands are generated into the explicit `AppManifest` and local
`main` capability: `get_foundation_status`, `get_engine_status`, `create_synthetic_scan`,
`get_scan`, `list_scans`, `get_scan_progress`, `cancel_scan`, `list_findings`, `get_finding`
and `generate_report`. The dependency-free Isolation hook validates exact payload shapes;
native code independently validates window label, origin, typed IDs, enum values and bounds.
There are no generic shell, fs, SQL, HTTP, store or updater plugins.

Content is bundled in debug and release; there is no dev server URL. CSP permits
only local resources and the Tauri IPC endpoint. Do not add `frame-src` or
`child-src` manually: Tauri 2.11.5 appends its per-build Isolation origin to
`default-src`, and the frame directives inherit that narrowly scoped fallback.
The effective response therefore contains that local origin as well as the
configured `'none'`; this is required for the sandboxed frame, not remote access.
That generated policy still needs a packaged smoke gate; static config tests alone
do not prove the running browser policy. Devtools, new windows, external navigation,
downloads, clipboard access, extensions and autofill are disabled.

The native bootstrap opens `.local/data/foundation.sqlite3`, verifies infrastructure schema
version 1, then opens `.local/data/level0.sqlite3` for Level 0 snapshots and reconciliation.
Snapshots use SQLite transactions, optimistic revisions, size limits and a same-database
SHA-256 corruption check. That digest is not an authenticity boundary against a same-user
attacker. WebView2 data is under project `.local/webview2`.
The project root is located from executable ancestors, with a debug-only compile
manifest fallback. A release moved outside the workspace intentionally fails.
Link/reparse checks on local paths are defense in depth, not a same-user malware
boundary. WebView2's own runtime/update behavior is not disabled or a project
network activity guarantee.

After JR provisions approved dependencies and root lockfiles, run from the project
environment: `pnpm --dir apps/desktop typecheck`, `lint`, `test`, `build` and the
JR-controlled Rust/Tauri build gate. The required order is `pnpm build` before Rust/Tauri
tests because `frontendDist` is generated. No-bundle builds require no NSIS installer.
Windows still requires an icon resource. `build.rs` generates a plain 16x16 ICO
under `src-tauri/.generated/`, without external image files or dependencies.

`edy-desktop.exe --foundation-smoke` enables only a technical 15-second watchdog.
Receipt of the validated IPC call writes a fixed `FOUNDATION_IPC_RECEIVED` marker
and schedules a clean exit. This proves the renderer invoked Rust through the
bridge, NOT that the final rendered labels were visually inspected. It does not
accept an exit code, path, script, provider, engine or command from the frontend.
An ordinary launch does not auto-exit. The Level 0 UI is not evidence of production scanning
readiness. Real engine execution remains policy-blocked until deny-network enforcement and
approved offline data are available, and Tauri promotion remains blocked upstream.
