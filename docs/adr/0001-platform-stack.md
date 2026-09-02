# ADR 0001 — Approved platform and stack replacement

Status: ACCEPTED by the user, 2026-09-01. Implementation gate remains separate.

The historical C# / .NET / Avalonia decision is SUPERSEDED, not deleted.
The original documentation remains unmodified in the intake documentation package
and is copied byte-for-byte to `docs/legacy/codex-pack-v0.1/` (19 files, hash checked).
The current user authorization takes precedence over its older platform/level gates.

WINDOWS_10_REQUIREMENT = FIXED (Pro 22H2 x64).
WINDOWS_11_MIGRATION = CANCELLED.
PRIMARY_STACK = Rust 1.98.0 + Tauri 2.11.5 + WebView2 Evergreen.
FRONTEND = React 19.2.8 + TypeScript 6.0.3 + Vite 8.2.2.
DEFENDER_PROVIDER = OPTIONAL / DISABLED_BY_USER.
SMBIOS_TRUST = USER_MODIFIED / UNTRUSTED.
MANDATORY_MONTHLY_COST = R$ 0.

Alternatives evaluated: Rust with native Slint; C# with supported Windows 10 UI
stacks; previous .NET 10/Avalonia; Svelte, Solid and framework-free Vite UI.
The approved choice retains a Rust-only domain and CLI, local SQLite, minimal IPC
and a maintainable client-only React presentation layer. Node is development-only.
Slint is the fallback, subject to a new license/packaging/accessibility review.

Risks: unsupported consumer Windows 10 lifecycle is accepted by the user, not
resolved by a UI toolkit. WebView2 updates on Windows 10 are promised at least
through October 2028, not indefinitely. Same-user malware can compromise secrets.
Future Windows 11/Linux support is an architectural option, not a tested promise.
Reassess before WebView2 support ends, on a critical unpatchable advisory, on loss
of required accessibility/performance, or if Rust/Tauri drops this target.

Sources: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-support-lifecycle
https://doc.rust-lang.org/stable/rustc/platform-support/windows-msvc.html
https://v2.tauri.app/security/capabilities/

No real engines/providers, scanner, remediation, installer or Level 0 is authorized.
NSIS 3.12 acquisition review is separate and cannot block a no-bundle smoke build.
