# Level 7 — product finalization and local RC

Level 7 finalizes all work independent of the Tauri upstream release: product identity, Windows 10 UX, deterministic pt-BR/en UI, accessibility/navigation, diagnostics/privacy/about surfaces, versioned reports/CLI, full native E2E, supply-chain evidence, documentation and a local unsigned NSIS candidate.

The native master test uses the actual Tauri desktop executable, WebView2, React, typed IPC and SQLite. It exercises bounded synthetic targets only, runs no real engine, performs no external request and restarts each of three isolated profiles. All matrix screens passed without horizontal clipping, unnamed controls, raw i18n keys or undefined rendering. Hostile URL and path classes fail closed.

Security acceptance preserves Isolation, CSP, IPC/origin/navigation policy, frontend shell/filesystem/clipboard denial, redaction, explicit coverage and non-mutating remediation. Cargo deny continues to fail only at the separately classified Tauri upstream gate; it is not waived.

`LEVEL 7 = COMPLETE` for the authorized local scope. Public release remains blocked by Tauri upstream, product-license selection and code signing. The local installer is unsigned, not executed, not committed and not distributed.
