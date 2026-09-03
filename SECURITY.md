# Security policy

Report suspected vulnerabilities privately to the project owner. Use a minimal synthetic reproducer; never attach real secrets, credentials, private files, malware samples or personal data.

The supported candidate is `1.0.0-rc.1` on Windows 10 Pro 22H2 x64 build 19045. Public releases are blocked until the Tauri upstream advisory, product licensing and code-signing gates close.

EDY VERDICT is local-first and fail-closed. It has no telemetry; file bytes are not uploaded; URL analysis is passive and SSRF-constrained; secrets are redacted; frontend shell, filesystem and clipboard capabilities are denied; automatic target mutation is absent. Real external engines remain unavailable under the current production execution policy. Missing checks reduce coverage and never imply a clean verdict.

Future BYOK values must be held by Windows Credential Manager and must not be persisted in SQLite, preferences, logs or diagnostic bundles.
