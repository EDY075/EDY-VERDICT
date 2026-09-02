# 02 - TECHNICAL STACK AND OPTIONS

## Selected architecture baseline

| Concern | Selected | Alternatives retained | Re-evaluation trigger |
|---|---|---|---|
| Language/Core | C# / .NET 10 LTS | Rust; Python | Native parser/perf boundary proves .NET inadequate |
| UI | Avalonia 12.1.x Core | WinUI 3; Tauri | Cross-platform no longer matters or Avalonia blocker confirmed |
| Persistence | SQLite + EF Core | LiteDB; PostgreSQL | Multi-user/server edition becomes a real requirement |
| Local rules | YARA-X CLI adapter initially | Native Rust bridge; classic YARA | CLI startup/interop becomes measurable bottleneck |
| Secrets | Gitleaks CLI | Trivy secret scanner; custom rules | License/coverage/performance issue discovered |
| Dependency/IaC | Trivy + OSV-Scanner | Dependency-Check; custom parsers | Ecosystem-specific gap validated |
| Vulnerability intel | OSV + NVD + CISA KEV + EPSS | Vendor advisories | Missing/incorrect mapping requires vendor source |
| Reports | HTML + JSON; Playwright .NET for PDF | QuestPDF; Chromium system print | PDF runtime footprint unacceptable |
| Distribution | Self-contained Windows build; signing path separate | MSIX/Store | Store becomes chosen channel |

## Version policy as of 2026-09-01

- .NET 10 is LTS and was observed at patch 10.0.11 in Microsoft support data; support ends 2028-11-14.
- Avalonia 12.1 was released in July 2026; official GitHub releases show the 12.1.x line. Pin the newest validated 12.1.x patch during Level -1 rather than hardcoding `latest` in build automation.
- YARA-X official releases provide prebuilt Windows binaries. End users do not need Rust.
- OSV-Scanner provides official Windows binaries/WinGet installation.

## Why C#/.NET is preferred

- excellent Windows integration without making the domain layer Windows-only;
- strong async/networking/crypto support;
- mature testing/DI/serialization/database tooling;
- self-contained deployment option;
- clean path to CLI/API later;
- easier long-term maintenance than a multi-runtime Electron/Python stack;
- Avalonia permits cross-platform evolution while keeping a Windows-first product.

## Avalonia constraint

Use **Avalonia open-source Core/MIT components only** for the MVP. Do not introduce Avalonia Pro/premium components by accident. If a paid component is proposed later, it requires an explicit architecture/license decision.

## External engine packaging strategy - SELECTED

**MVP default: Engine Manager + verified acquisition.**

The EDY installer contains the EDY application and its normal NuGet/runtime dependencies. Third-party standalone CLI engines should be acquired by an `Engine Manager` from their official release locations, with pinned version metadata and integrity verification where upstream provides checksums/provenance.

Why this is preferred initially:

- reduces redistribution/legal mistakes;
- makes engine updates independent from EDY app releases;
- keeps the core installer smaller;
- lets an engine be optional/unavailable without breaking the product;
- provides a clear audit trail of engine version/source/hash.

Alternatives:

1. **Bundle engines** in a full/offline distribution after license audit.
2. **Require user-installed tools** - lower maintenance, worse UX; not preferred.

## Required project components

- `EDY.Verdict.Domain` - pure business entities/value objects.
- `EDY.Verdict.Application` - use cases/orchestration.
- `EDY.Verdict.Infrastructure` - database, filesystem, process execution, platform services.
- `EDY.Verdict.ProviderContracts` - stable provider interfaces and normalized responses.
- `EDY.Verdict.Providers.Local.*`
- `EDY.Verdict.Providers.Intel.*`
- `EDY.Verdict.Desktop` - Avalonia UI.
- `EDY.Verdict.Reporting`.
- `EDY.Verdict.Tests.Unit`.
- `EDY.Verdict.Tests.Integration`.
- `EDY.Verdict.Tests.Contracts`.
- `EDY.Verdict.Tests.E2E`.

## Runtime rules

- No Python runtime requirement.
- No Node.js runtime requirement.
- No Rust runtime/toolchain requirement for users.
- No Docker requirement for the desktop MVP.
- Do not shell out to PowerShell for operations that have a stable managed/.NET API unless PowerShell provides a meaningful reliability advantage.
- All external process execution uses a central safe process runner with timeout, cancellation, bounded output, explicit argument arrays and no shell interpolation.
