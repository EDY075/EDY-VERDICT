# EDY VERDICT - START HERE

**Document set:** Codex Engineering Pack v0.1
**Status:** PRE-CODE / LEVEL -1
**Research snapshot:** 2026-09-01
**Working name:** EDY VERDICT
**Product description:** Security Verification, Exposure & Remediation Workbench.

## 1. Instruction to Codex/JR Orchestrator

Do **not** start feature implementation merely because this pack exists. The first execution is **Level -1: Technical Readiness**. Its purpose is to verify the development machine, licenses, exact dependency versions, external-service terms, acquisition methods, secret storage, update strategy and release prerequisites.

The project follows a mandatory **4-prompt competition** at every implementation level:

1. Generate or receive Prompt A, B, C and D for the same level.
2. Score all four against the project's fixed rubric.
3. Choose one winner or explicitly construct a justified hybrid only when the scoring reveals a genuine gap.
4. Execute only the winning prompt.
5. Run tests, security review and integration review.
6. Mark the level PASS/FAIL with evidence.
7. Do not advance on appearance or partial success.

## 2. Product truth rules

- Production behavior must be real. No silent mock fallback.
- `LOCAL ONLY`, `HASH LOOKUP`, and `CONNECTED` privacy modes are distinct.
- A provider being unavailable must produce `Unavailable`, `Not configured`, `Rate limited`, `Permission denied`, or equivalent truthful state.
- A clean scan means **No known indicators found under the checks performed**, never “100% safe”.
- No file upload to third parties without explicit user action and provider-specific disclosure.
- MalwareBazaar upload is **out of scope** for normal user scanning.
- Active web exploitation is out of scope. Public URL analysis is passive/non-invasive by default; any future active assessment requires explicit authorization controls.
- Remediation must be reviewable, auditable, reversible where feasible, and followed by verification/rescan.
- External CLI engines may be used behind adapters, but the EDY domain model must not depend on their output schema directly.
- No secret, token or API key is committed to Git, written to reports, or logged.

## 3. Selected baseline

- Core: **C# / .NET 10 LTS**.
- Desktop UI: **Avalonia 12.1.x**, pin exact patch during Level -1 after validation.
- Persistence: **SQLite + EF Core**.
- Local/security engines: **YARA-X**, Windows Authenticode, Microsoft Defender when available, **Gitleaks CLI**, **Trivy**, **OSV-Scanner**.
- Online enrichment: OSV, CISA KEV, FIRST EPSS, NVD; optional URLhaus/MalwareBazaar; VirusTotal strictly optional and policy-gated.
- Reports: HTML/JSON first; PDF through Playwright .NET after the reporting level.
- Runtime dependencies: Python, Node.js and Rust are **not** required for end users in the MVP.

## 4. Read these files in order

1. `01_PRODUCT_VISION.md`
2. `02_TECHNICAL_STACK.md`
3. `03_PROVIDERS_KEYS_COSTS.md`
4. `04_ARCHITECTURE.md`
5. `05_SECURITY_PRIVACY.md`
6. `06_SCAN_FINDING_MODEL.md`
7. `07_UX_PRODUCT_DESIGN.md`
8. `08_REPORTING_REMEDIATION.md`
9. `09_SUBAGENTS_ORCHESTRATION.md`
10. `10_ROADMAP_GATES.md`
11. `11_TEST_STRATEGY.md`
12. `12_RELEASE_DISTRIBUTION.md`
13. `13_LEVEL_MINUS_1_PROMPT_ROUND.md`
14. `14_CODEX_MASTER_HANDOFF.md`
15. `SOURCES.md`

## 5. Definition of Level -1 done

Level -1 is complete only when Codex can show evidence that:

- exact versions are pinned or intentionally ranged;
- tool acquisition locations are official and integrity-verifiable;
- redistribution vs first-run acquisition decisions are documented per engine;
- all license notices/obligations are understood and recorded;
- required local prerequisites are installed or a reproducible installation plan exists;
- required external accounts/keys are listed with safe placeholders;
- provider contract tests can run without real secrets;
- real secrets are stored outside the repository;
- offline behavior works without cloud keys;
- provider failures are fail-closed;
- Windows distribution/signing path and SmartScreen expectations are documented;
- no production feature code has been created prematurely.


---

# 01 - PRODUCT VISION

## Mission

EDY VERDICT is a local-first security verification product that converts fragmented security checks into an explainable workflow:

`TARGET -> DETECT -> EVIDENCE -> CORRELATE -> FINDING -> PRIORITIZE -> REMEDIATE -> VERIFY -> REPORT`

It is not an antivirus replacement and not an offensive exploitation framework. It is an evidence-driven verification and remediation workbench.

## Primary users

- Home/power users who want a trustworthy explanation of a file, program or URL.
- IT support technicians validating software and endpoint risk.
- Junior security analysts performing triage and evidence collection.
- Developers checking repositories before publication.
- Students/professors reviewing security engineering work with reproducible evidence.

## Initial target types

1. **Repository / source directory**
   - leaked secrets;
   - vulnerable dependencies;
   - IaC/configuration problems;
   - risky Git hygiene;
   - license/SBOM signals where supported.

2. **File / installer / executable**
   - cryptographic hashes;
   - real file type and metadata;
   - Authenticode signature/publisher;
   - YARA-X matches;
   - Microsoft Defender result when available;
   - hash reputation through optional providers;
   - PE metadata enrichment where justified later.

3. **Installed application**
   - inventory/version/publisher;
   - update availability when reliably determinable;
   - package/CPE/PURL mapping with confidence;
   - OSV/NVD vulnerability enrichment;
   - CISA KEV and EPSS prioritization.

4. **URL/domain**
   - DNS resolution;
   - TLS certificate/chain metadata;
   - redirects;
   - HTTP security headers;
   - cookie flags when observable without authentication;
   - reputation through optional threat-intel providers;
   - phishing/malware indicators based on evidence, not unsupported certainty.

## Core differentiation

The product is not “run 5 scanners and dump their output.” It owns a normalized **Finding/Evidence/Incident** model. Multiple providers may support the same finding. The UI explains why a verdict exists, how confident it is, what is unknown, what remediation is available, and whether the remediation was verified.

## Product modes

### LOCAL ONLY
No target-derived data is intentionally sent to threat-intelligence services. Local engines and cached/local databases are used.

### HASH LOOKUP
Only explicitly documented identifiers (for example SHA-256, CVE IDs, package coordinates) may be sent to configured providers. This is the recommended connected default for files.

### CONNECTED
Additional provider lookups may occur according to per-provider disclosure. File upload remains separately opt-in and is not enabled by entering this mode.

## Non-goals for MVP

- detonation/sandbox execution of malware;
- downloading live malware samples;
- automatic malware upload;
- active exploitation of websites or CVEs;
- arbitrary PowerShell/script execution from the UI;
- kernel driver development;
- EDR replacement;
- “AI says safe” decisions;
- mandatory cloud backend;
- organization/fleet management.

## Quality promise

A professor/recruiter should be able to inspect one finding and answer:

- What was checked?
- Which source produced the evidence?
- What exactly was observed?
- How was severity/prioritization derived?
- What uncertainty remains?
- What remediation was recommended/applied?
- Was the fix verified?
- Can the result be reproduced?

If the product cannot answer those questions, the feature is not complete.


---

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


---

# 03 - PROVIDERS, KEYS, COSTS AND PRE-REQUISITES

## A. Works without user API keys

| Capability/provider | Key | Cost to user | Role |
|---|---|---:|---|
| Local SHA-256/SHA-1/MD5 | none | 0 | File identity; SHA-256 is canonical |
| Authenticode/Windows certificate APIs | none | 0 | Signature/publisher evidence |
| Microsoft Defender (when present) | none | 0 | Local AV evidence |
| YARA-X | none | 0 | Local rule matching |
| Gitleaks CLI | none | 0 | Secret detection in repos/files |
| Trivy | none | 0 | Vulnerabilities/misconfig/secrets/licenses/SBOM |
| OSV-Scanner | none | 0 | Dependency vulnerability analysis |
| OSV API | none | 0 | Vulnerability enrichment; current API says no rate limit |
| CISA KEV JSON/CSV | none | 0 | Known exploited status |
| FIRST EPSS | none | 0 | Exploitation probability/percentile |
| DNS/TLS/HTTP checks | none | 0 | Passive web analysis |

## B. Free/community keys recommended

### NVD API key

**Placeholder:** `NVD_API_KEY`
**Required for MVP?** No.
**Recommended?** Yes.

Use NVD as enrichment, not the sole vulnerability database. The implementation must have throttling/backoff/cache and obey current NVD guidance/headers. Key is stored in the platform secret store, never `appsettings.json`.

### abuse.ch Auth-Key

**Placeholder:** `ABUSECH_AUTH_KEY`
Can be used with URLhaus and MalwareBazaar community APIs according to current service terms.

Community use is free under fair-use language, but commercial/for-profit usage may require an enhanced commercial subscription. Therefore abuse.ch providers are optional and policy-tagged.

### VirusTotal Community key - OPTIONAL / RESTRICTED

**Placeholder:** `VIRUSTOTAL_API_KEY`.

The public API currently documents 4 requests/minute and 500/day and explicitly forbids use in commercial products/services. Therefore:

- never make VirusTotal a required product dependency;
- keep it disabled unless the user configures it and accepts provider terms;
- label it `Community / Personal-Lab Only` in the provider UI;
- do not ship Edy's personal key;
- a future commercial product must use a licensed alternative/Premium arrangement or disable this provider.

## C. No-upload policy

Default file workflow:

`file -> local SHA-256 -> local engines -> hash/intel lookup`

Do not upload files to external services automatically. MalwareBazaar submission is not part of the user scan pipeline; their community documentation says submissions should be confirmed/vetted malware only.

## D. Key storage

Development:

- `.NET user-secrets` or process environment variables;
- CI: GitHub Actions encrypted secrets;
- never a checked-in `.env` containing real values.

Installed Windows app:

- Windows Credential Manager or DPAPI-backed secret store through an abstraction;
- store only provider credentials, not raw scan contents;
- expose `Remove key` and `Test connection` operations;
- redact keys from exception messages/logs.

Future non-Windows ports require another secret-store implementation behind the same interface.

## E. Engine Manager manifest

Create a signed/checked-in metadata file with fields such as:

```json
{
  "engineId": "yara-x",
  "version": "PINNED_AT_LEVEL_MINUS_1",
  "source": "official-release-url",
  "license": "BSD-3-Clause",
  "platform": "win-x64",
  "sha256": "UPSTREAM_OR_RELEASE_VERIFIED_VALUE",
  "acquisition": "download-on-demand"
}
```

Never write a fake checksum. If upstream does not publish one, record that limitation and use a stronger acquisition/provenance control where available.

## F. Accounts/checklist before feature work

- [ ] NVD key requested/available or explicit no-key mode accepted.
- [ ] abuse.ch account/Auth-Key available for optional URLhaus/MalwareBazaar tests.
- [ ] VirusTotal Community account/key only if personal-lab provider testing is desired.
- [ ] GitHub repository location decided before CI/release level.
- [ ] SignPath Foundation eligibility/application evaluated before public Windows release.
- [ ] No secret value added to this documentation pack.

## G. Expected mandatory monthly project cost

**MVP core: R$ 0/month.**

Potential future costs:

- code-signing path if free OSS signing is unavailable;
- Microsoft Artifact Signing (Microsoft currently describes paid pricing) if selected;
- commercial threat-intel subscriptions if the project becomes for-profit/enterprise;
- optional hosting/backend only if a later edition needs central services.


---

# 04 - ARCHITECTURE

## High-level flow

```text
Target
  -> Intake/Policy
  -> Scan Orchestrator
  -> Engine/Provider Runs
  -> Raw Provider Results (ephemeral)
  -> Normalization
  -> Evidence
  -> Finding Correlation/Deduplication
  -> Risk + Confidence + Priority
  -> Investigation/Incident
  -> Remediation Plan
  -> User-approved Action (when supported)
  -> Rescan/Verification
  -> Reports/Audit
```

## Architectural principles

1. **Ports and adapters:** external CLIs/APIs are adapters, not the domain.
2. **Normalized evidence first:** preserve raw provenance but map to EDY-owned evidence types.
3. **Deterministic where possible:** same local inputs + same engine/database versions should yield reproducible normalized results.
4. **Fail closed:** provider failure never means safe.
5. **Capability discovery:** UI only exposes operations supported by the current platform/provider state.
6. **Cancellation/timeouts:** every scan provider is cancellable and bounded.
7. **No shell concatenation:** arguments are structured.
8. **Version provenance:** reports record EDY version, engine versions, ruleset/database timestamps and provider states.

## Suggested solution structure

```text
src/
  EDY.Verdict.Domain/
  EDY.Verdict.Application/
  EDY.Verdict.ProviderContracts/
  EDY.Verdict.Infrastructure/
  EDY.Verdict.Reporting/
  EDY.Verdict.Desktop/
  Providers/
    Local.YaraX/
    Local.Defender/
    Local.Gitleaks/
    Local.Trivy/
    Local.OsvScanner/
    Intel.Osv/
    Intel.Nvd/
    Intel.CisaKev/
    Intel.Epss/
    Intel.Urlhaus/
    Intel.MalwareBazaar/
    Intel.VirusTotalCommunity/
tests/
  Unit/
  Integration/
  Contracts/
  E2E/
fixtures/
  safe/
  vulnerable-synthetic/
  repos-synthetic/
rules/
  yara/
docs/
  adr/
  threat-model/
  runbooks/
```

## Core domain entities

### Target
- `TargetId`
- `TargetType` (`Repository`, `File`, `InstalledApplication`, `Url`)
- canonical identifier/path/URI
- local/display-safe identifier
- authorization context for web target

### ScanSession
- start/end time
- requested profile/privacy mode
- selected providers
- provider versions
- outcome (`Completed`, `Partial`, `Failed`, `Cancelled`)
- warnings/errors

### ProviderRun
- provider id/version
- status
- started/completed
- cache state
- rate-limit metadata
- error category safe for display

### Evidence
- evidence type
- provider/source
- observation
- target component/location
- collected at
- confidence/source reliability metadata
- optional normalized identifiers (CVE, PURL, hash)
- raw evidence reference, not necessarily raw payload in reports

### Finding
- id/fingerprint
- category
- title
- severity
- confidence
- status
- affected target/component/location
- evidence links
- vulnerability/intel links
- remediation availability
- first seen / last seen / occurrences

### Incident/Case
- groups findings that require investigation/remediation
- lifecycle: `Open -> Investigating -> RemediationReady -> Remediating -> VerificationPending -> Resolved` plus controlled `Ignored/AcceptedRisk` states
- timeline events are append-only audit records

### RemediationPlan
- finding/case reference
- proposed steps
- impact/risk
- privilege requirement
- reversibility/backup plan
- automated/manual classification
- verification criteria

## Database

SQLite with EF Core migrations. Suggested tables:

- `Targets`
- `ScanSessions`
- `ProviderRuns`
- `Findings`
- `Evidence`
- `FindingEvidence`
- `Vulnerabilities`
- `Cases`
- `CaseTimeline`
- `RemediationPlans`
- `RemediationExecutions`
- `Reports`
- `EngineInstallations`
- `ProviderConfigurations` (non-secret metadata only)
- `Policies`
- `AuditEvents`

Secrets must not be stored in SQLite.

## Caching

- Cache threat-intel/vulnerability results with provider-specific TTL.
- Cache keys must include provider and query identity.
- Show cache age in evidence provenance where materially relevant.
- Support `Refresh evidence` to bypass stale cache subject to provider policy/rate limits.
- Do not cache uploaded file bodies to third-party provider queues because uploads are not an MVP workflow.

## Concurrency

The orchestrator may run independent engines in parallel, but impose per-provider semaphores and resource limits. Hashing should occur once and be shared. Repository scans should avoid launching duplicate heavyweight engines against the same target simultaneously without a performance reason.

## Future boundaries

CLI and API should reuse `Application` and provider contracts. Do not put scan logic in Avalonia ViewModels.


---

# 05 - SECURITY AND PRIVACY BASELINE

## Threat model highlights

The product processes untrusted paths, URLs, repository contents, binary files, command-line tool output and remote JSON. Treat all of them as attacker-controlled data.

### Primary risks

- command injection through filenames/paths;
- malicious output breaking parsers/UI/reports;
- symlink/path traversal during repository scans;
- decompression bombs if archive support is added;
- accidental secret leakage in logs/reports;
- external-provider data exfiltration;
- API-key theft;
- dependency/engine supply-chain compromise;
- TOCTOU when a scanned file changes between hash and remediation;
- malicious URLs causing SSRF-like behavior if later server mode exists;
- false confidence caused by provider outages;
- destructive remediation.

## Mandatory controls

- Process runner uses executable path + explicit argument collection; no `cmd /c` string interpolation.
- Reject/escape dangerous output in HTML reports.
- Never execute the target file as part of static analysis.
- Re-hash before any file remediation and verify identity still matches.
- Set timeouts and output size limits on CLI engines.
- Validate remote JSON schemas/required fields defensively.
- Provider TLS verification is never disabled.
- Never use `verify=false` patterns copied from provider samples.
- Use a central redaction service for paths/usernames/tokens/report export.
- Telemetry/crash upload is off by default in MVP unless a separate explicit privacy design is approved.
- Raw secret matches are masked; full secrets are never persisted in normal finding text.
- Reports identify uncertainty/provider failures.

## Web analysis boundary

MVP public URL analysis is passive/non-invasive:

- DNS resolution;
- TLS connection/certificate observation;
- normal HTTP(S) request flow;
- redirect observation with safe limits;
- response/security-header review;
- reputation lookups.

Do not brute force, exploit, fuzz, crawl aggressively, bypass authentication or perform intrusive vulnerability exploitation. Any future authorized active scanner must be a separate feature with explicit ownership/authorization gate and safety controls.

## Remediation rules

Automation is allowed only when:

- action is narrowly scoped;
- expected before/after state is known;
- privilege requirement is explicit;
- user can review the exact action;
- audit record is written;
- action has bounded timeout/result handling;
- post-action verification exists.

Never silently delete suspicious files. Quarantine/removal requires a dedicated later design.

## Supply-chain rules

- Pin third-party engine versions.
- Acquire from official locations only.
- Verify published checksums/signatures/provenance when available.
- Record engine hash/version in `EngineInstallation`.
- Keep third-party notices/licenses in release artifacts when redistribution occurs.
- Never auto-update an engine to an unreviewed major version.

## Safe testing

Use synthetic fixtures, known harmless vulnerable dependency fixtures, controlled fake secrets, EICAR where appropriate for Defender integration, and custom YARA fixtures. Do not place live malware in the normal repository/test suite.


---

# 06 - SCAN, EVIDENCE, FINDING AND VERDICT MODEL

## Finding categories

Initial taxonomy:

- `SecretExposure`
- `DependencyVulnerability`
- `KnownExploitedVulnerability`
- `MalwareIndicator`
- `SuspiciousFile`
- `SignatureProblem`
- `RepositoryMisconfiguration`
- `SupplyChainRisk`
- `WebTlsIssue`
- `WebHeaderIssue`
- `MaliciousUrlReputation`
- `PhishingIndicator`
- `OutdatedApplication`
- `ProviderCoverageGap`

Do not confuse a security hardening observation with confirmed vulnerability/malware.

## Severity

Use `Informational / Low / Medium / High / Critical`.

Severity is impact-oriented and must preserve authoritative values when available (for example CVSS context). Provider labels must not be blindly copied if semantics differ.

## Confidence

Separate from severity:

- Low
- Medium
- High

Internally a normalized confidence score may be used, but the UI must explain why confidence exists. Examples:

- Valid signed publisher + no local detections does not prove safety.
- Multiple independent high-quality signals increase confidence.
- A single heuristic YARA rule may produce Suspicious/Medium or Low confidence depending on rule metadata.
- An exact known-malware hash from a reputable source can support high-confidence malicious classification.

## Vulnerability prioritization

Keep these signals separate and visible:

- CVSS/severity;
- affected-version confidence;
- CISA KEV known-exploited flag;
- FIRST EPSS probability/percentile;
- installed/exposed status;
- fix availability.

Do not create an opaque “AI score.” If an EDY Priority score is introduced, document its formula and components and make it reproducible.

## File verdict vocabulary

Allowed examples:

- `Malicious - High confidence`
- `Suspicious - Medium confidence`
- `Needs review`
- `No known indicators found`
- `Insufficient coverage`

Disallowed:

- `100% safe`
- `virus-free guaranteed`
- claiming malware solely because an executable is unsigned.

## Deduplication

A finding fingerprint should use stable normalized fields appropriate to category, e.g.:

- secret detector + repository-relative path + secret fingerprint (not secret value);
- CVE + package/PURL + installed version + target;
- file SHA-256 + YARA rule id;
- URL canonical origin + finding type + evidence attribute.

Repeated observations update `lastSeen`/occurrence metadata instead of flooding the user.

## Provider disagreement

Display disagreement. Example:

```text
Microsoft Defender: no detection
YARA-X: suspicious rule match
MalwareBazaar hash: unknown
VirusTotal Community: not configured
Verdict: Suspicious
Confidence: Medium
Reason: one local static indicator with incomplete reputation coverage
```

This is a feature, not an error.


---

# 07 - UX AND PRODUCT DESIGN

## Visual direction: Evidence Workbench

Do not copy EDY's previous “dark dashboard + neon cards” pattern and do not imitate GitGuardian's visual identity.

The product should feel like an investigation desk rather than a KPI dashboard.

### Primary composition

```text
┌──────────────────────────────────────────────────────────────────┐
│ EDY VERDICT   Target: setup.exe   Mode: HASH LOOKUP   Scan 0241 │
├───────────────┬─────────────────────────────────┬────────────────┤
│ SIGNAL SPINE  │        EVIDENCE CANVAS          │ CASE / ACTION  │
│               │                                 │ DRAWER          │
│ File identity │ Verdict + explanation           │                │
│ Signature     │ Evidence timeline               │ Remediation    │
│ Local engines │ Finding relationships           │ Verification   │
│ Intel         │ Unknown/coverage states         │ Report         │
│ Vulns         │                                 │                │
├───────────────┴─────────────────────────────────┴────────────────┤
│ Command/search dock • Rescan • Compare • Export • Provider state│
└──────────────────────────────────────────────────────────────────┘
```

## Signature elements

- **Signal Spine:** compact vertical list of scan stages/providers with truthful states.
- **Evidence Canvas:** central investigation surface, not a grid of unrelated cards.
- **Case Drawer:** finding lifecycle, remediation and audit context.
- **Verdict Strip:** persistent but restrained severity/confidence/coverage summary.
- **Compare mode:** before/after remediation.

## Required UI states

Every provider/component must support:

- queued;
- running;
- completed;
- completed with findings;
- not configured;
- unavailable;
- unsupported platform;
- rate limited;
- timed out;
- failed;
- cancelled.

Never use a green success indicator for “provider did not run.”

## Accessibility/usability

- keyboard navigation;
- sufficient contrast;
- no critical meaning carried by color alone;
- scalable type;
- selectable/copyable technical evidence;
- friendly executive explanation without hiding technical detail;
- explicit privacy mode shown during every connected scan.

## First-run experience

1. Explain local-first model.
2. Show available built-in/platform capabilities.
3. Offer Engine Manager setup.
4. Providers requiring keys are optional.
5. Do not block first use on account creation.
6. Offer a synthetic demo target separately from real scans, clearly labeled.


---

# 08 - REPORTING AND REMEDIATION

## Three reports

### Executive / non-technical

Answers:

- What was analyzed?
- Overall result and uncertainty.
- What needs attention first?
- Why does it matter in plain language?
- What should the user do next?
- What was successfully fixed/verified?

No raw secrets, noisy stack traces or unneeded machine identifiers.

### Technical

Contains:

- scan identifiers/timestamps;
- target fingerprint;
- privacy mode;
- EDY/engine/provider versions;
- findings with IDs, severity, confidence;
- normalized evidence;
- CVE/CVSS/KEV/EPSS where relevant;
- source/provider attribution;
- remediation and verification status;
- coverage gaps/provider failures;
- audit trail.

### Developer Fix Report

For repository findings:

- file/location;
- why the pattern is risky;
- remediation pattern;
- safe example without leaking the discovered secret;
- follow-up actions such as rotation/history cleanup where relevant;
- rescan result.

## Formats

MVP:

- HTML
- JSON

Next reporting milestone:

- PDF generated from controlled local HTML using Playwright .NET.

## Report integrity

Reports should eventually include a SHA-256 of the report payload/export and an evidence manifest. Digital signing of reports is optional/future.

## Remediation lifecycle

```text
Finding -> Proposed Plan -> Review -> Approved -> Execute -> Verify -> Resolved/Failed
```

Manual remediation is still a first-class remediation plan. “Automated” must never be confused with “better.”

## Verification

A case cannot become `Resolved` from an automated action alone. The relevant detector(s) must be rerun or an explicit verification must prove the condition changed.

Example:

`Dependency CVE -> package updated -> lockfile rescanned -> CVE absent -> resolved`


---

# 09 - SUBAGENTS AND ORCHESTRATION

## Decision

**Yes: use dedicated subagents.** This project has enough independent domains to benefit from parallel analysis/implementation. However, parallelism must be controlled. The JR/Orchestrator remains the sole integration authority.

## Core rule

> Subagents may work simultaneously on independent contracts/modules. They may not independently redesign shared contracts or merge their own work into the integration branch.

## Roles

### 0. JR / Orchestrator

Owns:

- level scope and winning prompt;
- architecture decisions/ADRs;
- task decomposition;
- file ownership map;
- contract freezes;
- integration branch;
- cross-agent review;
- final test/security gates;
- PASS/FAIL decision.

The Orchestrator does not blindly accept specialist output.

### 1. Core Architecture Agent

Owns:

- Domain/Application/ProviderContracts;
- normalized models;
- database boundaries;
- provider orchestration abstractions;
- ADR proposals.

Cannot implement provider-specific logic unless assigned.

### 2. Local Analysis Agent

Owns adapters/tests for:

- hashing/file metadata;
- Authenticode;
- Defender availability/scan adapter;
- YARA-X integration;
- safe process execution requirements relevant to these engines.

Never executes scanned binaries.

### 3. Repository/AppSec Agent

Owns:

- Git target intake;
- Gitleaks adapter;
- Trivy repo/filesystem adapter;
- OSV-Scanner adapter;
- repository-relative safe paths;
- synthetic repo fixtures.

### 4. Vulnerability & Threat-Intel Agent

Owns:

- OSV API;
- NVD;
- CISA KEV;
- FIRST EPSS;
- URLhaus/MalwareBazaar/VT policy-gated adapters when their level arrives;
- caching/rate-limit semantics;
- vulnerability normalization/mapping evidence.

### 5. Web Surface Agent

Owns passive web checks:

- URI normalization;
- DNS;
- TLS/certificates;
- HTTP redirects;
- security headers/cookies;
- request limits/timeouts;
- explicit non-invasive boundary.

### 6. UX & Reporting Agent

Owns:

- Avalonia views/viewmodels/styles;
- Evidence Workbench interaction model;
- accessibility;
- report templates and redaction presentation.

Cannot move domain logic into ViewModels.

### 7. QA / Security Gate Agent

Read-mostly/review-focused role:

- adversarial input tests;
- process injection tests;
- secret leakage checks;
- provider failure tests;
- contract tests;
- E2E acceptance;
- dependency/license scan;
- release readiness evidence.

It should not “fix everything itself” unless the Orchestrator explicitly assigns a remediation task; otherwise it returns defects to the owning agent.

## Parallel work matrix

Safe parallel examples:

- Local Analysis Agent develops YARA adapter while Vulnerability Agent develops OSV client, provided ProviderContracts are already frozen.
- UX Agent builds static binding surfaces against agreed interfaces while Repository Agent implements adapters.
- QA Agent creates contract tests from frozen provider contracts while feature agents implement them.

Unsafe parallel examples:

- two agents edit `Finding` semantics independently;
- UI agent changes provider result schemas;
- multiple agents edit the same migration;
- any agent changes severity/confidence rules without ADR review.

## Branch/worktree convention

Recommended:

- `level/<N>/integration` - Orchestrator only.
- `agent/core/<task>`
- `agent/local/<task>`
- `agent/repo/<task>`
- `agent/intel/<task>`
- `agent/web/<task>`
- `agent/ux/<task>`
- `agent/qa/<task>`

Use separate worktrees when the environment supports them. No agent pushes directly to `main`.

## Mandatory handoff contract from every agent

Each specialist returns:

1. Scope completed.
2. Files changed.
3. Public contracts changed: yes/no; exact list.
4. Security implications.
5. Tests added/updated.
6. Commands run and results.
7. Known limitations.
8. Dependency/license changes.
9. Evidence/log snippets sufficient to reproduce tests.
10. Recommended integration order.

## JR integration gate

For every agent delivery:

1. Inspect diff.
2. Reject unrelated changes.
3. Re-run tests outside the agent worktree where practical.
4. Run format/build/static checks.
5. Check no secrets/new binaries were accidentally committed.
6. Validate provider behavior on success + timeout + unavailable + malformed output.
7. Resolve shared-contract conflicts centrally.
8. Integrate one delivery at a time.
9. Run the combined suite after each integration.
10. Only then move to final level gate.

## Subagent prompt template

```text
ROLE: <specialist>
LEVEL: <level>
TASK: <one bounded outcome>
READ FIRST: listed architecture/ADR files
OWNED PATHS: <paths>
READ-ONLY SHARED PATHS: <paths>
FORBIDDEN: altering shared contracts, main branch, unrelated refactors
INPUT CONTRACT: <interfaces/models>
OUTPUT CONTRACT: code + tests + handoff report
SECURITY REQUIREMENTS: <specific>
ACCEPTANCE TESTS: <specific>
STOP CONDITION: if shared contract must change, stop and request Orchestrator decision.
```

## Why this approach is better than “many agents edit everything”

It gives us real parallelism while preserving one architecture, one source of truth and one accountable integration gate. This is the model to show in project documentation because it demonstrates engineering discipline rather than simply using more agents.


---

# 10 - ROADMAP AND LEVEL GATES

## Level -1 - Technical Readiness

Stack validation, machine prerequisites, licenses, engine acquisition, keys, provider policies, signing/distribution plan, tool manifest, secret storage. **No feature implementation.**

## Level 0 - Product Contract & Architecture Freeze

Domain model, threat model, ADRs, repo skeleton, target/provider contracts, database model, UX information architecture, test architecture.

## Level 1 - Core Skeleton / Local Truth

Application launches; SQLite migrations; target intake; scan session lifecycle; provider status model; audit/logging foundation; no fake production data.

## Level 2 - Repository Security MVP

Local repositories/directories: Gitleaks + Trivy + OSV-Scanner; normalized findings; synthetic fixtures; Git-safe path handling.

## Level 3 - File Verification MVP

Hashing + file metadata + Authenticode + Defender capability + YARA-X; evidence correlation; no upload.

## Level 4 - Installed Software & Vulnerability Intelligence

Inventory strategy, package identity confidence, OSV/NVD/CISA KEV/EPSS correlation, fix availability where reliable.

## Level 5 - Passive Web Verification

DNS/TLS/redirect/header checks plus optional community reputation providers; strict request limits; no intrusive scanning.

## Level 6 - Finding Correlation & Case Lifecycle

Deduplication, evidence graph, confidence/coverage, cases/timeline, disagreement handling.

## Level 7 - Remediation & Verification

Manual plans first; safe automated actions only where narrowly scoped; before/after evidence and rescans.

## Level 8 - Reports

Executive + Technical + Developer Fix; HTML/JSON; PDF after HTML is stable; redaction/provenance.

## Level 9 - Evidence Workbench UX Polish

Keyboard flow, accessibility, empty/error/provider states, compare mode, first-run Engine Manager experience.

## Level 10 - CLI and CI Security Gate

`edy-verdict scan <target>` using same Application layer. GitHub CI integration for our own EDY projects; no dependency on gitleaks-action licensing.

## Level 11 - Hardening & Release Engineering

Supply-chain pinning, SAST/dependency audits, installer/updater decision, signing path, clean-machine tests, performance budgets.

## Level 12 - Public Release

Documentation, third-party notices, GitHub Release, checksums, release notes, safe synthetic demo, portfolio materials.

## Rule at every level

`4 prompts -> scored winner -> bounded execution -> specialist reviews -> JR integration -> full gate -> PASS/FAIL`.


---

# 11 - TEST STRATEGY

## Test layers

### Unit

- normalization;
- finding fingerprints;
- severity/confidence mapping;
- redaction;
- URI/path normalization;
- report view models;
- retry/backoff calculation.

### Provider contract

Every provider adapter must pass the same behavior contract:

- available/success;
- no findings;
- findings;
- unsupported/not configured;
- timeout;
- cancellation;
- malformed output;
- non-zero process exit;
- rate limited;
- sensitive error redaction.

### Integration

Run against installed official CLIs/services where safe. External API tests should be opt-in and quota-aware; default CI uses recorded/synthetic responses for transport-layer behavior without pretending those are production results.

### Safe security fixtures

- synthetic fake API tokens that match patterns but are not real credentials;
- intentionally vulnerable package locks in isolated fixture directories;
- intentionally weak config/IaC fixtures;
- EICAR only where appropriate to validate antivirus integration;
- custom harmless YARA test files/rules;
- local test HTTP/TLS endpoints where possible.

No live malware repository fixture.

### E2E

From clean app state:

1. scan safe synthetic repo;
2. observe known finding;
3. open evidence;
4. generate report;
5. execute allowed synthetic/manual remediation flow;
6. rescan;
7. verify lifecycle and report update.

## Negative/security tests

- filename containing shell metacharacters;
- extremely long path/name;
- malformed UTF-8/tool output;
- huge stdout/stderr;
- provider process hang;
- provider JSON schema drift;
- API 429/backoff;
- expired/invalid key;
- revoked TLS certificate test endpoint where safe;
- report HTML injection strings;
- symlink/junction traversal fixture;
- secret pattern in exception/log message to prove redaction.

## Quality gates

No level passes with:

- failing tests;
- build warnings newly introduced without disposition;
- Critical/High dependency vulnerability without explicit reviewed exception;
- secret scanner hit in tracked project files;
- unsupported third-party license introduction;
- production mock/fallback path;
- button/action without implementation in a feature declared done.


---

# 12 - RELEASE AND DISTRIBUTION

## External-user objective

A user should be able to obtain EDY VERDICT, install/run it, perform useful local scans without creating an account, and optionally configure free/community providers.

## Windows packaging options

### Option A - Self-contained installer/portable package

Pros: simplest development/release path.
Cons: unsigned/new binaries can trigger SmartScreen or Smart App Control friction.

### Option B - Microsoft Store

Pros: Microsoft documentation states Store apps are signed by Microsoft and avoid SmartScreen download warnings.
Cons: separate publishing requirements/process; decide later.

### Option C - Code signing outside Store

Microsoft currently recommends its Artifact Signing service for non-Store distribution, but it is paid. For an open-source project, evaluate **SignPath Foundation**, which advertises free code signing for qualifying OSS projects.

**Selected release-readiness action:** apply/evaluate SignPath Foundation before public v1.0. If not eligible, document unsigned beta behavior honestly rather than buying a service prematurely.

## Third-party engine delivery

Preferred v0.x:

- EDY app ships independently;
- Engine Manager downloads official pinned tools on demand;
- show source/version/license before acquisition;
- validate integrity/provenance;
- record installation metadata;
- allow engine removal/update.

A later offline/full bundle requires a separate redistribution audit and third-party notices.

## Release artifact set

- Windows installer or portable release chosen by ADR;
- SHA-256 checksums;
- SBOM for EDY app;
- `THIRD_PARTY_NOTICES.md`;
- `SECURITY.md`;
- `PRIVACY.md`;
- `CHANGELOG.md`;
- `RELEASE_NOTES.md`;
- signed artifacts if signing path available;
- clean-machine validation evidence.

## Update policy

No silent self-updater in the first milestone. Updates should be explicit. Engine databases/rules may have an explicit refresh operation with provenance and rollback/version history where feasible.


---

# 13 - LEVEL -1 PROMPT ROUND: TECHNICAL READINESS

## Scoring rubric (100)

| Criterion | Weight |
|---|---:|
| Technical correctness / reproducibility | 20 |
| Security & supply-chain rigor | 20 |
| Licensing/commercial-readiness | 15 |
| External-user installability | 15 |
| Provider/key/cost readiness | 10 |
| Long-term maintainability | 10 |
| Testability/evidence | 5 |
| Scope discipline | 5 |

---

## Prompt A - Stack Auditor

You are the technical platform auditor for EDY VERDICT. Perform Level -1 only. Do not create product feature code.

Read the entire documentation pack. Validate the proposed C#/.NET 10 + Avalonia 12.1.x + SQLite/EF Core architecture and all proposed third-party engines/providers using primary documentation available to you and the actual development environment.

Produce an evidence-backed readiness report that:

1. inventories installed Git, .NET SDK/runtime, PowerShell, Windows version/architecture and Defender capability;
2. determines the exact stable .NET 10 and Avalonia 12.1.x versions to pin today;
3. validates whether each NuGet dependency is compatible with the chosen target framework;
4. verifies official acquisition methods for YARA-X, Gitleaks CLI, Trivy and OSV-Scanner on Windows;
5. records official source URL, version, architecture, license, integrity mechanism/checksum/provenance availability for every external binary;
6. distinguishes `bundle`, `download-on-demand`, and `user-provided` distribution strategies and recommends one per engine;
7. verifies OSV, NVD, CISA KEV, FIRST EPSS, URLhaus, MalwareBazaar and VirusTotal community terms/requirements relevant to a free open-source desktop product;
8. creates a key/account checklist using placeholders only;
9. validates a safe local secret-store approach for development and installed Windows use;
10. evaluates Windows signing/distribution options, including free OSS signing eligibility paths;
11. defines a reproducible tool manifest schema and upgrade policy;
12. reports blockers and exact decisions required.

Do not install or download anything without first reporting the proposed source/version/impact. Do not store any real key in the repository. Do not use third-party download mirrors. Do not use `latest` in automation. End with PASS/FAIL for Level -1 and evidence for every gate.

### Score: 88/100

Strength: focused and disciplined. Weakness: weaker orchestration/test-contract planning and commercial-transition analysis.

---

## Prompt B - Public Distribution & Compliance Engineer

Act as release/platform engineer responsible for making EDY VERDICT genuinely downloadable by external users at zero mandatory monthly cost while keeping a credible future path to commercial use.

Perform Level -1 only. Read all project documents. Do not implement scan features.

For .NET/Avalonia, NuGet dependencies, YARA-X, Gitleaks CLI, Trivy, OSV-Scanner and every planned data/API provider:

- verify current license/terms from authoritative sources;
- identify redistribution obligations and whether we should bundle or acquire on demand;
- detect paid/proprietary components hidden behind otherwise open-source products;
- explicitly separate personal/community use from for-profit/commercial use;
- create `THIRD_PARTY_NOTICES` planning data;
- define what functionality remains when every optional API key is absent;
- verify how offline/local-only mode behaves;
- identify Windows SmartScreen/signing realities and evaluate SignPath Foundation vs Store vs paid signing without purchasing anything;
- define installation/update/uninstall requirements for external CLI engines;
- establish a zero-secret release build pipeline;
- define supply-chain verification and SBOM requirements.

Also produce a decision matrix for `free OSS release`, `free personal use`, and `future commercial edition`, making sure VirusTotal Public API and abuse.ch community terms cannot accidentally become mandatory commercial dependencies.

End with a concrete procurement/readiness checklist and blockers.

### Score: 91/100

Strength: excellent external-user/commercial readiness. Weakness: less deep on application/provider architecture and local environment validation.

---

## Prompt C - Security & Provider Readiness Lead

Act as Security Architect for EDY VERDICT Level -1. Your job is to prove that the planned security engines/providers can be integrated safely before feature development begins.

Do not implement the product.

Read the pack and validate:

- safe process execution model for external CLIs;
- untrusted-path/output handling;
- tool authenticity and pinned-version acquisition;
- provider authentication and secret storage;
- provider rate limits, retries, timeouts and caching;
- privacy modes LOCAL ONLY / HASH LOOKUP / CONNECTED;
- no-upload defaults and provider disclosures;
- fail-closed semantics;
- normalized provider contract requirements;
- provider contract-test fixtures for success, timeout, malformed data, unavailable, rate-limit and credential failure;
- secure report/redaction requirements;
- safe Windows distribution/signing prerequisites.

Threat-model the planned integrations with YARA-X, Defender, Gitleaks, Trivy, OSV-Scanner, OSV, NVD, CISA KEV, EPSS, URLhaus, MalwareBazaar and optional VirusTotal.

Create a risk register with severity, likelihood, mitigation, owner and gate. Any provider or tool whose terms/licensing cannot be confirmed must remain disabled/unselected rather than assumed safe to ship.

End with Level -1 PASS/FAIL and evidence.

### Score: 90/100

Strength: best security posture. Weakness: could underweight packaging/product maintenance and over-focus on threat modeling.

---

## Prompt D - Principal Engineer Bootstrap & Orchestration - WINNER

You are the Principal Engineer and JR Orchestrator for **EDY VERDICT**, currently at **LEVEL -1: TECHNICAL READINESS**. Your goal is to leave the project ready for implementation without creating feature code prematurely.

### Mandatory reading

Read every file in this documentation pack in the specified order, especially `START_HERE`, technical stack, providers/keys/costs, architecture, security/privacy, subagents/orchestration and release/distribution.

### Non-negotiable boundaries

- Do not create scanner UI or product features in Level -1.
- Do not publish/deploy.
- Do not purchase anything.
- Do not create external accounts or API keys on the user's behalf.
- Do not write secrets into repository files.
- Do not use unofficial mirrors.
- Do not bundle third-party binaries before license/redistribution decision.
- Do not silently change the selected stack; alternatives require an ADR with evidence.
- Do not treat a provider failure as a clean result.

### Phase 1 - Environment evidence

Audit the actual machine and produce reproducible evidence for:

- OS/build/architecture;
- Git;
- .NET SDKs/runtimes;
- PowerShell;
- Defender capability/state relevant to local scan integration;
- available package managers;
- existing relevant tools if already installed.

Do not infer installation from PATH alone; verify versions and executable origins where practical.

### Phase 2 - Version and license freeze proposal

Using authoritative current documentation and official releases, propose exact pinned versions or intentional compatible ranges for:

- .NET 10 SDK/runtime;
- Avalonia 12.1.x OSS core packages;
- EF Core SQLite;
- logging/DI/testing packages;
- YARA-X;
- Gitleaks CLI (not gitleaks-action);
- Trivy;
- OSV-Scanner;
- Playwright .NET when reporting requires it.

For every third-party component record:

`name | version | source | license | distribution strategy | integrity verification | update strategy | commercial concern`.

Reject accidental premium/Avalonia Pro dependencies.

### Phase 3 - Provider procurement matrix

Validate and record for:

OSV, NVD, CISA KEV, FIRST EPSS, URLhaus, MalwareBazaar and optional VirusTotal Community:

- key/account required?;
- current documented quota/rate behavior where published;
- local/community/commercial restrictions;
- query data we intend to send;
- whether the provider is Core/Optional/Restricted;
- caching/backoff requirement;
- exact safe secret placeholder name;
- behavior when missing/unavailable.

The core product must remain functional with zero user API keys.

### Phase 4 - Distribution and supply chain

Design the initial Engine Manager strategy:

- official acquisition endpoints;
- pinned platform artifact;
- checksum/signature/provenance verification;
- version manifest;
- atomic install/update/remove;
- license/notice display;
- failure/rollback behavior.

Evaluate public Windows release paths:

- unsigned beta implications;
- SignPath Foundation eligibility path for qualifying OSS;
- Microsoft Store as later option;
- paid Artifact Signing as non-MVP option.

Do not purchase or submit applications yet.

### Phase 5 - Secret storage and config

Define and validate:

- development: dotnet user-secrets/environment;
- CI: encrypted repository secrets later;
- installed Windows: Credential Manager or DPAPI-backed abstraction;
- redaction rules;
- provider configuration model that stores only non-secret metadata in SQLite.

Create example/config templates with placeholders only.

### Phase 6 - Subagent readiness

Create the subagent task map for future levels using the roles in `09_SUBAGENTS_ORCHESTRATION.md`.

For each agent define:

- owned paths;
- read-only shared paths;
- forbidden paths/actions;
- required handoff report;
- expected tests;
- stop condition if a shared contract needs change.

Do not spawn implementation work for later levels. You may delegate independent **read-only/readiness audits** in Level -1 if the environment supports subagents, then personally reconcile their evidence before accepting it.

### Phase 7 - Test/readiness artifacts

Create only Level -1 engineering artifacts such as:

- `docs/readiness/ENVIRONMENT.md`
- `docs/readiness/DEPENDENCIES.md`
- `docs/readiness/PROVIDERS.md`
- `docs/readiness/LICENSES.md`
- `docs/readiness/RELEASE_SIGNING.md`
- `docs/adr/` decisions for stack/acquisition/secret storage;
- version/tool manifest templates;
- safe example provider configuration;
- Level -1 gate report.

Do not create production scan implementations.

### PASS criteria

Level -1 is PASS only if:

1. stack versions are validated and pinned/proposed;
2. every external engine has an official acquisition/integrity/license strategy;
3. core works conceptually with zero API keys;
4. optional key list and safe storage are complete;
5. public-vs-commercial provider restrictions are documented;
6. no secret is in tracked files;
7. Engine Manager approach is implementable;
8. signing/SmartScreen release risk is understood;
9. subagent ownership model is ready;
10. no unresolved blocker makes the selected architecture unsafe or legally unsuitable.

Return `LEVEL -1: PASS` or `LEVEL -1: FAIL`, followed by evidence, blockers and the exact prerequisites for starting Level 0.

### Score: 98/100 - SELECTED

Why it wins: it combines environment validation, licensing, supply-chain security, zero-cost public distribution, provider/key readiness, subagent orchestration and objective gates while explicitly preventing premature feature coding.

---

## Result

**Winner: Prompt D.**

Do not execute A/B/C after D unless D discovers a blocker that specifically requires one of their specialist perspectives. Their strengths are already incorporated into D's acceptance criteria.


---

# 14 - CODEX MASTER HANDOFF

Copy/paste the block below to the Codex JR/Orchestrator together with this documentation folder.

---

You are taking ownership of the EDY VERDICT engineering workspace.

1. Read `00_START_HERE.md` and every referenced document in order.
2. The project is currently at `LEVEL -1: TECHNICAL READINESS`.
3. Do not implement product features yet.
4. The project uses a mandatory four-prompt competition per level. The Level -1 round has already been completed in `13_LEVEL_MINUS_1_PROMPT_ROUND.md` and **Prompt D is the selected winner**.
5. Execute Prompt D exactly, adapting only to facts discovered in the real environment. If an adaptation changes architecture, write an ADR and explain why before making the change.
6. Use specialist subagents only for bounded, independent readiness audits. You remain responsible for reviewing and reconciling every result.
7. Never allow multiple agents to change shared contracts concurrently.
8. Never place real API keys/tokens/secrets in tracked files, terminal transcripts intended for publication, reports or screenshots.
9. Do not publish, deploy, create paid resources or buy services.
10. End with an evidence-backed Level -1 PASS/FAIL report. Only PASS authorizes the next round of four Level-0 prompts.

Primary success condition: after Level -1, we should be able to begin Level 0 without discovering that our stack, licenses, API terms, key handling, engine acquisition or Windows distribution strategy was based on an assumption.

---


---

# SOURCES - RESEARCH SNAPSHOT

Checked around 2026-09-01. Always re-verify terms/version-sensitive facts before a public/commercial release.

- **Microsoft .NET Support Policy** - https://dotnet.microsoft.com/en-us/platform/support/policy
  .NET 10 LTS active; support through 2028-11-14; 10.0.11 current patch observed 2026-08-11.
- **Avalonia 12.1 release** - https://avaloniaui.net/blog/release-12-1
  Avalonia 12.1 released July 2026; cross-platform .NET UI; core open source.
- **Avalonia GitHub releases** - https://github.com/AvaloniaUI/Avalonia/releases
  12.1.x stable branch; 12.1.1 visible in August 2026 releases.
- **Avalonia license** - https://github.com/AvaloniaUI/Avalonia/blob/main/licence.md
  Avalonia core is MIT licensed.
- **YARA-X installation** - https://virustotal.github.io/yara-x/docs/intro/installation/
  Official prebuilt binaries exist for Windows/Linux/macOS; Rust not required for consumers.
- **YARA-X repository/license** - https://github.com/VirusTotal/yara-x
  YARA-X is mature/stable, production used by VirusTotal; BSD-3-Clause.
- **Gitleaks repository** - https://github.com/gitleaks/gitleaks
  Gitleaks CLI detects secrets; repository identifies MIT license.
- **Gitleaks CLI license** - https://github.com/gitleaks/gitleaks/blob/master/LICENSE
  CLI license is MIT. Do not confuse with gitleaks-action licensing.
- **Trivy filesystem scanning** - https://trivy.dev/docs/dev/target/filesystem/
  Trivy scans vulnerabilities, misconfigurations, secrets, licenses and can emit SBOM.
- **Trivy repository scanning** - https://trivy.dev/docs/latest/target/repository/
  Trivy scans local/remote code repositories.
- **Trivy license** - https://github.com/aquasecurity/trivy/blob/main/LICENSE
  Apache License 2.0.
- **OSV API** - https://google.github.io/osv.dev/api/
  Public OSV API currently states no rate limit; no API key required.
- **OSV-Scanner installation** - https://google.github.io/osv-scanner/installation/
  Official Windows binaries and WinGet distribution are available.
- **CISA KEV data** - https://github.com/cisagov/kev-data
  Official KEV data mirror publishes JSON/CSV and updates with the canonical catalog.
- **FIRST EPSS API** - https://api.first.org/epss/
  Public EPSS CVE exploitation probability data API.
- **NVD developers** - https://nvd.nist.gov/developers/start-here
  NVD API 2.0; API key recommended. Current published rate guidance commonly states 5 requests/30s without key and 50/30s with key; implementation must obey headers/retry guidance.
- **URLhaus Community API** - https://urlhaus.abuse.ch/api/
  Free under fair use; Auth-Key required; commercial/for-profit use may require enhanced commercial API.
- **MalwareBazaar Community API** - https://bazaar.abuse.ch/api/
  Free under fair use; Auth-Key required; submit confirmed malware only; commercial use may require enhanced API.
- **VirusTotal Public vs Premium API** - https://docs.virustotal.com/reference/public-vs-premium-api
  Public API: 4 requests/minute, 500/day; must not be used in commercial products/services.
- **Microsoft SmartScreen reputation** - https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation
  Unsigned downloads can show SmartScreen warnings; Store distribution avoids download warnings; Artifact Signing is paid.
- **SignPath Foundation** - https://signpath.org/
  Free code signing is offered for qualifying open-source projects.
- **Playwright .NET license** - https://github.com/microsoft/playwright-dotnet/blob/main/LICENSE
  Playwright for .NET is MIT licensed.
