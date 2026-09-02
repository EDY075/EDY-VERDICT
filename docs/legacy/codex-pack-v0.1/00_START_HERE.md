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
