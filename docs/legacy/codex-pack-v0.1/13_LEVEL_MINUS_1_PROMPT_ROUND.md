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
