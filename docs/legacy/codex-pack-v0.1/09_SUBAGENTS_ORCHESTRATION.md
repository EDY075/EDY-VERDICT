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
