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
