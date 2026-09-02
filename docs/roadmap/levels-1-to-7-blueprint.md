# EDY VERDICT — Levels 1–7 blueprint

Status: DESIGN CONTRACT. This document plans future work; it does not authorize
active scanning, host modification, packaging, deployment, or paid providers.

## Invariants

- Windows 10 Pro 22H2 x64 remains a fixed requirement.
- Mandatory monthly service cost remains R$ 0.
- Remote providers are optional and BYOK; local operation must remain useful.
- Every scan reports coverage and limitations. Unavailable checks never become a
  clean result or increase confidence.
- Inputs, evidence, logs, and reports redact detected secrets by default.
- Engine execution requires a valid V2 manifest, receipt, artifact hash, policy
  decision, bounded process execution, and controlled arguments.
- Active web testing is restricted to targets the user owns or is authorized to
  test. Malware execution is never part of this plan.

## Level 1 — Repository security

Targets: an explicitly selected repository checkout. Planned checks: Gitleaks;
Trivy repository/configuration; OSV-Scanner dependency analysis; dependency,
misconfiguration, supply-chain, and license findings. Full secret values must not
enter findings, evidence summaries, storage, or reports. The scan plan records
which checks were requested, executed, skipped, or failed.

Exit gate: deterministic normalized findings, secret-redaction regression tests,
dependency and configuration fixtures, full coverage semantics, and no arbitrary
path scan exposed by the public CLI before authorization controls exist.

## Level 2 — File and binary analysis

Targets: user-selected files and binaries. Planned passive analysis: SHA-256 and
SHA-512, size/type metadata, PE metadata, Authenticode status, YARA-X rules, local
reputation cache, and optional hash-only provider lookup. Files are never executed.

Exit gate: bounded reads, race-resistant identity checks, parser fixtures, benign
YARA-X smoke only, signature validation evidence, and explicit unsupported-format
results rather than optimistic verdicts.

## Level 3 — Installed applications

Targets: read-only software inventory. Planned evidence: application name,
version, publisher, installation source where safely available, signature status,
CVE mapping, CISA KEV, EPSS, and update priority. Inventory does not uninstall,
update, repair, or modify software.

Exit gate: source provenance per inventory record, version-normalization tests,
ambiguous-product handling, coverage reporting, and a confirmation boundary before
any future remediation action.

## Level 4 — Web and URL

Baseline is PASSIVE FIRST: DNS, redirects, TLS and certificate metadata, security
headers, CSP, HSTS, cookie attributes, URL reputation, URLhaus, and optional
VirusTotal BYOK. Redirects remain bounded and every network destination is logged
as provenance without recording secrets.

Active tests are a separate future capability restricted to owned or explicitly
authorized targets. Exploitation, credential attacks, denial of service, stealth,
and persistence are out of scope.

Exit gate: target-authorization model, SSRF defenses, private-network policy,
redirect policy, rate limits, request budgets, user-agent policy, and reproducible
passive fixtures.

## Level 5 — Correlation expansion

Extend the deterministic Level 0 correlation model with vulnerability identity,
asset relationships, independent-source weighting, KEV/EPSS context, temporal
history, and contradiction preservation. Confidence remains separate from risk;
provider failure lowers confidence and coverage but never automatically lowers
risk.

Exit gate: versioned scoring policy, golden scenario matrix, migration strategy,
explanation stability, and explicit behavior for missing or stale intelligence.

## Level 6 — Remediation and verification

Start with plans and guided manual steps. Automation is limited by safety class:
informational, safe-automatable, confirmation-required, manual-only, or prohibited.
Each executable step requires authorization, preconditions, rollback information,
audit events, and a verification/rescan plan.

Exit gate: fake executor coverage, idempotency, cancellation, rollback and partial
failure semantics, user confirmation UX, least privilege, and platform-specific
security review. No host mutation is enabled merely by reaching this level.

## Level 7 — Release and QA

Planned gates: reproducible locked builds, SBOM and notices, dependency/advisory
review, secret scan, Windows 10 test matrix, accessibility, performance, installer
provenance, code signing decision, upgrade/uninstall testing, rollback, and release
artifact hashes. Distribution remains local until separately authorized.

Exit gate: all mandatory security gates pass, known exceptions are time-bounded and
approved, release signing is configured through an existing trusted mechanism, and
the installer never bundles engines whose redistribution decision forbids it.

## Cost policy

Core operation, local engines, OSV, CISA KEV, URLhaus community access where its
terms permit, and local reporting must not impose a mandatory subscription. NVD
keys, VirusTotal, commercial intelligence, signing services, and other paid plans
remain optional/BYOK and may improve limits or coverage only; their absence is a
reported limitation, not a product failure.
