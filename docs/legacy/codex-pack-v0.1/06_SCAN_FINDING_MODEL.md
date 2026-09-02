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
