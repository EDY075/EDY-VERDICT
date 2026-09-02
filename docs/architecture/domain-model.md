# Domain model

## Aggregate map

| Type | Identity and purpose | Important rules |
|---|---|---|
| `Scan` | `ScanId`; one requested analysis | Has 1..128 unique targets and a closed lifecycle |
| `Target` | `TargetId`; repository, file, binary, installed app, URL or website | Kind and locator are validated together; remote targets are HTTPS-only |
| `Evidence` | `EvidenceId`; immutable observation material | Digest, provenance, timestamp, bounded summary/facts and explicit redaction flag |
| `Finding` | `FindingId`; correlated security observation | Carries scan/target, sources, rules, severity, confidence, fingerprint, timestamps, evidence and remediation references |
| `Verdict` | Result for one evaluated scan | Contains kind, separate risk/confidence, reasons, evidence references and unavailable checks |
| `RemediationPlan` | `RemediationId`; conservative response contract | Every step declares safety, confirmation and reversibility; verification is mandatory |

IDs are supplied by an outer UUIDv7 generator. Parsing rejects other UUID versions, non-canonical
shape and invalid variant bits. This crate deliberately does not synthesize random IDs.

## Evidence and findings

Evidence records source, timestamp, SHA-256 digest, human summary, bounded structured facts, an
optional raw reference and producer provenance. A redacted flag is part of the contract; raw secret
material must never be placed in summary or structured facts. Persistence and presentation layers
remain responsible for enforcing their own secret filters.

A finding starts `open`. Correlation retains all distinct engines, rules and evidence IDs while
merging observations with the same stable semantic identity. Severity and parser confidence may
increase as independent observations arrive. `first_seen` cannot move backwards; `last_seen` cannot
move backwards. A resolved finding reopens only through the explicit regression operation.

## Fingerprint V1

`FindingFingerprint` has the form `ffp1-` plus 32 lower-case hexadecimal characters. V1 hashes a
length-framed, normalized tuple:

1. target kind;
2. canonical target locator;
3. normalized category;
4. normalized semantic key;
5. normalized location.

It intentionally excludes scan/finding IDs, timestamps, message prose, severity, engine name,
engine version and rule source. The algorithm is a deterministic domain-separated FNV-1a pair.
It is a stable deduplication key, not a cryptographic integrity primitive. Evidence integrity uses
the separate SHA-256 digest. Changing the tuple or algorithm requires `Fingerprint V2`; V1 output
must never be silently reinterpreted.

## Validation boundary

Constructors reject empty/oversized text, duplicate structured keys, incoherent locator kinds,
invalid digests and invalid lifecycle transitions. Deserialization provides strict unknown-field
handling and re-enters aggregate validation for targets, evidence, findings, coverage, engine tasks,
scan plans and remediation workflows. External adapters must still call domain constructors or
validation methods before publishing engine observations; serialized input is not authorization.

Provider coverage is recorded separately from `(engine, target)` execution. Every planned provider
has an explicit availability result. Any result other than `available` makes total scan coverage
incomplete and must be mirrored by the verdict's unavailable-check list.
