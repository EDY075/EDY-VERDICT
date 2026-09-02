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
