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
