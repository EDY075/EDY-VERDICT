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
