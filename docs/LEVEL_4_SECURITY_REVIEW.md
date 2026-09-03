# EDY VERDICT — Level 4 security review

Date: 2026-09-03. Scope: authorized passive Web/URL Security only. This is a
manual review plus automated tests, not an independent penetration test or a
claim that a target is safe.

## Trust boundaries and controls

The URL, DNS answers, redirects and response headers are attacker-controlled.
Parsing is closed to HTTP(S), default ports and credential-free absolute URLs.
All DNS answers must be public; mixed answers fail. Connections consume the exact
validated and pinned address while preserving hostname/SNI validation. Redirects
repeat the policy and HTTPS downgrade is blocked. reqwest uses rustls, no proxy,
automatic redirects disabled, fixed GET headers, bounded timeouts and zero body
reads. CRLF, controls, encoded separators and arbitrary frontend headers/methods
are rejected by construction.

Isolation, CSP, local assets, navigation/origin checks and typed IPC remain in
force. Generic frontend filesystem, shell and HTTP permissions remain denied.
The fake resolver, transport, reputation data and WebDriver exist only under
`native-e2e` plus `debug_assertions`; release compilation explicitly rejects that
feature.

SQLite schema v5 stores sanitized analysis under a SHA-256 integrity check and
optimistic revision. It is not an authenticity boundary against same-user
malware. Cancellation is persisted before signalling; a terminal snapshot cannot
be resurrected. Reports escape HTML and use conservative language.

## Resource and privacy review

Limits cover URL/query sizes, DNS answers/time, connect/request time, redirects,
total requests, header count/value/aggregate, cookies, CSP, SQLite snapshot count
and report size. No response body, crawler, JavaScript, form, login, enumeration,
active TLS probing or exploit request exists.

Cookie values are never represented in the domain model. Query values are either
stripped or held only in the authorized in-memory request URL. URL credentials are
rejected. Synthetic marker searches across SQLite, reports, IPC and DOM returned
zero full-value occurrences outside test-only fixture source/evidence.

## Findings

| Severity | Open | Resolution |
|---|---:|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | Two native-integration defects were fixed: terminal URL scans can start a new target, and failed coverage no longer double-counts one check. |
| Low | 1 | Accepted: blocking DNS uses a bounded helper thread that cannot be cancelled after the 3-second receiver timeout; the detached thread has no mutation or transport capability. |
| Informational | 2 | Certificate success records normal validated negotiation but not cipher/protocol enumeration. Local SQLite SHA-256 detects corruption, not hostile same-user replacement. |

`CRITICAL=0`, `HIGH=0`, `MEDIUM=0`. The Low is bounded and does not permit an SSRF
escape, secret persistence, additional request or false clean verdict. The five
pre-existing Tauri `unic-*` advisories remain the separate Level -1C upstream
blocker and are not reclassified as Level 4 findings.

## Environment incident

The exact trigger was the direct unwrapped global command `rustup toolchain list`
from repository CWD with both Rust homes unset. That bypassed the project guard and
the neutral global-inventory helper, allowing the repository override to act on the
global home and briefly recreate toolchain 1.98.0. The extra toolchain was removed
through official Rustup under the user's earlier exact cleanup authorization.
Stable/default, settings, PATH, proxy and certificate-store fingerprints match the
baseline.

The escape path is closed fail-closed: repository Rust commands require exact
project-local homes; global inventory requires an explicit neutral caller and
target and exposes only the read-only list operation; provisioning requires a
separate explicit project-local switch. The 14-case test-double/environment matrix
passes without invoking global Rustup or provisioning a toolchain. The historical
incident remains auditable as remediated, the current environment is approved, and
the remediation introduced no new global mutation.
