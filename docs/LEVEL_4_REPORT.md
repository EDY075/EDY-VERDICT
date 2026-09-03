# EDY VERDICT — Level 4: Web / URL Security

Date: 2026-09-03. Scope is Level 4 only. Level 5 was not started. No Windows,
Defender, firewall, proxy, certificate-store, SMBIOS or global Rustup setting was
changed; no push, PR, deployment, package, installer or release was performed.

## Rustup hygiene incident

During the final read-only environment comparison, the direct unwrapped command
`C:\Users\edmil\.cargo\bin\rustup.exe toolchain list` was invoked from the
repository with `RUSTUP_HOME` and `CARGO_HOME` unset. The repository override then
caused Rustup to recreate the global `1.98.0-x86_64-pc-windows-msvc` toolchain.
The incident was immediately stopped and remediated using the previously authorized
official `rustup toolchain uninstall` command, executed outside the repository.
The global `stable` default, Rustup settings hash and user/machine PATH hashes never
changed; the final extra-toolchain state is absent.

The root cause was the bypass of both approved project helpers by an interactive
global inventory call from repository CWD. The global-inventory helper now rejects
both a repository caller and a repository target, requires its declared directory
to be the current neutral directory, and remains restricted to `toolchain list`.
Project-local provisioning now requires an explicit switch and validates the local
homes before resolving Rustup. A 14-case non-provisioning regression matrix covers
root/child unset, global, foreign and approved homes; child inheritance; neutral
inventory; repository denial; and the exact repository-to-neutral bypass shape.
The historical incident remains recorded as `YES / REMEDIATED`; prevention is
verified and no new Rustup incident occurred during final remediation.

## Delivered contract

- explicit sanitized preview, single-use authorization and typed Web/URL IPC;
- HTTP(S)-only normalization with IDNA, fragment removal and query-value privacy;
- public-internet-only DNS, mixed-answer rejection, rebinding defense and pinned
  hostname-preserving transport for every redirect hop;
- rustls-backed GET client with no proxy, cookies, credentials, referer, body read,
  automatic redirect or arbitrary frontend network request;
- validated TLS negotiation, bounded redirects and downgrade prevention;
- HSTS, CSP, selected security-header, CORS and cookie-attribute observations;
- optional exact canonical URLhaus local-dataset contract with honest unavailable
  state and no URL submission;
- conservative correlation, risk/confidence/coverage, SQLite v5, deterministic
  JSON/HTML reports, React workflow and cancellable terminal-safe worker.

## Dependency delta

No new direct dependency was added. The existing runtime dependency `reqwest
0.13.4` (`MIT OR Apache-2.0`) changed from feature `native-tls` to `rustls` so the
Level 4 transport has an explicit Rust TLS backend. The locked Windows runtime
graph now includes `rustls 0.23.43` (`Apache-2.0 OR ISC OR MIT`),
`hyper-rustls 0.27.9` (same), `tokio-rustls 0.26.4` (`MIT OR Apache-2.0`),
`rustls-platform-verifier 0.7.0` (`MIT OR Apache-2.0`), `rustls-webpki 0.103.15`
(`ISC`), `aws-lc-rs 1.18.1` and `aws-lc-sys 0.45.0` (multi-license expressions
recorded verbatim in the generated inventory), plus their build/runtime
transitives. Native TLS/OpenSSL transitives used by reqwest were removed. The
lockfile changed by 356 inserted and 94 removed lines; no broad `cargo update` was
used. SBOM, license inventory, lock hashes and preliminary notices were regenerated.

Cargo deny is the advisory authority for this graph. Licenses, sources and bans
must pass; only the five already documented pinned-Tauri `unic-*` advisories may
remain. Generated notices are preliminary and do not grant redistribution
clearance.

The reviewed SPDX policy now explicitly permits `ISC` and `MIT-0`, both
permissive/OSI-approved identifiers required by the rustls/AWS-LC expressions.
No package, source or advisory is ignored.

## Validation evidence

The deterministic suites cover parsing differentials, IDNA, IPv4/IPv6 and mapped
addresses, empty/mixed/excessive DNS, timeout/failure, rebinding, pinned requests,
private redirects, all supported redirect statuses, loop/limit/downgrade, ordinary
HTTP statuses, transport/TLS errors, HSTS/CSP variants, cookies and redaction,
reputation states, correlation, storage migration, reports, IPC and cancellation.

The native Tauri/WebView2 E2E uses only debug-gated fake DNS/HTTP/reputation while
retaining real React, Isolation, IPC, domain logic, correlation, SQLite and
reporting. It exercises three resolutions (1366×768, 1920×1080, 2560×1440), the
authorized redirect flow, direct and redirect SSRF blocks, HTTPS downgrade,
cancelled terminal state, reports and query/cookie redaction.

One separately authorized production smoke used only `https://example.com/`, one
normal GET, no body read and no reputation query. DNS policy, address pinning,
certificate/hostname validation, bounded headers and status succeeded. The domain
is reserved for documentation by IANA; no security rating was assigned.

## Provider and limitations

URLhaus Auth-Key is optional and not configured. The provider contract, future
native credential boundary, local exact-match parser and synthetic E2E are ready;
live reputation is `BYOK NOT CONFIGURED`, not a clean result and not Level 4 debt.
Mandatory monthly cost is zero.

Passive checks do not prove a website is safe. Missing headers do not prove
exploitability, and present headers do not prove security. No active testing,
crawling, page JavaScript, subdomain enumeration, form submission, login, cipher
enumeration or vulnerability exploitation is performed. DNS/TLS/HTTP and local
reputation results are point-in-time observations.

## Preserved external state

The pinned Tauri versions and all engines/providers from earlier levels remain
unchanged. `TAURI_UPSTREAM_GATE=WAITING_FOR_OFFICIAL_RELEASE`; `LEVEL-1C=FAIL /
WAITING UPSTREAM`. Real engine execution remains policy-blocked. The final Level 4
freeze, local annotated tag and hashes are recorded outside the repository in the
Level 4 evidence ledger.
