# Publication Security Audit

Audit date: 2026-09-05<br>
Repository visibility: PUBLIC<br>
Audited HEAD: `ffa08db57c06`<br>
Decision: **READY FOR OWNER REVIEW — source release candidate only**

## Scope

The review covered the current working tree, Git index, every reachable commit, all local and remote refs, all tags, deleted historical paths, unreachable loose blobs, documentation, fixtures, screenshots, generated dependency inventories, SBOM material, and release instructions.

No matched credential or private value is reproduced in this report.

## Coverage

| Surface | Coverage |
|---|---:|
| Reachable refs | 21 |
| Tags | 10 |
| Reachable blobs | 558 |
| Staged paths at audit start | 0 |
| Unreachable loose blobs | 48 |
| Unreachable commits | 0 |

The unreachable blobs were scanned separately because they are not covered by `rev-list --all`.

## Findings

| Type | Sanitized location | Status | Action |
|---|---|---|---|
| Credential signatures | Reachable history | FALSE POSITIVE | Authorization field names and synthetic provider fixtures; no credential value confirmed. |
| Personal e-mail pattern | Third-party notices | EXPECTED THIRD-PARTY ATTRIBUTION | Retained because it belongs to an upstream copyright notice. |
| Phone pattern | Lockfiles, hashes, schemas, fixtures | FALSE POSITIVE / SYNTHETIC | Numeric ranges and hashes were manually classified; no personal phone confirmed. |
| Host-specific user path | `docs/LEVEL_4_REPORT.md`, first seen in `6ca900e8b8b0` | REMOVED FROM HEAD | Replaced in the working tree with `%USERPROFILE%`; old public history remains non-secret. |
| Host-specific user path | `docs/security/provisioning-incident.md`, historical versions first seen in `22ff2eb45ebb` and `a78954b9db1a` | REMOVED FROM HEAD | Replaced with neutral placeholders; no history rewrite is required for security. |
| Workspace path | Public contributor/incident documentation | REMOVED WHERE UNNECESSARY | Current prose now uses portable wording and neutral placeholders. |
| Unreachable blob matches | Build output, dependency metadata, hashes, upstream attribution | FALSE POSITIVE / NON-SECRET | No credentials and no unreachable commits were found. |
| Screenshots | `docs/screenshots/`, `linkedin-post/` | APPROVED SYNTHETIC | Synthetic paths and targets only; no user profile, real inventory, browsing data, credential, or machine identifier. |
| SQLite / DPAPI material | Full history and current tree | NOT FOUND | No database, DPAPI payload, private-key material, `.env`, or credential container is tracked. |

## History decision

No valid historical credential was found. Therefore:

- `SECURITY_BLOCKER = NO`
- Credential rotation is not required by this audit.
- Automatic history rewriting was not performed.
- The low-risk historical host-path references are already public and do not contain a credential; rewriting them would be disruptive and requires separate approval if desired for privacy hygiene.

## Public repository review

`AGENTS.md`, `THREAT_MODEL.md`, `SECURITY.md`, `PRIVACY.md`, `SUPPORT.md`, `CONTRIBUTING.md`, `docs/`, generated security inventories, and build instructions were retained because they document real trust boundaries, release limitations, and reproducibility. The main README now summarizes these materials instead of duplicating them.

## Final validation

| Gate | Result |
|---|---|
| TypeScript + ESLint | PASS |
| Frontend/architecture tests | PASS — 106 tests |
| Production frontend build | PASS |
| Rust workspace tests | PASS — 302 passed, 4 intentionally ignored |
| Clippy + rustfmt | PASS |
| Current-tree secret scan | PASS — 684 owned source/document files, 0 findings |
| Full-history semantic review | PASS — no valid credential or personal investigation data |
| `pnpm audit --prod` | PASS — no known vulnerabilities |
| `cargo audit` | PASS — zero vulnerabilities; 17 allowed transitive warnings |
| `cargo deny advisories` | EXPECTED NON-ZERO — five unsuppressed `unic-*` maintenance advisories inherited through Tauri, no safe upgrade currently available |
| README links + PowerShell render parse | PASS |
| Publication images | PASS — 5 slides at 1800×942 and banner at 1800×600 |
| Large tracked/new files | PASS — none at or above 20 MiB |

The five `unic-*` advisories remain a documented upstream release limitation. They do not change the decision to present this repository as a transparent source-only release candidate; they do block any claim of a fully clean `cargo deny` gate.
