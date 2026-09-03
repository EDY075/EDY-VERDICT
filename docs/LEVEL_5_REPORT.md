# EDY VERDICT — Level 5 advanced correlation and investigation

Scope: deterministic cross-target correlation for repository, file/binary,
installed-application and Web/URL findings. Level 6 and remediation execution are
not part of this work.

The domain provides strong typed entity identities, evidence-backed relationship
edges, canonical rule ordering, finding-preserving clusters, suggested/manual
cases, lifecycle audit, observed blast radius, separate risk/confidence/coverage,
explainable priority, recurrence and timeline. Indexed identity keys avoid full
pairwise comparison. Bounded cancellation returns no promoted partial graph and
limit exhaustion is explicit.

SQLite schema v6 stores integrity-checked redacted input/result envelopes plus
normalized runs, entities, findings, evidence, relationships, relationship
evidence/finding links, clusters, cases, memberships and timelines. Composite
foreign keys, uniqueness checks and bounded indexes are enabled on every runtime
connection. Promotion independently replays the supplied observations, verifies
semantic equality and commits in one transaction. Cancelled or limit-exhausted
correlation is never authoritative. Every stored envelope and materialized
payload is verified by SHA-256 when read.

The read-only CLI can replay a persisted approved run and list/show clusters and
cases in human or JSON form. The typed Tauri IPC exposes bounded pages, graph,
case lifecycle and local Executive/Technical/Analyst reports. The React
Investigations workspace renders overview metrics, filters, cases, findings,
affected assets, relationships, timeline, evidence, score rationale and coverage.
Native Tauri/WebView2 QA exercises the real backend and SQLite at 1366x768,
1920x1080 and 2560x1440; no mocked IPC or external request is used. A dedicated
purpose-specific cancellation command can interrupt correlation without taking
the storage mutex. Native QA also proves `CANCELLED` and
`LIMIT_REACHED / PARTIAL_CORRELATION` leave the authoritative graph unchanged.
Temporal replay preserves finding identity while increasing occurrence metadata;
recurrence creates an ordered `finding_reopened` timeline event.

The Level 5 security acceptance found zero Critical, High or Medium issues. The
only informational observation is the localized MSVC linker status message; it
does not represent a code diagnostic. `cargo-deny` remains blocked only by the
five frozen upstream `unic-*` unmaintained advisories inherited through the
pinned Tauri dependency. No exception or dependency update was introduced.

Correlation does not prove causation. A shared CVE does not mean the same asset or
same compromise. A shared domain does not mean the same incident. A suggested case
does not prove an incident occurred. Observed blast radius is limited to associated
analyzed targets. Unavailable providers reduce coverage. Priority is not severity,
and confidence is not risk.

Tauri remains pinned at 2.11.5. The upstream gate remains an external blocker but
does not prevent Level 5 closure. No host setting, provider key, engine, installer,
Level 6 behavior or remediation action is changed by Level 5.
