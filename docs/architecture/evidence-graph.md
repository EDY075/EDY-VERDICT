# Level 5 evidence graph

`ENTITY_ID_V1` derives deterministic IDs only from typed strong identities.
Supported entities are repository, package, installed application, file artifact,
vulnerability, URL, origin, domain, publisher, scan target and finding. Edges have
specific semantics, a stable rule ID, evidence IDs, source scans, confidence and a
safe explanation. There is no generic `RELATED` edge.

The graph is an in-process bounded representation persisted as an
integrity-checked SQLite snapshot; no external graph database is introduced.
Secret plaintext, cookie values, query values, provider credentials, private keys
and authentication tokens are refused. Normal explanations do not expose digests,
private paths or implementation internals.

A URL belongs structurally to an origin and domain. A common domain never implies
the same vulnerability, application or incident. A shared CVE groups separate
affected assets and never erases their individual findings.
