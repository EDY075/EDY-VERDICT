# Level 5 evidence graph

`ENTITY_ID_V1` derives deterministic IDs only from typed strong identities.
Supported entities are repository, package, installed application, file artifact,
vulnerability, URL, origin, domain, publisher, scan target, finding and evidence.
`RELATIONSHIP_ID_V1` derives a stable directional ID from relationship type,
endpoints and the versioned rule. Edges retain contributing finding IDs, evidence
IDs, source scans, creator, confidence, rule/version and a safe explanation. There
is no generic `RELATED` edge.

The graph is an in-process bounded representation persisted both as an
integrity-checked canonical envelope and normalized SQLite entities/relationships;
no external graph database is introduced.
Secret plaintext, cookie values, query values, provider credentials, private keys
and authentication tokens are refused. Normal explanations do not expose digests,
private paths or implementation internals.

A URL belongs structurally to an origin and domain. A common domain never implies
the same vulnerability, application or incident. A shared CVE groups separate
affected assets and never erases their individual findings.

The structural matrix is: target contains component, finding affects entity,
package/application has vulnerability, file has SHA-256, file is explicitly
associated with an application through an exact shared artifact, URL belongs to
origin, origin belongs to domain, and finding is supported by evidence. Cross-
finding edges are separate (`findings share vulnerability/artifact/component/origin`)
and require an exact canonical identity.
