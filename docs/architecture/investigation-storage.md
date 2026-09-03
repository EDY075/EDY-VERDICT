# Level 5 relational storage v6

The project-local SQLite database migrates forward from snapshot versions 1–5 to
schema version 6. Earlier Level 0–4 tables and data remain intact.

Level 5 uses `level5_correlation_runs`, `level5_entities`, `level5_findings`,
`level5_evidence`, `level5_relationships`, `level5_relationship_findings`,
`level5_relationship_evidence`, `level5_clusters`, cluster membership tables,
`level5_cases`, case membership tables and `level5_case_timeline`. Run-scoped
composite keys prevent cross-run references. Foreign keys protect every
graph/case/finding/evidence reference; uniqueness constraints prevent duplicate
entities, edges and memberships. Indexes cover stable identity, entity type, CVE,
SHA-256, PURL, CPE, directed endpoints, finding, cluster, case status/priority/risk
and ordered timeline reads.

Promotion serializes redacted normalized observations and the deterministic result,
verifies every edge endpoint, then inserts the canonical envelope and all
relational rows in one transaction. Only `complete` non-limited results may be
promoted. A constraint, duplicate, cancellation, limit or serialization failure
rolls back the whole operation.

Reload verifies observation, result and normalized payload SHA-256 values before
deserialization. Replay reruns the closed rule set over persisted observations
and requires semantic equality with the stored result. The CLI opens SQLite in
read-only/query-only mode and a byte-for-byte test proves it performs no write.
Lists are explicitly paginated (maximum 100); identifiers and payload sizes are
bounded. Fixture secret markers are refused before SQL writes.
