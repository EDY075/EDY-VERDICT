# Level 5 deterministic correlation model

Level 5 reuses normalized findings and evidence from Levels 1–4. Rules are a
closed, versioned set executed in canonical order. Exact CVE, SHA-256, PURL, CPE
and normalized-origin keys use indexed maps; display names, filenames, publisher
text and similarity never create strong relationships.

Deduplication remains limited to the same logical finding on the same affected
asset. Cross-target matches preserve every finding and form evidence groups.
`L5-RULE-STRUCTURAL-V1`, `L5-RULE-SHARED-CVE-V1`, `L5-RULE-SHARED-ARTIFACT-V1`,
`L5-RULE-SHARED-COMPONENT-V1` and `L5-RULE-SHARED-WEB-ORIGIN-V1` explain every
edge. Replay from the same normalized observations produces the same ordered
graph, clusters, cases and reasons without network access.

Limits bound nodes, edges, case members, evidence references, timeline events and
traversal depth. Exceeding a limit returns `PARTIAL_CORRELATION / LIMIT_REACHED`;
cancellation promotes no partial graph.

Case risk starts with the maximum original technical severity, then adds bounded
KEV, high-EPSS, multi-target and multi-target-type contributions (maximum 100).
Confidence starts independently and is reduced by unavailable providers,
conflicting evidence and parser uncertainty. Coverage is reduced independently by
unavailable providers. Priority is derived from risk plus KEV and low-confidence
review rules; none of these dimensions rewrites source severity.
