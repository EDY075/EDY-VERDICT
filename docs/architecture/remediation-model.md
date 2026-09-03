# Level 6 manual remediation model

Production lifecycle:
`persisted run/case/finding → plan → guidance / suggested diff → manual action outside EDY
→ explicit rescan-only authorization → original-family rescan → verification result`.

No automatic mutation or rollback is available. See the
[production safety policy](../security/remediation-safety-policy.md).

## Contracts

RemediationPlan, RemediationAction and VerificationPlan retain bounded deterministic
identifiers and SHA-256 binding. ManualSnapshot stores run, revision, guidance, suggested
diff, limitations, VerificationAuthorization metadata, result and ordered events.

GUIDANCE_ONLY, MANUAL_CHANGE_VERIFIABLE, POLICY_BLOCKED and UNSUPPORTED are production
classes. TEST_ONLY_REVERSIBLE is refused at the manual boundary. Suggested diffs are
sanitized explanatory suggestions, not directly executable patches, and explicitly say
“Suggested change — not applied by EDY VERDICT”.

VerificationAuthorization expires after five minutes, is single use and binds action,
finding, case, run, stable target identity and both plan hashes. It grants no write.
Expected post-apply hashes in the legacy data contract are zero placeholders for manual
plans and are not used to reject authorized pre-scan manual changes.

## States and actual cases

States: planned, awaiting_manual_change, verification_pending, verifying, resolved,
still_present, inconclusive, regression_detected, target_invalid, cancelled, interrupted.

The Level 5 membership row must exist before plan creation. Production accepts no orphan
finding. Each meaningful transition appends a Level 6 event and a real Level 5 case event
inside the same revision-checked transaction. A finding's successful verification cannot
resolve other open members. Reverification/regression prevents a stale resolved case.

## Data and interfaces

SQLite schema 8 preserves prior data and stores only manual workflow objects in its new
tables. Mutating executor state is historical/test-only and is not loaded by this backend.
CLI stays read-only. The historical CLI “receipt” read command returns a manual verification
report, never an automatic-change receipt.

UI lists actual persisted cases/findings, creates plans, displays guidance/diff and calls
typed verify/cancel/report IPC. Requests carry IDs and transient rescan authority only.
Unavailable original scanner binding produces explicit unsupported guidance and an
inconclusive verification instead of inventing a positive result.
