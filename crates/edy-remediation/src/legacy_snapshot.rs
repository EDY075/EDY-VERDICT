//! Read-only legacy schema representation; contains no executor or recovery operation.
use crate::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationSnapshot {
    pub plan: RemediationPlan,
    pub state: RemediationActionState,
    pub finding_lifecycle: RemediationFindingLifecycle,
    pub case_lifecycle: Option<RemediationCaseLifecycle>,
    pub preview: Option<RemediationPreview>,
    pub authorizations: Vec<RemediationAuthorization>,
    pub receipt: Option<RemediationReceipt>,
    pub verification: Option<VerificationResult>,
    pub rollback_receipt: Option<RollbackReceipt>,
    pub journal: Option<RecoveryJournal>,
    pub timeline_safe: Vec<String>,
}
