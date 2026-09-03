use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const SHA256_LEN: usize = 64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationActionKind {
    ExactTextConfigPatch,
    RepositoryInventoryReview,
    InstalledApplicationUpdate,
    SoftwareUninstall,
    RegistryModification,
    WindowsServiceModification,
    FirewallModification,
    DefenderModification,
    GroupPolicyModification,
    CertificateStoreModification,
    FirmwareOrDriverUpdate,
    RemoteWebConfiguration,
    SecretRotation,
    CredentialRevocation,
    FileDeletionOrQuarantine,
    Unsupported,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationSafetyClass {
    GuidanceOnly,
    ManualChangeVerifiable,
    TestOnlyReversible,
    PolicyBlocked,
    Unsupported,
}

impl RemediationActionKind {
    pub const fn required_safety(self) -> RemediationSafetyClass {
        match self {
            Self::ExactTextConfigPatch => RemediationSafetyClass::TestOnlyReversible,
            Self::RepositoryInventoryReview => RemediationSafetyClass::ManualChangeVerifiable,
            Self::InstalledApplicationUpdate
            | Self::SoftwareUninstall
            | Self::RegistryModification
            | Self::WindowsServiceModification
            | Self::FirewallModification
            | Self::DefenderModification
            | Self::GroupPolicyModification
            | Self::CertificateStoreModification
            | Self::FirmwareOrDriverUpdate
            | Self::RemoteWebConfiguration
            | Self::SecretRotation
            | Self::CredentialRevocation
            | Self::FileDeletionOrQuarantine => RemediationSafetyClass::GuidanceOnly,
            Self::Unsupported => RemediationSafetyClass::Unsupported,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationPrecondition {
    pub canonical_path: String,
    pub stable_identity: String,
    pub expected_sha256: String,
    pub expected_size: u64,
    pub expected_anchor_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExactTextEdit {
    pub anchor_sha256: String,
    pub replacement_sha256: String,
    pub affected_line: u32,
    pub expected_occurrences: u8,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub(crate) expected_text: String,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub(crate) replacement_text: String,
}

impl ExactTextEdit {
    pub fn contract(
        anchor_sha256: String,
        replacement_sha256: String,
        affected_line: u32,
        expected_occurrences: u8,
    ) -> Self {
        Self {
            anchor_sha256,
            replacement_sha256,
            affected_line,
            expected_occurrences,
            expected_text: String::new(),
            replacement_text: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationPlan {
    pub scanner_id: String,
    pub original_fingerprint: String,
    pub required_checks: Vec<String>,
    pub expected_post_sha256: String,
    pub coverage_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_scope: Option<ManualVerificationScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManualVerificationScope {
    pub ecosystem: String,
    pub manifest_paths: Vec<String>,
    pub baseline_material_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackPlan {
    pub eligible: bool,
    pub required_post_sha256: String,
    pub explanation_safe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationAction {
    pub action_id: String,
    pub finding_id: String,
    pub case_id: Option<String>,
    pub target_id: String,
    pub kind: RemediationActionKind,
    pub safety_class: RemediationSafetyClass,
    pub rule_id: String,
    pub rule_version: u32,
    pub explanation_safe: String,
    pub precondition: RemediationPrecondition,
    pub edit: Option<ExactTextEdit>,
    pub verification: VerificationPlan,
    pub rollback: RollbackPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationPlan {
    pub plan_id: String,
    pub plan_sha256: String,
    pub finding_id: String,
    pub case_id: Option<String>,
    pub created_at_utc: String,
    pub actions: Vec<RemediationAction>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationActionState {
    Planned,
    Previewed,
    Authorized,
    Preparing,
    Applying,
    Applied,
    VerificationPending,
    Verified,
    Failed,
    VerificationInconclusive,
    RegressionDetected,
    RollbackAvailable,
    RollingBack,
    RolledBack,
    Cancelled,
    Blocked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationFindingLifecycle {
    Open,
    Investigating,
    Remediating,
    VerificationPending,
    Resolved,
    Reopened,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationCaseLifecycle {
    Open,
    Investigating,
    Remediating,
    VerificationPending,
    Resolved,
}

impl RemediationActionState {
    pub const fn terminal(self) -> bool {
        matches!(self, Self::RolledBack | Self::Cancelled | Self::Blocked)
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        use RemediationActionState as S;
        matches!(
            (self, next),
            (S::Planned, S::Previewed | S::Blocked | S::Cancelled)
                | (S::Previewed, S::Authorized | S::Cancelled | S::Blocked)
                | (S::Authorized, S::Preparing | S::Cancelled | S::Blocked)
                | (S::Preparing, S::Applying | S::Cancelled | S::Failed)
                | (S::Applying, S::Applied | S::Failed)
                | (S::Applied, S::VerificationPending | S::RollbackAvailable)
                | (
                    S::VerificationPending,
                    S::Verified
                        | S::Failed
                        | S::VerificationInconclusive
                        | S::RegressionDetected
                        | S::RollbackAvailable
                        | S::Cancelled
                )
                | (S::Verified, S::RollbackAvailable)
                | (
                    S::Failed | S::VerificationInconclusive | S::RegressionDetected,
                    S::RollbackAvailable
                )
                | (S::RollbackAvailable, S::RollingBack)
                | (S::RollingBack, S::RolledBack | S::Failed)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationAuthorization {
    pub authorization_id: String,
    pub action_id: String,
    pub plan_sha256: String,
    pub canonical_path: String,
    pub stable_identity: String,
    pub expected_sha256: String,
    pub finding_id: String,
    pub case_id: Option<String>,
    pub expires_at_unix: i64,
    pub used: bool,
    pub token_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationPreview {
    pub action_id: String,
    pub plan_sha256: String,
    pub finding_id: String,
    pub target_safe: String,
    pub rule_id: String,
    pub safety_class: RemediationSafetyClass,
    pub current_state_safe: String,
    pub proposed_state_safe: String,
    pub affected_line: Option<u32>,
    pub preconditions_safe: Vec<String>,
    pub expected_effect_safe: String,
    pub verification_plan: VerificationPlan,
    pub rollback_available: bool,
    pub limitations: Vec<String>,
    pub sanitized_unified_diff: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationReceipt {
    pub action_id: String,
    pub plan_sha256: String,
    pub rule_id: String,
    pub rule_version: u32,
    pub target_stable_identity: String,
    pub original_sha256: String,
    #[serde(default)]
    pub original_stable_identity: String,
    pub resulting_sha256: String,
    pub applied_at_utc: String,
    pub state: RemediationActionState,
    pub backup_id: String,
    pub backup_sha256: String,
    pub verification_status: Option<VerificationOutcome>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    Resolved,
    StillPresent,
    Inconclusive,
    RegressionDetected,
    TargetChanged,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationResult {
    pub action_id: String,
    pub outcome: VerificationOutcome,
    pub scanner_id: String,
    pub new_snapshot_id: String,
    pub original_fingerprint_absent: bool,
    pub required_checks_executed: bool,
    pub coverage_sufficient: bool,
    pub target_stable: bool,
    pub contradictory_evidence: bool,
    pub regression_fingerprints: Vec<String>,
    pub completed_at_utc: String,
    pub explanation_safe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackReceipt {
    pub action_id: String,
    pub plan_sha256: String,
    pub restored_sha256: String,
    pub rolled_back_at_utc: String,
    pub state: RemediationActionState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryClassification {
    OriginalPresent,
    PatchedPresent,
    UnknownState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryJournal {
    pub action_id: String,
    pub plan_sha256: String,
    pub target_safe: String,
    #[serde(default)]
    pub repository_root_safe: String,
    pub original_sha256: String,
    #[serde(default)]
    pub original_stable_identity: String,
    pub patched_sha256: String,
    pub backup_id: Option<String>,
    #[serde(default)]
    pub backup_sha256: Option<String>,
    pub state: RemediationActionState,
    pub manual_review_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryInspection {
    pub classification: RecoveryClassification,
    pub backup_integrity: Option<bool>,
    pub manual_review_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuidanceAction {
    pub action_id: String,
    pub finding_id: String,
    pub case_id: Option<String>,
    pub kind: RemediationActionKind,
    pub safety_class: RemediationSafetyClass,
    pub affected_target_safe: String,
    pub guidance_safe: Vec<String>,
    pub verification_steps_safe: Vec<String>,
    pub execution_disclosure: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn deterministic_action_id(action: &RemediationAction) -> Result<String, &'static str> {
    #[derive(Serialize)]
    struct Identity<'a> {
        version: &'static str,
        finding_id: &'a str,
        case_id: &'a Option<String>,
        target_id: &'a str,
        kind: RemediationActionKind,
        expected_state: &'a str,
        proposed_change: &'a Option<ExactTextEdit>,
        rule_id: &'a str,
        rule_version: u32,
    }
    let bytes = serde_json::to_vec(&Identity {
        version: crate::REMEDIATION_ACTION_ID_VERSION,
        finding_id: &action.finding_id,
        case_id: &action.case_id,
        target_id: &action.target_id,
        kind: action.kind,
        expected_state: &action.precondition.expected_sha256,
        proposed_change: &action.edit,
        rule_id: &action.rule_id,
        rule_version: action.rule_version,
    })
    .map_err(|_| "action_serialization_failed")?;
    Ok(format!("rma-v1-{}", sha256_hex(&bytes)))
}

pub fn calculate_plan_sha256(plan: &RemediationPlan) -> Result<String, &'static str> {
    #[derive(Serialize)]
    struct PlanIdentity<'a> {
        plan_id: &'a str,
        finding_id: &'a str,
        case_id: &'a Option<String>,
        actions: &'a [RemediationAction],
    }
    serde_json::to_vec(&PlanIdentity {
        plan_id: &plan.plan_id,
        finding_id: &plan.finding_id,
        case_id: &plan.case_id,
        actions: &plan.actions,
    })
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|_| "plan_serialization_failed")
}

pub fn validate_plan(plan: &RemediationPlan) -> Result<(), &'static str> {
    if plan.actions.is_empty() || plan.actions.len() > 16 || plan.plan_id.len() > 128 {
        return Err("invalid_plan_bounds");
    }
    let mut ids = BTreeSet::new();
    for action in &plan.actions {
        let edit_valid = match (&action.kind, &action.edit) {
            (RemediationActionKind::ExactTextConfigPatch, Some(edit)) => {
                valid_sha256(&edit.anchor_sha256)
                    && valid_sha256(&edit.replacement_sha256)
                    && edit.affected_line > 0
                    && edit.expected_occurrences == 1
            }
            (RemediationActionKind::ExactTextConfigPatch, None) => false,
            (_, None) => true,
            (_, Some(_)) => false,
        };
        if action.safety_class != action.kind.required_safety()
            || action.action_id != deterministic_action_id(action)?
            || !ids.insert(&action.action_id)
            || !edit_valid
            || !valid_sha256(&action.precondition.expected_sha256)
            || !valid_sha256(&action.precondition.expected_anchor_sha256)
            || !valid_sha256(&action.verification.expected_post_sha256)
        {
            return Err("invalid_action_contract");
        }
    }
    if plan.plan_sha256 != calculate_plan_sha256(plan)? {
        return Err("invalid_plan_sha256");
    }
    Ok(())
}

pub fn valid_sha256(value: &str) -> bool {
    value.len() == SHA256_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_kinds_are_never_executable() {
        let guidance = [
            RemediationActionKind::InstalledApplicationUpdate,
            RemediationActionKind::SoftwareUninstall,
            RemediationActionKind::RegistryModification,
            RemediationActionKind::WindowsServiceModification,
            RemediationActionKind::FirewallModification,
            RemediationActionKind::DefenderModification,
            RemediationActionKind::GroupPolicyModification,
            RemediationActionKind::CertificateStoreModification,
            RemediationActionKind::FirmwareOrDriverUpdate,
            RemediationActionKind::RemoteWebConfiguration,
            RemediationActionKind::SecretRotation,
            RemediationActionKind::CredentialRevocation,
            RemediationActionKind::FileDeletionOrQuarantine,
        ];
        assert!(
            guidance
                .into_iter()
                .all(|kind| kind.required_safety() == RemediationSafetyClass::GuidanceOnly)
        );
    }

    #[test]
    fn state_machine_denies_frontend_shortcuts() {
        assert!(
            !RemediationActionState::Planned.can_transition_to(RemediationActionState::Applying)
        );
        assert!(
            !RemediationActionState::Applied.can_transition_to(RemediationActionState::Verified)
        );
        assert!(
            RemediationActionState::VerificationPending
                .can_transition_to(RemediationActionState::Verified)
        );
        assert!(!RemediationActionState::Verified.terminal());
        assert!(RemediationActionState::RolledBack.terminal());
    }
}
