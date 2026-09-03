use crate::{
    ApplyRequest, ApprovedExactEdit, AuthorizedTextTarget, ExecutorError, GuidanceAction,
    RecoveryClassification, RecoveryJournal, RemediationAction, RemediationActionKind,
    RemediationActionState, RemediationAuthorization, RemediationCaseLifecycle,
    RemediationFindingLifecycle, RemediationPlan, RemediationPrecondition, RemediationPreview,
    RemediationReceipt, RemediationSafetyClass, RollbackPlan, RollbackReceipt, VerificationOutcome,
    VerificationPlan, VerificationResult, apply_exact_edit, calculate_plan_sha256, current_sha256,
    deterministic_action_id, preview_exact_edit, rollback_exact_edit, sha256_hex, validate_plan,
};
#[cfg(any(test, feature = "native-e2e"))]
use crate::{
    EXACT_TEXT_CONFIG_RULE_ID, EXACT_TEXT_CONFIG_RULE_VERSION, ExactTextEdit, authorize_text_target,
};
#[cfg(any(test, feature = "native-e2e"))]
use std::path::Path;
use std::{collections::BTreeMap, path::PathBuf};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const SYNTHETIC_FINDING_LEVEL6: &str = "SYNTHETIC_MISCONFIGURATION_LEVEL6";
pub const SYNTHETIC_REGRESSION_LEVEL6: &str = "NEW_SYNTHETIC_HIGHER_RISK_FINDING";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationGrant {
    pub authorization: RemediationAuthorization,
    pub raw_token: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationObservation {
    pub scanner_id: String,
    pub new_snapshot_id: String,
    pub observed_fingerprints: Vec<String>,
    pub required_checks_executed: bool,
    pub coverage_sufficient: bool,
    pub target_stable: bool,
    pub contradictory_evidence: bool,
    pub scanner_error: bool,
    pub cancelled: bool,
}

use crate::RemediationSnapshot;

#[derive(Debug, Clone)]
struct RuntimeAction {
    snapshot: RemediationSnapshot,
    target: AuthorizedTextTarget,
    edit: ApprovedExactEdit,
    backup_root: PathBuf,
}

#[derive(Debug, Default)]
pub struct RemediationService {
    actions: BTreeMap<String, RuntimeAction>,
}

impl RemediationService {
    pub fn guidance_snapshot(action: GuidanceAction) -> Result<RemediationSnapshot, ServiceError> {
        let has_case = action.case_id.is_some();
        let zero = "0".repeat(64);
        let mut remediation_action = RemediationAction {
            action_id: String::new(),
            finding_id: action.finding_id.clone(),
            case_id: action.case_id.clone(),
            target_id: format!(
                "guidance-target-v1-{}",
                sha256_hex(action.affected_target_safe.as_bytes())
            ),
            kind: action.kind,
            safety_class: action.safety_class,
            rule_id: "STRUCTURED_GUIDANCE_V1".into(),
            rule_version: 1,
            explanation_safe: action.guidance_safe.join(" "),
            precondition: RemediationPrecondition {
                canonical_path: action.affected_target_safe,
                stable_identity: "guidance-only".into(),
                expected_sha256: zero.clone(),
                expected_size: 0,
                expected_anchor_sha256: zero.clone(),
            },
            edit: None,
            verification: VerificationPlan {
                scanner_id: "manual-rescan-required".into(),
                original_fingerprint: action.finding_id.clone(),
                required_checks: action.verification_steps_safe,
                expected_post_sha256: zero.clone(),
                coverage_required: true,
                manual_scope: None,
            },
            rollback: RollbackPlan {
                eligible: false,
                required_post_sha256: zero,
                explanation_safe: "No action was executed by EDY VERDICT.".into(),
            },
        };
        remediation_action.action_id =
            deterministic_action_id(&remediation_action).map_err(|_| ServiceError::Integrity)?;
        let mut plan = RemediationPlan {
            plan_id: uuid::Uuid::now_v7().to_string(),
            plan_sha256: String::new(),
            finding_id: action.finding_id,
            case_id: action.case_id,
            created_at_utc: now_utc()?,
            actions: vec![remediation_action],
        };
        plan.plan_sha256 = calculate_plan_sha256(&plan).map_err(|_| ServiceError::Integrity)?;
        validate_plan(&plan).map_err(|_| ServiceError::Integrity)?;
        Ok(RemediationSnapshot {
            plan,
            state: RemediationActionState::Blocked,
            finding_lifecycle: RemediationFindingLifecycle::Investigating,
            case_lifecycle: has_case.then_some(RemediationCaseLifecycle::Investigating),
            preview: None,
            authorizations: Vec::new(),
            receipt: None,
            verification: None,
            rollback_receipt: None,
            journal: None,
            timeline_safe: vec![
                "guidance_created".into(),
                "not_executed_by_edy_verdict".into(),
            ],
        })
    }

    #[cfg(any(test, feature = "native-e2e"))]
    pub fn create_synthetic_plan(
        &mut self,
        repository_root: &Path,
        finding_id: &str,
        case_id: Option<&str>,
    ) -> Result<RemediationPlan, ServiceError> {
        if finding_id != SYNTHETIC_FINDING_LEVEL6 {
            return Err(ServiceError::RuleUnavailable);
        }
        let target_path = repository_root.join("security-config.toml");
        let target = authorize_text_target(repository_root, &target_path)?;
        let edit = ApprovedExactEdit {
            expected_text: "insecure_test_mode = true".into(),
            replacement_text: "insecure_test_mode = false".into(),
            expected_occurrences: 1,
        };
        let (_, patched, line) = preview_exact_edit(&target, &edit)?;
        let edit_contract = ExactTextEdit {
            anchor_sha256: sha256_hex(edit.expected_text.as_bytes()),
            replacement_sha256: sha256_hex(edit.replacement_text.as_bytes()),
            affected_line: line,
            expected_occurrences: 1,
            expected_text: edit.expected_text.clone(),
            replacement_text: edit.replacement_text.clone(),
        };
        let mut action = RemediationAction {
            action_id: String::new(),
            finding_id: finding_id.into(),
            case_id: case_id.map(str::to_owned),
            target_id: format!(
                "target-v1-{}",
                sha256_hex(target.canonical_path_safe.to_ascii_lowercase().as_bytes())
            ),
            kind: RemediationActionKind::ExactTextConfigPatch,
            safety_class: RemediationSafetyClass::TestOnlyReversible,
            rule_id: EXACT_TEXT_CONFIG_RULE_ID.into(),
            rule_version: EXACT_TEXT_CONFIG_RULE_VERSION,
            explanation_safe:
                "Change the single approved synthetic configuration flag from true to false.".into(),
            precondition: RemediationPrecondition {
                canonical_path: target.canonical_path_safe.clone(),
                stable_identity: target.stable_identity.clone(),
                expected_sha256: target.sha256.clone(),
                expected_size: target.size,
                expected_anchor_sha256: sha256_hex(edit.expected_text.as_bytes()),
            },
            edit: Some(edit_contract),
            verification: VerificationPlan {
                scanner_id: "level6-synthetic-config-scanner-v1".into(),
                original_fingerprint: SYNTHETIC_FINDING_LEVEL6.into(),
                required_checks: vec!["exact_config_rescan".into()],
                expected_post_sha256: sha256_hex(&patched),
                coverage_required: true,
                manual_scope: None,
            },
            rollback: RollbackPlan {
                eligible: true,
                required_post_sha256: sha256_hex(&patched),
                explanation_safe:
                    "Rollback is available only while the target still matches the applied result."
                        .into(),
            },
        };
        action.action_id = deterministic_action_id(&action).map_err(|_| ServiceError::Integrity)?;
        let mut plan = RemediationPlan {
            plan_id: uuid::Uuid::now_v7().to_string(),
            plan_sha256: String::new(),
            finding_id: finding_id.into(),
            case_id: case_id.map(str::to_owned),
            created_at_utc: now_utc()?,
            actions: vec![action.clone()],
        };
        plan.plan_sha256 = calculate_plan_sha256(&plan).map_err(|_| ServiceError::Integrity)?;
        validate_plan(&plan).map_err(|_| ServiceError::Integrity)?;
        let snapshot = RemediationSnapshot {
            plan: plan.clone(),
            state: RemediationActionState::Planned,
            finding_lifecycle: RemediationFindingLifecycle::Investigating,
            case_lifecycle: case_id.map(|_| RemediationCaseLifecycle::Investigating),
            preview: None,
            authorizations: Vec::new(),
            receipt: None,
            verification: None,
            rollback_receipt: None,
            journal: None,
            timeline_safe: vec!["plan_created".into()],
        };
        let backup_root = target
            .repository_root
            .join(".local")
            .join("remediation-backups");
        self.actions.insert(
            action.action_id.clone(),
            RuntimeAction {
                snapshot,
                target,
                edit,
                backup_root,
            },
        );
        Ok(plan)
    }

    pub fn guidance(
        finding_id: &str,
        case_id: Option<&str>,
        kind: RemediationActionKind,
        affected_target_safe: &str,
        guidance_safe: Vec<String>,
        verification_steps_safe: Vec<String>,
    ) -> Result<GuidanceAction, ServiceError> {
        if kind.required_safety() != RemediationSafetyClass::GuidanceOnly
            || affected_target_safe.len() > 512
            || guidance_safe.is_empty()
            || guidance_safe.len() > 16
            || verification_steps_safe.is_empty()
            || verification_steps_safe.len() > 16
            || guidance_safe
                .iter()
                .chain(&verification_steps_safe)
                .any(|value| value.len() > 1024 || value.chars().any(char::is_control))
        {
            return Err(ServiceError::InvalidRequest);
        }
        let identity = serde_json::to_vec(&(finding_id, case_id, kind, affected_target_safe))
            .map_err(|_| ServiceError::Integrity)?;
        Ok(GuidanceAction {
            action_id: format!("rma-v1-{}", sha256_hex(&identity)),
            finding_id: finding_id.into(),
            case_id: case_id.map(str::to_owned),
            kind,
            safety_class: RemediationSafetyClass::GuidanceOnly,
            affected_target_safe: affected_target_safe.into(),
            guidance_safe,
            verification_steps_safe,
            execution_disclosure: "NOT EXECUTED BY EDY VERDICT".into(),
        })
    }

    pub fn preview(&mut self, action_id: &str) -> Result<RemediationPreview, ServiceError> {
        let runtime = self.action_mut(action_id)?;
        transition(
            &mut runtime.snapshot,
            RemediationActionState::Previewed,
            "previewed",
        )?;
        let action = &runtime.snapshot.plan.actions[0];
        let (diff, _, line) = preview_exact_edit(&runtime.target, &runtime.edit)?;
        let preview = RemediationPreview {
            action_id: action.action_id.clone(),
            plan_sha256: runtime.snapshot.plan.plan_sha256.clone(),
            finding_id: action.finding_id.clone(),
            target_safe: action.precondition.canonical_path.clone(),
            rule_id: action.rule_id.clone(),
            safety_class: action.safety_class,
            current_state_safe:
                "insecure_test_mode is enabled in the authorized synthetic configuration".into(),
            proposed_state_safe:
                "insecure_test_mode is disabled in the authorized synthetic configuration".into(),
            affected_line: Some(line),
            preconditions_safe: vec![
                "Canonical local repository file is unchanged".into(),
                "Expected SHA-256 and stable identity match".into(),
            ],
            expected_effect_safe:
                "The original synthetic finding should be absent on a fresh rescan.".into(),
            verification_plan: action.verification.clone(),
            rollback_available: action.rollback.eligible,
            limitations: vec![
                "Verification covers only the checks shown.".into(),
                "Remediation is not proof that the target is safe.".into(),
            ],
            sanitized_unified_diff: Some(diff),
        };
        runtime.snapshot.preview = Some(preview.clone());
        Ok(preview)
    }

    pub fn authorize(
        &mut self,
        action_id: &str,
        plan_sha256: &str,
        ttl_seconds: i64,
    ) -> Result<AuthorizationGrant, ServiceError> {
        if !(1..=900).contains(&ttl_seconds) {
            return Err(ServiceError::InvalidRequest);
        }
        let runtime = self.action_mut(action_id)?;
        if runtime.snapshot.state != RemediationActionState::Previewed
            || runtime.snapshot.plan.plan_sha256 != plan_sha256
        {
            return Err(ServiceError::AuthorizationDenied);
        }
        let action = &runtime.snapshot.plan.actions[0];
        let raw_token = format!(
            "{}{}",
            uuid::Uuid::now_v7().simple(),
            uuid::Uuid::now_v7().simple()
        );
        let authorization = RemediationAuthorization {
            authorization_id: uuid::Uuid::now_v7().to_string(),
            action_id: action_id.into(),
            plan_sha256: plan_sha256.into(),
            canonical_path: action.precondition.canonical_path.clone(),
            stable_identity: action.precondition.stable_identity.clone(),
            expected_sha256: action.precondition.expected_sha256.clone(),
            finding_id: action.finding_id.clone(),
            case_id: action.case_id.clone(),
            expires_at_unix: OffsetDateTime::now_utc().unix_timestamp() + ttl_seconds,
            used: false,
            token_sha256: sha256_hex(raw_token.as_bytes()),
        };
        runtime.snapshot.authorizations.push(authorization.clone());
        transition(
            &mut runtime.snapshot,
            RemediationActionState::Authorized,
            "authorized",
        )?;
        runtime.snapshot.finding_lifecycle = RemediationFindingLifecycle::Remediating;
        if runtime.snapshot.case_lifecycle.is_some() {
            runtime.snapshot.case_lifecycle = Some(RemediationCaseLifecycle::Remediating);
        }
        Ok(AuthorizationGrant {
            authorization,
            raw_token,
        })
    }

    pub fn apply(
        &mut self,
        action_id: &str,
        raw_token: &str,
    ) -> Result<RemediationReceipt, ServiceError> {
        self.apply_with_journal(action_id, raw_token, |_| Ok(()))
    }

    pub fn apply_with_journal<F>(
        &mut self,
        action_id: &str,
        raw_token: &str,
        mut persist: F,
    ) -> Result<RemediationReceipt, ServiceError>
    where
        F: FnMut(&RemediationSnapshot) -> Result<(), ServiceError>,
    {
        let runtime = self.action_mut(action_id)?;
        if runtime.snapshot.state != RemediationActionState::Authorized {
            return Err(ServiceError::AuthorizationDenied);
        }
        let plan_sha = runtime.snapshot.plan.plan_sha256.clone();
        validate_plan(&runtime.snapshot.plan).map_err(|_| ServiceError::AuthorizationDenied)?;
        let token_hash = sha256_hex(raw_token.as_bytes());
        let authorization = runtime
            .snapshot
            .authorizations
            .iter_mut()
            .find(|item| {
                item.action_id == action_id
                    && item.plan_sha256 == plan_sha
                    && !item.used
                    && item.token_sha256 == token_hash
            })
            .ok_or(ServiceError::AuthorizationDenied)?;
        let action = runtime
            .snapshot
            .plan
            .actions
            .first()
            .ok_or(ServiceError::Integrity)?
            .clone();
        if authorization.expires_at_unix < OffsetDateTime::now_utc().unix_timestamp()
            || authorization.canonical_path != action.precondition.canonical_path
            || authorization.stable_identity != action.precondition.stable_identity
            || authorization.expected_sha256 != action.precondition.expected_sha256
            || authorization.finding_id != action.finding_id
            || authorization.case_id != action.case_id
        {
            authorization.used = true;
            return Err(ServiceError::AuthorizationDenied);
        }
        // Consume before any write. A failed or interrupted attempt cannot replay the authority.
        authorization.used = true;
        let backup_id = format!("backup-{}", uuid::Uuid::now_v7());
        transition(
            &mut runtime.snapshot,
            RemediationActionState::Preparing,
            "action_prepared",
        )?;
        runtime.snapshot.journal = Some(RecoveryJournal {
            action_id: action_id.into(),
            plan_sha256: plan_sha.clone(),
            target_safe: action.precondition.canonical_path.clone(),
            repository_root_safe: runtime
                .target
                .repository_root
                .to_string_lossy()
                .replace('\\', "/"),
            original_sha256: action.precondition.expected_sha256.clone(),
            original_stable_identity: action.precondition.stable_identity.clone(),
            patched_sha256: action.verification.expected_post_sha256.clone(),
            backup_id: Some(backup_id.clone()),
            backup_sha256: Some(action.precondition.expected_sha256.clone()),
            state: RemediationActionState::Preparing,
            manual_review_required: false,
        });
        persist(&runtime.snapshot)?;
        transition(
            &mut runtime.snapshot,
            RemediationActionState::Applying,
            "applying",
        )?;
        if let Some(journal) = &mut runtime.snapshot.journal {
            journal.state = RemediationActionState::Applying;
        }
        persist(&runtime.snapshot)?;
        let applied = match apply_exact_edit(&ApplyRequest {
            action_id,
            plan_sha256: &plan_sha,
            target: &runtime.target,
            precondition: &action.precondition,
            edit: &runtime.edit,
            backup_root: &runtime.backup_root,
            backup_id: &backup_id,
        }) {
            Ok(value) => value,
            Err(error) => {
                transition(
                    &mut runtime.snapshot,
                    RemediationActionState::Failed,
                    error.code(),
                )?;
                runtime.snapshot.finding_lifecycle = RemediationFindingLifecycle::Investigating;
                if runtime.snapshot.case_lifecycle.is_some() {
                    runtime.snapshot.case_lifecycle = Some(RemediationCaseLifecycle::Investigating);
                }
                persist(&runtime.snapshot)?;
                return Err(ServiceError::Executor(error));
            }
        };
        transition(
            &mut runtime.snapshot,
            RemediationActionState::Applied,
            "applied",
        )?;
        if let Some(journal) = &mut runtime.snapshot.journal {
            journal.state = RemediationActionState::Applied;
            journal.backup_id = Some(applied.backup_id.clone());
            journal.backup_sha256 = Some(applied.backup_sha256.clone());
        }
        let receipt = RemediationReceipt {
            action_id: action_id.into(),
            plan_sha256: plan_sha,
            rule_id: action.rule_id,
            rule_version: action.rule_version,
            target_stable_identity: applied.resulting_stable_identity,
            original_sha256: applied.original_sha256,
            original_stable_identity: action.precondition.stable_identity.clone(),
            resulting_sha256: applied.resulting_sha256,
            applied_at_utc: now_utc()?,
            state: RemediationActionState::Applied,
            backup_id: applied.backup_id,
            backup_sha256: applied.backup_sha256,
            verification_status: None,
        };
        runtime.snapshot.receipt = Some(receipt.clone());
        transition(
            &mut runtime.snapshot,
            RemediationActionState::VerificationPending,
            "verification_pending",
        )?;
        runtime.snapshot.finding_lifecycle = RemediationFindingLifecycle::VerificationPending;
        if runtime.snapshot.case_lifecycle.is_some() {
            runtime.snapshot.case_lifecycle = Some(RemediationCaseLifecycle::VerificationPending);
        }
        persist(&runtime.snapshot)?;
        Ok(receipt)
    }

    /// Reacquire a bounded, canonical snapshot and compare it with the apply
    /// receipt. Scanner booleans cannot substitute for this filesystem check.
    pub fn verification_target_stable(&self, action_id: &str) -> Result<bool, ServiceError> {
        let runtime = self.action(action_id)?;
        let receipt = runtime
            .snapshot
            .receipt
            .as_ref()
            .ok_or(ServiceError::Integrity)?;
        Ok(crate::authorize_text_target(
            &runtime.target.repository_root,
            &runtime.target.canonical_path,
        )
        .is_ok_and(|current| {
            current.canonical_path == runtime.target.canonical_path
                && current.sha256 == receipt.resulting_sha256
                && current.stable_identity == receipt.target_stable_identity
        }))
    }

    pub fn verify(
        &mut self,
        action_id: &str,
        observation: VerificationObservation,
    ) -> Result<VerificationResult, ServiceError> {
        let target_stable =
            observation.target_stable && self.verification_target_stable(action_id)?;
        let runtime = self.action_mut(action_id)?;
        if runtime.snapshot.state != RemediationActionState::VerificationPending {
            return Err(ServiceError::InvalidTransition);
        }
        let action = runtime
            .snapshot
            .plan
            .actions
            .first()
            .ok_or(ServiceError::Integrity)?;
        let original_absent = !observation
            .observed_fingerprints
            .iter()
            .any(|value| value == &action.verification.original_fingerprint);
        let regression = observation
            .observed_fingerprints
            .iter()
            .filter(|value| *value != &action.verification.original_fingerprint)
            .cloned()
            .collect::<Vec<_>>();
        let outcome = if observation.cancelled {
            VerificationOutcome::Cancelled
        } else if observation.scanner_error
            || observation.scanner_id != action.verification.scanner_id
            || !observation.required_checks_executed
            || !observation.coverage_sufficient
        {
            VerificationOutcome::Inconclusive
        } else if !target_stable {
            VerificationOutcome::TargetChanged
        } else if !regression.is_empty() || observation.contradictory_evidence {
            VerificationOutcome::RegressionDetected
        } else if !original_absent {
            VerificationOutcome::StillPresent
        } else {
            VerificationOutcome::Resolved
        };
        let next = match outcome {
            VerificationOutcome::Resolved => RemediationActionState::Verified,
            VerificationOutcome::StillPresent | VerificationOutcome::TargetChanged => {
                RemediationActionState::Failed
            }
            VerificationOutcome::Inconclusive => RemediationActionState::VerificationInconclusive,
            VerificationOutcome::RegressionDetected => RemediationActionState::RegressionDetected,
            VerificationOutcome::Cancelled => RemediationActionState::Cancelled,
        };
        if outcome == VerificationOutcome::Cancelled {
            runtime
                .snapshot
                .timeline_safe
                .push("verification_cancelled_after_apply".into());
        } else {
            transition(&mut runtime.snapshot, next, "verification_completed")?;
        }
        let result = VerificationResult {
            action_id: action_id.into(),
            outcome,
            scanner_id: observation.scanner_id,
            new_snapshot_id: observation.new_snapshot_id,
            original_fingerprint_absent: original_absent,
            required_checks_executed: observation.required_checks_executed,
            coverage_sufficient: observation.coverage_sufficient,
            target_stable,
            contradictory_evidence: observation.contradictory_evidence,
            regression_fingerprints: regression,
            completed_at_utc: now_utc()?,
            explanation_safe: verification_explanation(outcome).into(),
        };
        if let Some(receipt) = &mut runtime.snapshot.receipt {
            receipt.verification_status = Some(outcome);
        }
        runtime.snapshot.verification = Some(result.clone());
        if outcome == VerificationOutcome::Resolved {
            runtime.snapshot.finding_lifecycle = RemediationFindingLifecycle::Resolved;
            if runtime.snapshot.case_lifecycle.is_some() {
                // This action cannot establish that every required case member
                // was resolved. Keep the aggregate case open until Level 5's
                // membership-aware resolution policy has sufficient evidence.
                runtime.snapshot.case_lifecycle = Some(RemediationCaseLifecycle::Investigating);
                runtime
                    .snapshot
                    .timeline_safe
                    .push("case_resolution_requires_all_members".into());
            }
        } else {
            runtime.snapshot.finding_lifecycle = RemediationFindingLifecycle::Investigating;
            if runtime.snapshot.case_lifecycle.is_some() {
                runtime.snapshot.case_lifecycle = Some(RemediationCaseLifecycle::Investigating);
            }
        }
        Ok(result)
    }

    pub fn cancel_before_write(&mut self, action_id: &str) -> Result<(), ServiceError> {
        let runtime = self.action_mut(action_id)?;
        if !matches!(
            runtime.snapshot.state,
            RemediationActionState::Planned
                | RemediationActionState::Previewed
                | RemediationActionState::Authorized
                | RemediationActionState::Preparing
        ) {
            return Err(ServiceError::InvalidTransition);
        }
        for authorization in &mut runtime.snapshot.authorizations {
            authorization.used = true;
        }
        transition(
            &mut runtime.snapshot,
            RemediationActionState::Cancelled,
            "cancelled_before_write",
        )
    }

    pub fn cancel_verification(
        &mut self,
        action_id: &str,
    ) -> Result<VerificationResult, ServiceError> {
        let scanner = self.action(action_id)?.snapshot.plan.actions[0]
            .verification
            .scanner_id
            .clone();
        self.verify(
            action_id,
            VerificationObservation {
                scanner_id: scanner,
                new_snapshot_id: uuid::Uuid::now_v7().to_string(),
                observed_fingerprints: Vec::new(),
                required_checks_executed: false,
                coverage_sufficient: false,
                target_stable: true,
                contradictory_evidence: false,
                scanner_error: false,
                cancelled: true,
            },
        )
    }

    pub fn rollback(&mut self, action_id: &str) -> Result<RollbackReceipt, ServiceError> {
        self.rollback_with_journal(action_id, |_| Ok(()))
    }

    pub fn rollback_with_journal<F>(
        &mut self,
        action_id: &str,
        mut persist: F,
    ) -> Result<RollbackReceipt, ServiceError>
    where
        F: FnMut(&RemediationSnapshot) -> Result<(), ServiceError>,
    {
        let runtime = self.action_mut(action_id)?;
        let verification_cancelled = runtime
            .snapshot
            .verification
            .as_ref()
            .is_some_and(|value| value.outcome == VerificationOutcome::Cancelled);
        if !runtime.snapshot.plan.actions[0].rollback.eligible
            || !matches!(
                runtime.snapshot.state,
                RemediationActionState::Verified
                    | RemediationActionState::Failed
                    | RemediationActionState::VerificationInconclusive
                    | RemediationActionState::RegressionDetected
                    | RemediationActionState::RollbackAvailable
            ) && !(runtime.snapshot.state == RemediationActionState::VerificationPending
                && verification_cancelled)
        {
            return Err(ServiceError::InvalidTransition);
        }
        let receipt = runtime
            .snapshot
            .receipt
            .clone()
            .ok_or(ServiceError::Integrity)?;
        let plan_sha = runtime.snapshot.plan.plan_sha256.clone();
        if runtime.snapshot.state != RemediationActionState::RollbackAvailable {
            transition(
                &mut runtime.snapshot,
                RemediationActionState::RollbackAvailable,
                "rollback_available",
            )?;
        }
        transition(
            &mut runtime.snapshot,
            RemediationActionState::RollingBack,
            "rolling_back",
        )?;
        if let Some(journal) = &mut runtime.snapshot.journal {
            journal.state = RemediationActionState::RollingBack;
        }
        persist(&runtime.snapshot)?;
        let restored = match rollback_exact_edit(&crate::RollbackRequest {
            action_id,
            expected_action_id: &receipt.action_id,
            expected_plan_sha256: &receipt.plan_sha256,
            target: &runtime.target.canonical_path,
            expected_original_stable_identity: &receipt.original_stable_identity,
            expected_original_sha256: &receipt.original_sha256,
            expected_patched_stable_identity: &receipt.target_stable_identity,
            expected_patched_sha256: &receipt.resulting_sha256,
            backup_root: &runtime.backup_root,
            backup_id: &receipt.backup_id,
            expected_backup_sha256: &receipt.backup_sha256,
        }) {
            Ok(value) => value,
            Err(error) => {
                transition(
                    &mut runtime.snapshot,
                    RemediationActionState::Failed,
                    error.code(),
                )?;
                persist(&runtime.snapshot)?;
                return Err(ServiceError::Executor(error));
            }
        };
        if restored != receipt.original_sha256 {
            return Err(ServiceError::Integrity);
        }
        transition(
            &mut runtime.snapshot,
            RemediationActionState::RolledBack,
            "rolled_back_finding_reopened",
        )?;
        if let Some(journal) = &mut runtime.snapshot.journal {
            journal.state = RemediationActionState::RolledBack;
        }
        let rollback = RollbackReceipt {
            action_id: action_id.into(),
            plan_sha256: plan_sha,
            restored_sha256: restored,
            rolled_back_at_utc: now_utc()?,
            state: RemediationActionState::RolledBack,
        };
        runtime.snapshot.rollback_receipt = Some(rollback.clone());
        runtime.snapshot.finding_lifecycle = RemediationFindingLifecycle::Reopened;
        if runtime.snapshot.case_lifecycle.is_some() {
            runtime.snapshot.case_lifecycle = Some(RemediationCaseLifecycle::Open);
        }
        persist(&runtime.snapshot)?;
        Ok(rollback)
    }

    pub fn record_rollback_rescan(
        &mut self,
        action_id: &str,
        original_fingerprint_present: bool,
        required_checks_executed: bool,
    ) -> Result<(), ServiceError> {
        let runtime = self.action_mut(action_id)?;
        if runtime.snapshot.state != RemediationActionState::RolledBack {
            return Err(ServiceError::InvalidTransition);
        }
        let marker = if original_fingerprint_present && required_checks_executed {
            "rollback_rescan_original_finding_present"
        } else {
            "rollback_rescan_inconclusive"
        };
        runtime.snapshot.timeline_safe.push(marker.into());
        Ok(())
    }

    pub fn recover(&mut self, action_id: &str) -> Result<RecoveryClassification, ServiceError> {
        let runtime = self.action_mut(action_id)?;
        if !matches!(
            runtime.snapshot.state,
            RemediationActionState::Preparing
                | RemediationActionState::Applying
                | RemediationActionState::Applied
                | RemediationActionState::RollingBack
        ) {
            return Err(ServiceError::InvalidTransition);
        }
        let journal = runtime
            .snapshot
            .journal
            .as_mut()
            .ok_or(ServiceError::Integrity)?;
        let hash = current_sha256(&runtime.target.canonical_path).ok();
        let classification = match hash.as_deref() {
            Some(value) if value == journal.original_sha256 => {
                RecoveryClassification::OriginalPresent
            }
            Some(value) if value == journal.patched_sha256 => {
                RecoveryClassification::PatchedPresent
            }
            _ => RecoveryClassification::UnknownState,
        };
        journal.manual_review_required = classification == RecoveryClassification::UnknownState;
        Ok(classification)
    }

    pub fn snapshot(&self, action_id: &str) -> Result<RemediationSnapshot, ServiceError> {
        Ok(self.action(action_id)?.snapshot.clone())
    }

    pub fn list_snapshots(&self) -> Vec<RemediationSnapshot> {
        self.actions
            .values()
            .map(|value| value.snapshot.clone())
            .collect()
    }

    fn action(&self, action_id: &str) -> Result<&RuntimeAction, ServiceError> {
        self.actions.get(action_id).ok_or(ServiceError::NotFound)
    }
    fn action_mut(&mut self, action_id: &str) -> Result<&mut RuntimeAction, ServiceError> {
        self.actions
            .get_mut(action_id)
            .ok_or(ServiceError::NotFound)
    }
}

#[derive(Debug)]
pub enum ServiceError {
    InvalidRequest,
    RuleUnavailable,
    AuthorizationDenied,
    InvalidTransition,
    Integrity,
    NotFound,
    Executor(ExecutorError),
    Time,
}
impl From<ExecutorError> for ServiceError {
    fn from(value: ExecutorError) -> Self {
        Self::Executor(value)
    }
}
impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid_remediation_request",
            Self::RuleUnavailable => "approved_remediation_rule_unavailable",
            Self::AuthorizationDenied => "remediation_authorization_denied",
            Self::InvalidTransition => "remediation_transition_denied",
            Self::Integrity => "remediation_integrity_failed",
            Self::NotFound => "remediation_action_not_found",
            Self::Executor(error) => error.code(),
            Self::Time => "remediation_time_unavailable",
        })
    }
}
impl std::error::Error for ServiceError {}

fn transition(
    snapshot: &mut RemediationSnapshot,
    next: RemediationActionState,
    event: &str,
) -> Result<(), ServiceError> {
    if !snapshot.state.can_transition_to(next) {
        return Err(ServiceError::InvalidTransition);
    }
    snapshot.state = next;
    if snapshot.timeline_safe.len() >= 128 {
        return Err(ServiceError::Integrity);
    }
    snapshot.timeline_safe.push(event.into());
    Ok(())
}

fn now_utc() -> Result<String, ServiceError> {
    OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|_| ServiceError::Time)?
        .format(&Rfc3339)
        .map_err(|_| ServiceError::Time)
}

fn verification_explanation(outcome: VerificationOutcome) -> &'static str {
    match outcome {
        VerificationOutcome::Resolved => "Verification passed for the checks shown.",
        VerificationOutcome::StillPresent => {
            "The original finding remains present after the rescan."
        }
        VerificationOutcome::Inconclusive => {
            "Required verification was unavailable or incomplete; no resolution was claimed."
        }
        VerificationOutcome::RegressionDetected => {
            "New materially adverse evidence was observed; rollback is available when safe."
        }
        VerificationOutcome::TargetChanged => {
            "The target changed during verification; no resolution was claimed."
        }
        VerificationOutcome::Cancelled => {
            "Verification was cancelled after apply; the patched file remains and may be verified or rolled back."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture(label: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "edy-level6-service-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("security-config.toml");
        fs::write(&target, "[security]\ninsecure_test_mode = true\n").unwrap();
        (root, target)
    }
    fn observation(scanner: &str, findings: Vec<&str>) -> VerificationObservation {
        VerificationObservation {
            scanner_id: scanner.into(),
            new_snapshot_id: uuid::Uuid::now_v7().to_string(),
            observed_fingerprints: findings.into_iter().map(str::to_owned).collect(),
            required_checks_executed: true,
            coverage_sufficient: true,
            target_stable: true,
            contradictory_evidence: false,
            scanner_error: false,
            cancelled: false,
        }
    }

    #[test]
    fn happy_path_single_use_and_rollback_are_real() {
        let (root, target) = fixture("happy");
        let original = fs::read(&target).unwrap();
        let original_hash = sha256_hex(&original);
        let mut service = RemediationService::default();
        let plan = service
            .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, Some("case-v1-test"))
            .unwrap();
        let action = plan.actions[0].action_id.clone();
        let preview = service.preview(&action).unwrap();
        assert!(preview.sanitized_unified_diff.unwrap().contains("false"));
        let grant = service.authorize(&action, &plan.plan_sha256, 300).unwrap();
        let receipt = service.apply(&action, &grant.raw_token).unwrap();
        assert_ne!(receipt.original_sha256, receipt.resulting_sha256);
        assert_eq!(
            service
                .apply(&action, &grant.raw_token)
                .unwrap_err()
                .to_string(),
            "remediation_authorization_denied"
        );
        let scanner = plan.actions[0].verification.scanner_id.clone();
        assert_eq!(
            service
                .verify(&action, observation(&scanner, vec![]))
                .unwrap()
                .outcome,
            VerificationOutcome::Resolved
        );
        service.rollback(&action).unwrap();
        service.record_rollback_rescan(&action, true, true).unwrap();
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(current_sha256(&target).unwrap(), original_hash);
        assert_eq!(
            service
                .snapshot(&action)
                .unwrap()
                .timeline_safe
                .last()
                .unwrap(),
            "rollback_rescan_original_finding_present"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn target_change_produces_zero_remediation_writes_and_consumes_authorization() {
        let (root, target) = fixture("changed");
        let mut service = RemediationService::default();
        let plan = service
            .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, None)
            .unwrap();
        let action = plan.actions[0].action_id.clone();
        service.preview(&action).unwrap();
        let grant = service.authorize(&action, &plan.plan_sha256, 300).unwrap();
        fs::write(&target, "user_change = true\n").unwrap();
        let before = fs::read(&target).unwrap();
        assert!(matches!(
            service.apply(&action, &grant.raw_token),
            Err(ServiceError::Executor(ExecutorError::TargetChanged))
        ));
        assert_eq!(fs::read(&target).unwrap(), before);
        assert!(matches!(
            service.apply(&action, &grant.raw_token),
            Err(ServiceError::AuthorizationDenied)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verification_failure_matrix_never_resolves() {
        for (label, mutate, expected) in [
            ("still", 0, VerificationOutcome::StillPresent),
            ("scanner", 1, VerificationOutcome::Inconclusive),
            ("coverage", 2, VerificationOutcome::Inconclusive),
            ("changed", 3, VerificationOutcome::TargetChanged),
            ("regression", 4, VerificationOutcome::RegressionDetected),
            ("cancel", 5, VerificationOutcome::Cancelled),
        ] {
            let (root, _) = fixture(label);
            let mut service = RemediationService::default();
            let plan = service
                .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, None)
                .unwrap();
            let action = plan.actions[0].action_id.clone();
            service.preview(&action).unwrap();
            let grant = service.authorize(&action, &plan.plan_sha256, 300).unwrap();
            service.apply(&action, &grant.raw_token).unwrap();
            let scanner = plan.actions[0].verification.scanner_id.clone();
            let mut value = observation(&scanner, vec![]);
            match mutate {
                0 => value
                    .observed_fingerprints
                    .push(SYNTHETIC_FINDING_LEVEL6.into()),
                1 => value.scanner_error = true,
                2 => value.coverage_sufficient = false,
                3 => value.target_stable = false,
                4 => value
                    .observed_fingerprints
                    .push(SYNTHETIC_REGRESSION_LEVEL6.into()),
                5 => value.cancelled = true,
                _ => unreachable!(),
            }
            assert_eq!(service.verify(&action, value).unwrap().outcome, expected);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn verification_reacquires_target_and_does_not_resolve_the_whole_case() {
        for replace_identity in [false, true] {
            let (root, target) = fixture("verification-revalidation");
            let mut service = RemediationService::default();
            let plan = service
                .create_synthetic_plan(
                    &root,
                    SYNTHETIC_FINDING_LEVEL6,
                    Some("case-with-other-members"),
                )
                .unwrap();
            let action = &plan.actions[0];
            service.preview(&action.action_id).unwrap();
            let grant = service
                .authorize(&action.action_id, &plan.plan_sha256, 300)
                .unwrap();
            service.apply(&action.action_id, &grant.raw_token).unwrap();
            if replace_identity {
                let bytes = fs::read(&target).unwrap();
                fs::rename(&target, root.join("displaced.toml")).unwrap();
                fs::write(&target, bytes).unwrap();
            } else {
                fs::write(&target, "external_change = true\n").unwrap();
            }
            let before = fs::read(&target).unwrap();
            let result = service
                .verify(
                    &action.action_id,
                    observation(&action.verification.scanner_id, vec![]),
                )
                .unwrap();
            assert_eq!(result.outcome, VerificationOutcome::TargetChanged);
            assert!(!result.target_stable);
            assert_ne!(
                service.snapshot(&action.action_id).unwrap().case_lifecycle,
                Some(RemediationCaseLifecycle::Resolved)
            );
            assert_eq!(fs::read(&target).unwrap(), before);
            fs::remove_dir_all(root).unwrap();
        }
        let (root, _) = fixture("case-member-policy");
        let mut service = RemediationService::default();
        let plan = service
            .create_synthetic_plan(
                &root,
                SYNTHETIC_FINDING_LEVEL6,
                Some("case-with-other-members"),
            )
            .unwrap();
        let action = &plan.actions[0];
        service.preview(&action.action_id).unwrap();
        let grant = service
            .authorize(&action.action_id, &plan.plan_sha256, 300)
            .unwrap();
        service.apply(&action.action_id, &grant.raw_token).unwrap();
        assert_eq!(
            service
                .verify(
                    &action.action_id,
                    observation(&action.verification.scanner_id, vec![])
                )
                .unwrap()
                .outcome,
            VerificationOutcome::Resolved
        );
        assert_eq!(
            service.snapshot(&action.action_id).unwrap().case_lifecycle,
            Some(RemediationCaseLifecycle::Investigating)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn forged_plan_hash_cross_binding_and_cancel_before_write_are_denied() {
        let (root, target) = fixture("auth");
        let mut service = RemediationService::default();
        let plan = service
            .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, Some("case-a"))
            .unwrap();
        let action = plan.actions[0].action_id.clone();
        service.preview(&action).unwrap();
        assert!(matches!(
            service.authorize(&action, &"0".repeat(64), 300),
            Err(ServiceError::AuthorizationDenied)
        ));
        let before = fs::read(&target).unwrap();
        service.cancel_before_write(&action).unwrap();
        assert_eq!(fs::read(&target).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn guidance_is_structured_and_never_executable() {
        let action = RemediationService::guidance(
            "finding",
            None,
            RemediationActionKind::InstalledApplicationUpdate,
            "Synthetic App 1.0",
            vec!["Investigate the vendor update.".into()],
            vec!["Rescan the installed application inventory.".into()],
        )
        .unwrap();
        assert_eq!(action.safety_class, RemediationSafetyClass::GuidanceOnly);
        assert_eq!(action.execution_disclosure, "NOT EXECUTED BY EDY VERDICT");
    }

    #[test]
    fn authorization_is_bound_to_plan_case_target_expiry_and_single_use() {
        let (root, _) = fixture("bindings");
        let mut service = RemediationService::default();
        let plan = service
            .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, Some("case-a"))
            .unwrap();
        let action = plan.actions[0].action_id.clone();
        service.preview(&action).unwrap();
        let grant = service.authorize(&action, &plan.plan_sha256, 300).unwrap();
        let runtime = service.actions.get_mut(&action).unwrap();
        runtime.snapshot.authorizations[0].case_id = Some("case-forged".into());
        assert!(matches!(
            service.apply(&action, &grant.raw_token),
            Err(ServiceError::AuthorizationDenied)
        ));
        assert_eq!(
            fs::read_to_string(root.join("security-config.toml")).unwrap(),
            "[security]\ninsecure_test_mode = true\n"
        );
        fs::remove_dir_all(root).unwrap();

        let (root, _) = fixture("expiry");
        let mut service = RemediationService::default();
        let plan = service
            .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, None)
            .unwrap();
        let action = plan.actions[0].action_id.clone();
        service.preview(&action).unwrap();
        let grant = service.authorize(&action, &plan.plan_sha256, 300).unwrap();
        service
            .actions
            .get_mut(&action)
            .unwrap()
            .snapshot
            .authorizations[0]
            .expires_at_unix = 0;
        assert!(matches!(
            service.apply(&action, &grant.raw_token),
            Err(ServiceError::AuthorizationDenied)
        ));
        fs::remove_dir_all(root).unwrap();

        let (root, target) = fixture("plan-change");
        let mut service = RemediationService::default();
        let plan = service
            .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, None)
            .unwrap();
        let action = plan.actions[0].action_id.clone();
        service.preview(&action).unwrap();
        let grant = service.authorize(&action, &plan.plan_sha256, 300).unwrap();
        service
            .actions
            .get_mut(&action)
            .unwrap()
            .snapshot
            .plan
            .actions[0]
            .explanation_safe
            .push_str(" changed");
        let before = fs::read(&target).unwrap();
        assert!(matches!(
            service.apply(&action, &grant.raw_token),
            Err(ServiceError::AuthorizationDenied)
        ));
        assert_eq!(fs::read(&target).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_after_apply_preserves_patch_and_never_resolves() {
        let (root, target) = fixture("cancel-after");
        let mut service = RemediationService::default();
        let plan = service
            .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, None)
            .unwrap();
        let action = plan.actions[0].action_id.clone();
        service.preview(&action).unwrap();
        let grant = service.authorize(&action, &plan.plan_sha256, 300).unwrap();
        service.apply(&action, &grant.raw_token).unwrap();
        let result = service.cancel_verification(&action).unwrap();
        assert_eq!(result.outcome, VerificationOutcome::Cancelled);
        assert!(fs::read_to_string(&target).unwrap().contains("false"));
        assert_ne!(
            service.snapshot(&action).unwrap().finding_lifecycle,
            RemediationFindingLifecycle::Resolved
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_classification_never_writes_unknown_state() {
        for (label, state, bytes, expected) in [
            (
                "preparing",
                RemediationActionState::Preparing,
                "[security]\ninsecure_test_mode = true\n",
                RecoveryClassification::OriginalPresent,
            ),
            (
                "applying",
                RemediationActionState::Applying,
                "[security]\ninsecure_test_mode = false\n",
                RecoveryClassification::PatchedPresent,
            ),
            (
                "applied",
                RemediationActionState::Applied,
                "[security]\ninsecure_test_mode = false\n",
                RecoveryClassification::PatchedPresent,
            ),
            (
                "rolling-back",
                RemediationActionState::RollingBack,
                "unrelated = true\n",
                RecoveryClassification::UnknownState,
            ),
        ] {
            let (root, target) = fixture(label);
            let mut service = RemediationService::default();
            let plan = service
                .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, None)
                .unwrap();
            let action = plan.actions[0].action_id.clone();
            let runtime = service.actions.get_mut(&action).unwrap();
            runtime.snapshot.state = state;
            runtime.snapshot.journal = Some(RecoveryJournal {
                action_id: action.clone(),
                plan_sha256: plan.plan_sha256.clone(),
                target_safe: runtime.target.canonical_path_safe.clone(),
                repository_root_safe: runtime
                    .target
                    .repository_root
                    .to_string_lossy()
                    .replace('\\', "/"),
                original_sha256: runtime.target.sha256.clone(),
                original_stable_identity: runtime.target.stable_identity.clone(),
                patched_sha256: plan.actions[0].verification.expected_post_sha256.clone(),
                backup_id: None,
                backup_sha256: None,
                state,
                manual_review_required: false,
            });
            fs::write(&target, bytes).unwrap();
            let before = fs::read(&target).unwrap();
            assert_eq!(service.recover(&action).unwrap(), expected);
            assert_eq!(fs::read(&target).unwrap(), before);
            assert_eq!(
                service
                    .snapshot(&action)
                    .unwrap()
                    .journal
                    .unwrap()
                    .manual_review_required,
                expected == RecoveryClassification::UnknownState
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn rollback_after_user_edit_is_conflict_and_preserves_user_bytes() {
        let (root, target) = fixture("rollback-conflict");
        let mut service = RemediationService::default();
        let plan = service
            .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, None)
            .unwrap();
        let action = plan.actions[0].action_id.clone();
        service.preview(&action).unwrap();
        let grant = service.authorize(&action, &plan.plan_sha256, 300).unwrap();
        service.apply(&action, &grant.raw_token).unwrap();
        let scanner = plan.actions[0].verification.scanner_id.clone();
        service
            .verify(&action, observation(&scanner, vec![]))
            .unwrap();
        fs::write(&target, "later_user_edit = true\n").unwrap();
        let before = fs::read(&target).unwrap();
        assert!(matches!(
            service.rollback(&action),
            Err(ServiceError::Executor(ExecutorError::RollbackConflict))
        ));
        assert_eq!(fs::read(&target).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rollback_rejects_same_bytes_with_replaced_file_identity() {
        let (root, target) = fixture("rollback-identity");
        let mut service = RemediationService::default();
        let plan = service
            .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, None)
            .unwrap();
        let action = plan.actions[0].action_id.clone();
        service.preview(&action).unwrap();
        let grant = service.authorize(&action, &plan.plan_sha256, 300).unwrap();
        service.apply(&action, &grant.raw_token).unwrap();
        let scanner = plan.actions[0].verification.scanner_id.clone();
        service
            .verify(&action, observation(&scanner, vec![]))
            .unwrap();
        let patched = fs::read(&target).unwrap();
        let displaced = root.join("displaced.toml");
        fs::rename(&target, &displaced).unwrap();
        fs::write(&target, &patched).unwrap();
        assert!(matches!(
            service.rollback(&action),
            Err(ServiceError::Executor(ExecutorError::RollbackConflict))
        ));
        assert_eq!(fs::read(&target).unwrap(), patched);
        fs::remove_dir_all(root).unwrap();
    }
}
