//! Production Level 6: plans and rescan authority only. No filesystem API.
use crate::*;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const MANUAL_DISCLOSURE: &str =
    "Manual action required. Suggested change — not applied by EDY VERDICT.";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManualState {
    Planned,
    AwaitingManualChange,
    VerificationPending,
    Verifying,
    Resolved,
    StillPresent,
    Inconclusive,
    RegressionDetected,
    TargetInvalid,
    Cancelled,
    Interrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationAuthorization {
    pub authorization_id: String,
    pub action_id: String,
    pub finding_id: String,
    pub case_id: String,
    pub run_id: String,
    pub target_identity: String,
    pub plan_sha256: String,
    pub verification_plan_sha256: String,
    pub expires_at_unix: i64,
    pub used: bool,
    pub token_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManualVerificationResult {
    pub outcome: ManualState,
    pub scanner_id: String,
    pub snapshot_id: String,
    pub original_finding_absent: bool,
    pub required_checks_executed: bool,
    pub coverage_sufficient: bool,
    pub stable_during_scan: bool,
    pub contradictory_evidence: bool,
    pub regression_count: u32,
    pub explanation_safe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManualSnapshot {
    pub plan: RemediationPlan,
    pub run_id: String,
    pub state: ManualState,
    pub revision: u32,
    pub guidance: Vec<String>,
    pub suggested_diff: Option<String>,
    pub limitations: Vec<String>,
    pub authorization: Option<VerificationAuthorization>,
    pub verification: Option<ManualVerificationResult>,
    pub timeline: Vec<ManualEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManualEvent {
    pub sequence: u32,
    pub event_type: String,
    pub at_utc: String,
}

/// Observations from the original scanner family. Never accepted from frontend IPC.
#[derive(Debug, Clone)]
pub struct FreshVerification {
    pub scanner_id: String,
    pub original_present: bool,
    pub required_checks_executed: bool,
    pub sufficient_coverage: bool,
    pub stable_during_scan: bool,
    pub target_valid: bool,
    pub contradictory: bool,
    pub regression_count: u32,
    pub cancelled: bool,
}

pub fn safe_manual_text(text: &str, limit: usize) -> String {
    let lower = text.to_ascii_lowercase();
    if text.len() > limit
        || text.chars().any(|c| c.is_control() && c != '\n')
        || text.chars().any(|c| {
            ('\u{202a}'..='\u{202e}').contains(&c) || ('\u{2066}'..='\u{2069}').contains(&c)
        })
        || [
            "edy_fake_",
            "bearer ",
            "-----begin ",
            "password=",
            "token=",
            "cookie=",
        ]
        .iter()
        .any(|s| lower.contains(s))
    {
        "[REDACTED]".into()
    } else {
        text.into()
    }
}

pub fn manual_now() -> String {
    OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("zero nanos")
        .format(&Rfc3339)
        .expect("UTC formatting is bounded")
}

impl ManualSnapshot {
    pub fn create(
        mut plan: RemediationPlan,
        run_id: String,
        guidance: Vec<String>,
        suggested_diff: Option<String>,
    ) -> Result<Self, &'static str> {
        if plan.actions.len() != 1
            || plan.case_id.is_none()
            || uuid::Uuid::parse_str(&run_id).is_err()
        {
            return Err("manual_plan_invalid");
        }
        let action = &mut plan.actions[0];
        if !matches!(
            action.safety_class,
            RemediationSafetyClass::GuidanceOnly
                | RemediationSafetyClass::ManualChangeVerifiable
                | RemediationSafetyClass::PolicyBlocked
                | RemediationSafetyClass::Unsupported
        ) || action.rollback.eligible
        {
            return Err("production_mutation_policy_blocked");
        }
        action.action_id = deterministic_action_id(action)?;
        plan.plan_sha256 = calculate_plan_sha256(&plan)?;
        validate_plan(&plan)?;
        let mut result = Self {
            plan,
            run_id,
            state: ManualState::Planned,
            revision: 0,
            guidance: guidance.iter().map(|s| safe_manual_text(s, 2048)).collect(),
            suggested_diff: suggested_diff.map(|s| safe_manual_text(&s, 4096)),
            limitations: vec![
                MANUAL_DISCLOSURE.into(),
                "Verification covers only the checks executed; it does not prove system safety."
                    .into(),
            ],
            authorization: None,
            verification: None,
            timeline: vec![],
        };
        result.event("REMEDIATION_PLAN_CREATED")?;
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_plan(&self.plan)?;
        if self.plan.actions.len() != 1
            || self.timeline.is_empty()
            || self.timeline.len() > 256
            || self.guidance.is_empty()
            || self.guidance.len() > 16
            || self.plan.case_id.is_none()
        {
            return Err("manual_snapshot_invalid");
        }
        let action = &self.plan.actions[0];
        if action.safety_class == RemediationSafetyClass::TestOnlyReversible
            || action.rollback.eligible
            || action.finding_id != self.plan.finding_id
            || action.case_id != self.plan.case_id
        {
            return Err("production_mutation_policy_blocked");
        }
        if uuid::Uuid::parse_str(&self.run_id).is_err()
            || self
                .guidance
                .iter()
                .any(|s| safe_manual_text(s, 2048) != *s)
            || self
                .suggested_diff
                .as_ref()
                .is_some_and(|s| safe_manual_text(s, 4096) != *s)
            || self
                .limitations
                .iter()
                .any(|s| safe_manual_text(s, 4096) != *s)
        {
            return Err("sensitive_manual_snapshot");
        }
        if let Some(v) = &self.verification {
            if v.scanner_id != action.verification.scanner_id {
                return Err("verification_family_mismatch");
            }
            if matches!(
                self.state,
                ManualState::Resolved
                    | ManualState::StillPresent
                    | ManualState::Inconclusive
                    | ManualState::RegressionDetected
                    | ManualState::TargetInvalid
                    | ManualState::Cancelled
            ) && v.outcome != self.state
            {
                return Err("verification_state_mismatch");
            }
        }
        if self.state == ManualState::Resolved
            && !self.verification.as_ref().is_some_and(|v| {
                v.original_finding_absent
                    && v.required_checks_executed
                    && v.coverage_sufficient
                    && v.stable_during_scan
                    && !v.contradictory_evidence
                    && v.regression_count == 0
                    && self.authorization.as_ref().is_some_and(|a| a.used)
            })
        {
            return Err("false_resolution_denied");
        }
        for (i, event) in self.timeline.iter().enumerate() {
            if event.sequence != i as u32 + 1 || !allowed_event(&event.event_type) {
                return Err("manual_timeline_invalid");
            }
        }
        let bytes = serde_json::to_string(self).map_err(|_| "manual_snapshot_invalid")?;
        if bytes.len() > 128 * 1024 || bytes.to_ascii_lowercase().contains("edy_fake_") {
            return Err("sensitive_manual_snapshot");
        }
        Ok(())
    }
    fn event(&mut self, name: &str) -> Result<(), &'static str> {
        if !allowed_event(name) || self.timeline.len() >= 256 {
            return Err("manual_timeline_full");
        }
        self.timeline.push(ManualEvent {
            sequence: self.timeline.len() as u32 + 1,
            event_type: name.into(),
            at_utc: manual_now(),
        });
        Ok(())
    }
    pub fn review(&mut self) -> Result<(), &'static str> {
        if self.state != ManualState::Planned {
            return Ok(());
        }
        self.event("GUIDANCE_REVIEWED")?;
        self.state = ManualState::AwaitingManualChange;
        self.event("MANUAL_CHANGE_AWAITING_VERIFICATION")
    }
    pub fn authorize_verification(&mut self, now: i64) -> Result<String, &'static str> {
        self.validate()?;
        if !matches!(
            self.state,
            ManualState::AwaitingManualChange
                | ManualState::StillPresent
                | ManualState::Inconclusive
                | ManualState::RegressionDetected
                | ManualState::TargetInvalid
                | ManualState::Cancelled
                | ManualState::Interrupted
                | ManualState::Resolved
        ) {
            return Err("verification_state_refused");
        }
        let action = &self.plan.actions[0];
        let raw = format!(
            "{}{}",
            uuid::Uuid::now_v7().simple(),
            uuid::Uuid::now_v7().simple()
        );
        self.authorization = Some(VerificationAuthorization {
            authorization_id: uuid::Uuid::now_v7().to_string(),
            action_id: action.action_id.clone(),
            finding_id: self.plan.finding_id.clone(),
            case_id: self.plan.case_id.clone().ok_or("case_missing")?,
            run_id: self.run_id.clone(),
            target_identity: action.precondition.stable_identity.clone(),
            plan_sha256: self.plan.plan_sha256.clone(),
            verification_plan_sha256: sha256_hex(
                &serde_json::to_vec(&action.verification)
                    .map_err(|_| "verification_plan_invalid")?,
            ),
            expires_at_unix: now + 300,
            used: false,
            token_sha256: sha256_hex(raw.as_bytes()),
        });
        self.state = ManualState::VerificationPending;
        self.event("VERIFICATION_AUTHORIZED")?;
        Ok(raw)
    }
    pub fn begin_verification(&mut self, token: &str, now: i64) -> Result<(), &'static str> {
        self.validate()?;
        let action = &self.plan.actions[0];
        let a = self
            .authorization
            .as_mut()
            .ok_or("verification_authorization_denied")?;
        if self.state != ManualState::VerificationPending
            || a.used
            || now >= a.expires_at_unix
            || token.len() != 64
            || a.token_sha256 != sha256_hex(token.as_bytes())
            || a.action_id != action.action_id
            || a.plan_sha256 != self.plan.plan_sha256
            || a.case_id != *self.plan.case_id.as_ref().ok_or("case_missing")?
            || a.finding_id != self.plan.finding_id
            || a.run_id != self.run_id
            || a.target_identity != action.precondition.stable_identity
            || a.verification_plan_sha256
                != sha256_hex(
                    &serde_json::to_vec(&action.verification)
                        .map_err(|_| "verification_plan_invalid")?,
                )
        {
            return Err("verification_authorization_denied");
        }
        a.used = true;
        self.state = ManualState::Verifying;
        self.verification = None;
        self.event("VERIFICATION_STARTED")
    }
    pub fn finish(&mut self, observation: FreshVerification) -> Result<(), &'static str> {
        if self.state != ManualState::Verifying {
            return Err("verification_state_refused");
        }
        let family_matches = observation.scanner_id == self.plan.actions[0].verification.scanner_id;
        let state = if observation.cancelled {
            ManualState::Cancelled
        } else if !observation.target_valid || !observation.stable_during_scan {
            ManualState::TargetInvalid
        } else if !family_matches
            || !observation.required_checks_executed
            || !observation.sufficient_coverage
            || observation.contradictory
        {
            ManualState::Inconclusive
        } else if observation.regression_count > 0 {
            ManualState::RegressionDetected
        } else if observation.original_present {
            ManualState::StillPresent
        } else {
            ManualState::Resolved
        };
        self.verification = Some(ManualVerificationResult {
            outcome: state,
            scanner_id: self.plan.actions[0].verification.scanner_id.clone(),
            snapshot_id: uuid::Uuid::now_v7().to_string(),
            original_finding_absent: !observation.original_present,
            required_checks_executed: family_matches && observation.required_checks_executed,
            coverage_sufficient: observation.sufficient_coverage,
            stable_during_scan: observation.stable_during_scan,
            contradictory_evidence: observation.contradictory,
            regression_count: observation.regression_count,
            explanation_safe: manual_wording(state).into(),
        });
        self.state = state;
        self.event(match state {
            ManualState::Resolved => "VERIFICATION_RESOLVED",
            ManualState::StillPresent => "VERIFICATION_STILL_PRESENT",
            ManualState::RegressionDetected => "REGRESSION_DETECTED",
            ManualState::Cancelled => "VERIFICATION_CANCELLED",
            ManualState::TargetInvalid => "VERIFICATION_TARGET_INVALID",
            _ => "VERIFICATION_INCONCLUSIVE",
        })
    }
    pub fn interrupt_on_restart(&mut self) -> Result<bool, &'static str> {
        if !matches!(
            self.state,
            ManualState::Verifying | ManualState::VerificationPending
        ) {
            return Ok(false);
        }
        if let Some(a) = self.authorization.as_mut() {
            a.used = true;
        }
        self.state = ManualState::Interrupted;
        self.event("VERIFICATION_INTERRUPTED")?;
        Ok(true)
    }
}

pub fn manual_wording(state: ManualState) -> &'static str {
    match state {
        ManualState::Resolved => "Verification passed for the checks executed",
        ManualState::StillPresent => "Still present",
        ManualState::RegressionDetected => "Regression detected",
        ManualState::Inconclusive => "Verification inconclusive",
        ManualState::Cancelled => {
            "Verification cancelled; manual-change verification can be requested again"
        }
        ManualState::TargetInvalid => {
            "Target invalid or changed during verification; no resolution claimed"
        }
        ManualState::Interrupted => "Verification interrupted; request a fresh verification",
        _ => {
            "Remediation guidance generated. Manual action required. Verification not yet performed"
        }
    }
}

fn allowed_event(event: &str) -> bool {
    matches!(
        event,
        "REMEDIATION_PLAN_CREATED"
            | "GUIDANCE_REVIEWED"
            | "MANUAL_CHANGE_AWAITING_VERIFICATION"
            | "VERIFICATION_AUTHORIZED"
            | "VERIFICATION_STARTED"
            | "VERIFICATION_RESOLVED"
            | "VERIFICATION_STILL_PRESENT"
            | "VERIFICATION_INCONCLUSIVE"
            | "REGRESSION_DETECTED"
            | "VERIFICATION_TARGET_INVALID"
            | "VERIFICATION_CANCELLED"
            | "VERIFICATION_INTERRUPTED"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> ManualSnapshot {
        let z = "0".repeat(64);
        let case = Some(format!("case-v1-{}", "a".repeat(64)));
        let a = RemediationAction {
            action_id: String::new(),
            finding_id: "finding-a".into(),
            case_id: case.clone(),
            target_id: "target-a".into(),
            kind: RemediationActionKind::RepositoryInventoryReview,
            safety_class: RemediationSafetyClass::ManualChangeVerifiable,
            rule_id: "MANUAL_REPOSITORY_INVENTORY_V1".into(),
            rule_version: 1,
            explanation_safe: "Read-only rescan".into(),
            precondition: RemediationPrecondition {
                canonical_path: "synthetic-authorized-root".into(),
                stable_identity: "directory-identity-a".into(),
                expected_sha256: z.clone(),
                expected_size: 0,
                expected_anchor_sha256: z.clone(),
            },
            edit: None,
            verification: VerificationPlan {
                scanner_id: "edy-inventory".into(),
                original_fingerprint: "original".into(),
                required_checks: vec!["inventory".into()],
                expected_post_sha256: z.clone(),
                coverage_required: true,
                manual_scope: None,
            },
            rollback: RollbackPlan {
                eligible: false,
                required_post_sha256: z,
                explanation_safe: "Policy blocked".into(),
            },
        };
        ManualSnapshot::create(
            RemediationPlan {
                plan_id: uuid::Uuid::now_v7().to_string(),
                plan_sha256: String::new(),
                finding_id: "finding-a".into(),
                case_id: case,
                created_at_utc: manual_now(),
                actions: vec![a],
            },
            uuid::Uuid::now_v7().to_string(),
            vec!["Manual action required".into()],
            None,
        )
        .unwrap()
    }
    fn clear() -> FreshVerification {
        FreshVerification {
            scanner_id: "edy-inventory".into(),
            original_present: false,
            required_checks_executed: true,
            sufficient_coverage: true,
            stable_during_scan: true,
            target_valid: true,
            contradictory: false,
            regression_count: 0,
            cancelled: false,
        }
    }
    #[test]
    fn manual_verification_false_resolution_matrix() {
        for case in 0..10 {
            let mut s = sample();
            s.review().unwrap();
            let token = s.authorize_verification(100).unwrap();
            s.begin_verification(&token, 101).unwrap();
            let mut v = clear();
            let expected = match case {
                0 => ManualState::Resolved,
                1 => {
                    v.original_present = true;
                    ManualState::StillPresent
                }
                2 => {
                    v.required_checks_executed = false;
                    ManualState::Inconclusive
                }
                3 => {
                    v.sufficient_coverage = false;
                    ManualState::Inconclusive
                }
                4 => {
                    v.stable_during_scan = false;
                    ManualState::TargetInvalid
                }
                5 => {
                    v.target_valid = false;
                    ManualState::TargetInvalid
                }
                6 => {
                    v.contradictory = true;
                    ManualState::Inconclusive
                }
                7 => {
                    v.regression_count = 1;
                    ManualState::RegressionDetected
                }
                8 => {
                    v.cancelled = true;
                    ManualState::Cancelled
                }
                _ => {
                    v.scanner_id = "not-original-family".into();
                    ManualState::Inconclusive
                }
            };
            s.finish(v).unwrap();
            assert_eq!(s.state, expected);
            assert!(s.begin_verification(&token, 102).is_err());
        }
    }
    #[test]
    fn single_use_verification_authority_is_bound_to_all_fields() {
        for field in 0..10 {
            let mut s = sample();
            s.review().unwrap();
            let token = s.authorize_verification(100).unwrap();
            let a = s.authorization.as_mut().unwrap();
            match field {
                0 => a.finding_id = "other".into(),
                1 => a.case_id = "other".into(),
                2 => a.action_id = "other".into(),
                3 => a.run_id = "other".into(),
                4 => a.target_identity = "other".into(),
                5 => a.plan_sha256 = "0".repeat(64),
                6 => a.verification_plan_sha256 = "0".repeat(64),
                7 => a.expires_at_unix = 101,
                8 => a.used = true,
                _ => a.token_sha256 = "0".repeat(64),
            }
            assert!(s.begin_verification(&token, 101).is_err(), "field {field}");
        }
    }
    #[test]
    fn restart_is_idempotent_and_never_replays_authority() {
        let mut s = sample();
        s.review().unwrap();
        let token = s.authorize_verification(100).unwrap();
        assert!(s.interrupt_on_restart().unwrap());
        let count = s.timeline.len();
        assert!(!s.interrupt_on_restart().unwrap());
        assert_eq!(s.timeline.len(), count);
        assert!(s.begin_verification(&token, 101).is_err());
        let new = s.authorize_verification(102).unwrap();
        s.begin_verification(&new, 103).unwrap();
        assert!(s.interrupt_on_restart().unwrap());
        assert_eq!(s.state, ManualState::Interrupted);
    }
    #[test]
    fn every_seeded_secret_is_redacted_before_guidance_or_diff() {
        for sentinel in [
            "EDY_FAKE_SECRET_LEVEL6",
            "EDY_FAKE_COOKIE_LEVEL6",
            "EDY_FAKE_QUERY_LEVEL6",
            "EDY_FAKE_AUTH_TOKEN_LEVEL6",
            "EDY_FAKE_PASSWORD_LEVEL6",
        ] {
            assert_eq!(
                safe_manual_text(&format!("suggested sensitive line {sentinel}"), 4096),
                "[REDACTED]"
            );
        }
        assert_eq!(safe_manual_text("bidi\u{202e}text", 4096), "[REDACTED]");
    }
}
