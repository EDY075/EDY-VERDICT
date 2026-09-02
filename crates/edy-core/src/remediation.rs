use crate::{
    DomainError, EngineId, FindingFingerprint, FindingId, RemediationId, Timestamp,
    ValidationErrorKind, VerificationId, validation,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SafetyClass {
    Informational,
    SafeAutomatable,
    ConfirmationRequired,
    ManualOnly,
    Prohibited,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequiresConfirmation {
    No,
    Yes,
    NotExecutable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    Reversible,
    BackupRequired,
    Irreversible,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationStep {
    pub sequence: u16,
    pub title: String,
    pub instruction: String,
    pub safety_class: SafetyClass,
    pub requires_confirmation: RequiresConfirmation,
    pub reversibility: Reversibility,
}

impl RemediationStep {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.sequence == 0 {
            return Err(DomainError::new(
                "sequence",
                ValidationErrorKind::OutOfRange,
            ));
        }
        validation::bounded_text("step_title", &self.title, 256)?;
        validation::bounded_text("step_instruction", &self.instruction, 2048)?;
        let coherent = match self.safety_class {
            SafetyClass::Informational | SafetyClass::ManualOnly | SafetyClass::Prohibited => {
                self.requires_confirmation == RequiresConfirmation::NotExecutable
            }
            SafetyClass::SafeAutomatable => self.requires_confirmation == RequiresConfirmation::No,
            SafetyClass::ConfirmationRequired => {
                self.requires_confirmation == RequiresConfirmation::Yes
            }
        };
        coherent.then_some(()).ok_or_else(|| {
            DomainError::new("requires_confirmation", ValidationErrorKind::Incoherent)
        })
    }

    pub const fn can_auto_execute(&self) -> bool {
        matches!(self.safety_class, SafetyClass::SafeAutomatable)
            && matches!(self.requires_confirmation, RequiresConfirmation::No)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationPlan {
    pub expected_fingerprint: FindingFingerprint,
    pub required_engines: Vec<EngineId>,
    pub description: String,
}

impl VerificationPlan {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.required_engines.is_empty() || self.required_engines.len() > 64 {
            return Err(DomainError::new(
                "required_engines",
                ValidationErrorKind::OutOfRange,
            ));
        }
        if self.required_engines.iter().collect::<BTreeSet<_>>().len()
            != self.required_engines.len()
        {
            return Err(DomainError::new(
                "required_engines",
                ValidationErrorKind::Duplicate,
            ));
        }
        validation::bounded_text("verification_description", &self.description, 1024)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationPlan {
    pub id: RemediationId,
    pub finding_id: FindingId,
    pub created_at: Timestamp,
    pub steps: Vec<RemediationStep>,
    pub verification: VerificationPlan,
}

impl RemediationPlan {
    pub fn new(
        id: RemediationId,
        finding_id: FindingId,
        created_at: Timestamp,
        mut steps: Vec<RemediationStep>,
        verification: VerificationPlan,
    ) -> Result<Self, DomainError> {
        if steps.is_empty() || steps.len() > 32 {
            return Err(DomainError::new(
                "remediation_steps",
                ValidationErrorKind::OutOfRange,
            ));
        }
        for step in &steps {
            step.validate()?;
        }
        steps.sort_by_key(|step| step.sequence);
        if steps
            .windows(2)
            .any(|pair| pair[0].sequence == pair[1].sequence)
        {
            return Err(DomainError::new(
                "remediation_steps",
                ValidationErrorKind::Duplicate,
            ));
        }
        verification.validate()?;
        Ok(Self {
            id,
            finding_id,
            created_at,
            steps,
            verification,
        })
    }

    pub fn automatic_steps(&self) -> impl Iterator<Item = &RemediationStep> {
        self.steps.iter().filter(|step| step.can_auto_execute())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationWorkflowState {
    Requested,
    Completed,
    VerificationPending,
    RescanRunning,
    Resolved,
    StillPresent,
    Regression,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    Resolved,
    StillPresent,
    Regression,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowTransition {
    pub from: RemediationWorkflowState,
    pub to: RemediationWorkflowState,
    pub at: Timestamp,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationWorkflow {
    pub plan_id: RemediationId,
    pub state: RemediationWorkflowState,
    pub history: Vec<WorkflowTransition>,
}

impl RemediationWorkflow {
    pub fn new(plan_id: RemediationId) -> Self {
        Self {
            plan_id,
            state: RemediationWorkflowState::Requested,
            history: Vec::new(),
        }
    }

    pub fn transition(
        &mut self,
        next: RemediationWorkflowState,
        at: Timestamp,
        reason: impl Into<String>,
    ) -> Result<(), DomainError> {
        let valid = matches!(
            (self.state, next),
            (
                RemediationWorkflowState::Requested,
                RemediationWorkflowState::Completed
            ) | (
                RemediationWorkflowState::Requested,
                RemediationWorkflowState::Failed
            ) | (
                RemediationWorkflowState::Completed,
                RemediationWorkflowState::VerificationPending
            ) | (
                RemediationWorkflowState::VerificationPending,
                RemediationWorkflowState::RescanRunning
            ) | (
                RemediationWorkflowState::RescanRunning,
                RemediationWorkflowState::Resolved
            ) | (
                RemediationWorkflowState::RescanRunning,
                RemediationWorkflowState::StillPresent
            ) | (
                RemediationWorkflowState::RescanRunning,
                RemediationWorkflowState::Regression
            ) | (
                RemediationWorkflowState::RescanRunning,
                RemediationWorkflowState::Failed
            ) | (
                RemediationWorkflowState::StillPresent,
                RemediationWorkflowState::Requested
            ) | (
                RemediationWorkflowState::Resolved,
                RemediationWorkflowState::Regression
            )
        );
        if !valid {
            return Err(DomainError::new(
                "remediation_state",
                ValidationErrorKind::InvalidTransition,
            ));
        }
        let reason = reason.into();
        validation::bounded_text("transition_reason", &reason, 512)?;
        if self.history.last().is_some_and(|last| at < last.at) {
            return Err(DomainError::new(
                "transition_time",
                ValidationErrorKind::Incoherent,
            ));
        }
        let from = self.state;
        self.state = next;
        self.history.push(WorkflowTransition {
            from,
            to: next,
            at,
            reason,
        });
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationRecord {
    pub id: VerificationId,
    pub remediation_id: RemediationId,
    pub finding_id: FindingId,
    pub at: Timestamp,
    pub outcome: VerificationOutcome,
    pub evidence_ids: Vec<crate::EvidenceId>,
}

pub trait RemediationExecutor {
    fn execute(&mut self, plan: &RemediationPlan) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_class_and_confirmation_cannot_disagree() {
        let unsafe_step = RemediationStep {
            sequence: 1,
            title: "synthetic".into(),
            instruction: "do not execute".into(),
            safety_class: SafetyClass::ConfirmationRequired,
            requires_confirmation: RequiresConfirmation::No,
            reversibility: Reversibility::BackupRequired,
        };
        assert!(unsafe_step.validate().is_err());
    }

    #[test]
    fn workflow_requires_verification_and_rescan_before_resolution() {
        let mut workflow = RemediationWorkflow::new(
            RemediationId::new("018f4c2a-1d3b-7abc-8def-0123456789ab").unwrap(),
        );
        let at = || Timestamp::new("2026-09-02T03:00:00Z").unwrap();
        assert!(
            workflow
                .transition(RemediationWorkflowState::Resolved, at(), "skip")
                .is_err()
        );
        workflow
            .transition(RemediationWorkflowState::Completed, at(), "fake completion")
            .unwrap();
        workflow
            .transition(
                RemediationWorkflowState::VerificationPending,
                at(),
                "verification required",
            )
            .unwrap();
        workflow
            .transition(
                RemediationWorkflowState::RescanRunning,
                at(),
                "synthetic rescan",
            )
            .unwrap();
        workflow
            .transition(
                RemediationWorkflowState::Resolved,
                at(),
                "indicator absent with required coverage",
            )
            .unwrap();
        assert_eq!(workflow.state, RemediationWorkflowState::Resolved);
        assert_eq!(workflow.history.len(), 4);
    }

    #[test]
    fn fake_executor_has_no_host_action_contract() {
        struct Fake {
            called: bool,
        }
        impl RemediationExecutor for Fake {
            fn execute(&mut self, _: &RemediationPlan) -> Result<(), String> {
                self.called = true;
                Ok(())
            }
        }
        let step = RemediationStep {
            sequence: 1,
            title: "Review".into(),
            instruction: "Review synthetic evidence".into(),
            safety_class: SafetyClass::ManualOnly,
            requires_confirmation: RequiresConfirmation::NotExecutable,
            reversibility: Reversibility::NotApplicable,
        };
        let plan = RemediationPlan::new(
            RemediationId::new("018f4c2a-1d3b-7abc-8def-0123456789ab").unwrap(),
            FindingId::new("018f4c2a-1d3b-7abc-8def-0123456789ac").unwrap(),
            Timestamp::new("2026-09-02T03:00:00Z").unwrap(),
            vec![step],
            VerificationPlan {
                expected_fingerprint: FindingFingerprint::parse(
                    "ffp1-00000000000000000000000000000000",
                )
                .unwrap(),
                required_engines: vec![EngineId::new("fixture").unwrap()],
                description: "synthetic rescan".into(),
            },
        )
        .unwrap();
        let mut fake = Fake { called: false };
        fake.execute(&plan).unwrap();
        assert!(fake.called);
        assert_eq!(plan.automatic_steps().count(), 0);
    }
}
