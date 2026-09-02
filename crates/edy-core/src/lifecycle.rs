use crate::{DomainError, ValidationErrorKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    Queued,
    Preparing,
    Running,
    CancellationRequested,
    Cancelled,
    Completed,
    Partial,
    Failed,
}

impl ScanState {
    pub fn transition(self, next: Self) -> Result<Self, DomainError> {
        let valid = matches!(
            (self, next),
            (Self::Queued, Self::Preparing)
                | (Self::Queued, Self::CancellationRequested)
                | (Self::Preparing, Self::Running)
                | (Self::Preparing, Self::CancellationRequested)
                | (Self::Preparing, Self::Failed)
                | (Self::Running, Self::CancellationRequested)
                | (Self::Running, Self::Completed)
                | (Self::Running, Self::Partial)
                | (Self::Running, Self::Failed)
                | (Self::CancellationRequested, Self::Cancelled)
                | (Self::CancellationRequested, Self::Failed)
        );
        valid
            .then_some(next)
            .ok_or_else(|| DomainError::new("scan_state", ValidationErrorKind::InvalidTransition))
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Completed | Self::Partial | Self::Failed
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Investigating,
    Remediating,
    VerificationPending,
    Resolved,
    AcceptedRisk,
    Ignored,
}

impl FindingStatus {
    pub fn transition(self, next: Self) -> Result<Self, DomainError> {
        let valid = matches!(
            (self, next),
            (Self::Open, Self::Investigating)
                | (Self::Open, Self::AcceptedRisk)
                | (Self::Open, Self::Ignored)
                | (Self::Investigating, Self::Remediating)
                | (Self::Investigating, Self::AcceptedRisk)
                | (Self::Investigating, Self::Ignored)
                | (Self::Remediating, Self::VerificationPending)
                | (Self::VerificationPending, Self::Resolved)
                | (Self::VerificationPending, Self::Remediating)
                | (Self::AcceptedRisk, Self::Investigating)
                | (Self::Ignored, Self::Investigating)
        );
        valid.then_some(next).ok_or_else(|| {
            DomainError::new("finding_status", ValidationErrorKind::InvalidTransition)
        })
    }

    pub fn reopen_regression(self) -> Result<Self, DomainError> {
        if self == Self::Resolved {
            Ok(Self::Open)
        } else {
            Err(DomainError::new(
                "finding_status",
                ValidationErrorKind::InvalidTransition,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_transitions_are_closed_and_terminal_states_do_not_move() {
        assert_eq!(
            ScanState::Queued.transition(ScanState::Preparing).unwrap(),
            ScanState::Preparing
        );
        assert!(ScanState::Queued.transition(ScanState::Completed).is_err());
        assert!(ScanState::Completed.transition(ScanState::Running).is_err());
    }

    #[test]
    fn resolved_reopens_only_as_recorded_regression() {
        assert!(
            FindingStatus::Resolved
                .transition(FindingStatus::Open)
                .is_err()
        );
        assert_eq!(
            FindingStatus::Resolved.reopen_regression().unwrap(),
            FindingStatus::Open
        );
        assert!(FindingStatus::Open.reopen_regression().is_err());
    }
}
