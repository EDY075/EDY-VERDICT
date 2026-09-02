use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryPhase {
    Inventory,
    Planning,
    SecretChecks,
    DependencyChecks,
    ConfigChecks,
    Correlation,
    Reporting,
}

impl RepositoryPhase {
    pub const ALL: [Self; 7] = [
        Self::Inventory,
        Self::Planning,
        Self::SecretChecks,
        Self::DependencyChecks,
        Self::ConfigChecks,
        Self::Correlation,
        Self::Reporting,
    ];
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryPipelineState {
    Running,
    Partial,
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPipelineProgress {
    pub phase: RepositoryPhase,
    pub completed_tasks: u32,
    pub total_tasks: u32,
    pub percent: u32,
    pub state: RepositoryPipelineState,
    pub unavailable: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeRepositoryPipeline {
    next: usize,
    cancelled: bool,
    unavailable: Vec<String>,
}

impl FakeRepositoryPipeline {
    pub fn new(unavailable: Vec<String>) -> Self {
        let mut unavailable = unavailable;
        unavailable.sort();
        unavailable.dedup();
        Self {
            next: 0,
            cancelled: false,
            unavailable,
        }
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    pub fn advance(&mut self) -> RepositoryPipelineProgress {
        if self.cancelled {
            return self.progress(RepositoryPipelineState::Cancelled);
        }
        if self.next < RepositoryPhase::ALL.len() {
            self.next += 1;
        }
        let terminal = self.next == RepositoryPhase::ALL.len();
        let state = if terminal && self.unavailable.is_empty() {
            RepositoryPipelineState::Completed
        } else if terminal {
            RepositoryPipelineState::Partial
        } else {
            RepositoryPipelineState::Running
        };
        self.progress(state)
    }

    fn progress(&self, state: RepositoryPipelineState) -> RepositoryPipelineProgress {
        let completed = self.next.min(RepositoryPhase::ALL.len()) as u32;
        let phase_index = self
            .next
            .saturating_sub(1)
            .min(RepositoryPhase::ALL.len() - 1);
        RepositoryPipelineProgress {
            phase: RepositoryPhase::ALL[phase_index],
            completed_tasks: completed,
            total_tasks: RepositoryPhase::ALL.len() as u32,
            percent: completed * 100 / RepositoryPhase::ALL.len() as u32,
            state,
            unavailable: self.unavailable.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_is_monotonic_bounded_and_has_no_eta() {
        let mut pipeline = FakeRepositoryPipeline::new(Vec::new());
        let mut observed = Vec::new();
        for phase in RepositoryPhase::ALL {
            let progress = pipeline.advance();
            assert_eq!(progress.phase, phase);
            observed.push(progress.percent);
        }
        assert_eq!(observed, vec![14, 28, 42, 57, 71, 85, 100]);
        assert_eq!(pipeline.advance().state, RepositoryPipelineState::Completed);
    }

    #[test]
    fn unavailable_adapter_finishes_partial_and_reduces_coverage() {
        let mut pipeline = FakeRepositoryPipeline::new(vec!["osv-data".into()]);
        let mut result = pipeline.advance();
        while result.state == RepositoryPipelineState::Running {
            result = pipeline.advance();
        }
        assert_eq!(result.state, RepositoryPipelineState::Partial);
        assert_eq!(result.unavailable, vec!["osv-data"]);
        assert_eq!(result.percent, 100);
    }

    #[test]
    fn cancellation_is_terminal_at_every_required_boundary() {
        for completed_before_cancel in [0, 1, 2, 3, 5, 6] {
            let mut pipeline = FakeRepositoryPipeline::new(Vec::new());
            for _ in 0..completed_before_cancel {
                assert_ne!(pipeline.advance().state, RepositoryPipelineState::Cancelled);
            }
            pipeline.cancel();
            let cancelled = pipeline.advance();
            assert_eq!(cancelled.state, RepositoryPipelineState::Cancelled);
            assert_eq!(cancelled.completed_tasks, completed_before_cancel);
            assert_ne!(cancelled.state, RepositoryPipelineState::Completed);
        }
    }
}
