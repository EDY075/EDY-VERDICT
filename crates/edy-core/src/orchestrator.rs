use crate::{
    CoverageTask, DomainError, EngineCoverage, EngineId, EngineObservation, EngineRunState,
    ScanCoverage, ScanId, ScanState, TargetId, ValidationErrorKind, validation,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_ENGINE_TASKS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineTask {
    pub engine: EngineId,
    pub target_id: TargetId,
    pub timeout_ms: u64,
}

impl EngineTask {
    pub fn new(
        engine: EngineId,
        target_id: TargetId,
        timeout_ms: u64,
    ) -> Result<Self, DomainError> {
        if timeout_ms == 0 || timeout_ms > 600_000 {
            return Err(DomainError::new(
                "timeout_ms",
                ValidationErrorKind::OutOfRange,
            ));
        }
        Ok(Self {
            engine,
            target_id,
            timeout_ms,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanPlan {
    pub scan_id: ScanId,
    pub tasks: Vec<EngineTask>,
}

impl ScanPlan {
    pub fn new(scan_id: ScanId, tasks: Vec<EngineTask>) -> Result<Self, DomainError> {
        if tasks.is_empty() || tasks.len() > MAX_ENGINE_TASKS {
            return Err(DomainError::new("tasks", ValidationErrorKind::OutOfRange));
        }
        let unique: BTreeSet<_> = tasks
            .iter()
            .map(|task| (&task.engine, &task.target_id))
            .collect();
        if unique.len() != tasks.len() {
            return Err(DomainError::new("tasks", ValidationErrorKind::Duplicate));
        }
        Ok(Self { scan_id, tasks })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CancellationState {
    Active,
    Requested,
    CleanupPending,
    Confirmed,
}

impl CancellationState {
    pub fn request(&mut self) {
        if *self == Self::Active {
            *self = Self::Requested;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProgressPhase {
    Preparing,
    Executing,
    Cancelling,
    Finalizing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProgressEvent {
    pub sequence: u32,
    pub phase: ProgressPhase,
    pub completed_tasks: u32,
    pub total_tasks: u32,
    pub percent: Option<u8>,
    pub elapsed_ms: u64,
    pub current_engine: Option<EngineId>,
    pub message: String,
    pub eta_ms: Option<u64>,
}

impl ProgressEvent {
    fn new(
        sequence: u32,
        phase: ProgressPhase,
        completed_tasks: u32,
        total_tasks: u32,
        elapsed_ms: u64,
        current_engine: Option<EngineId>,
        message: &str,
    ) -> Result<Self, DomainError> {
        validation::bounded_text("progress_message", message, 256)?;
        let percent = (total_tasks > 0).then_some(((completed_tasks * 100) / total_tasks) as u8);
        Ok(Self {
            sequence,
            phase,
            completed_tasks,
            total_tasks,
            percent,
            elapsed_ms,
            current_engine,
            message: message.into(),
            eta_ms: None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EngineTaskOutcome {
    Completed {
        observations: Vec<EngineObservation>,
        elapsed_ms: u64,
    },
    Failed {
        reason: String,
        elapsed_ms: u64,
    },
    TimedOut {
        elapsed_ms: u64,
    },
    Cancelled {
        elapsed_ms: u64,
        cleanup_confirmed: bool,
    },
}

pub trait EngineTaskRunner {
    fn run(&mut self, task: &EngineTask, cancellation: &mut CancellationState)
    -> EngineTaskOutcome;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanJobResult {
    pub scan_id: ScanId,
    pub state: ScanState,
    pub coverage: ScanCoverage,
    pub observations: Vec<EngineObservation>,
    pub progress: Vec<ProgressEvent>,
    pub cleanup_confirmed: bool,
}

pub struct ScanJob {
    plan: ScanPlan,
}

impl ScanJob {
    pub fn new(plan: ScanPlan) -> Self {
        Self { plan }
    }

    pub fn execute<R: EngineTaskRunner>(
        &self,
        runner: &mut R,
        cancellation: &mut CancellationState,
    ) -> Result<ScanJobResult, DomainError> {
        let total = self.plan.tasks.len() as u32;
        let mut progress = vec![ProgressEvent::new(
            0,
            ProgressPhase::Preparing,
            0,
            total,
            0,
            None,
            "scan plan prepared",
        )?];
        let mut observations = Vec::new();
        let mut results = Vec::with_capacity(self.plan.tasks.len());
        let mut elapsed = 0_u64;
        let mut cleanup_confirmed = true;

        for (index, task) in self.plan.tasks.iter().enumerate() {
            if *cancellation == CancellationState::Requested {
                results.extend(
                    self.plan.tasks[index..]
                        .iter()
                        .map(|pending| EngineCoverage {
                            engine: pending.engine.clone(),
                            target_id: pending.target_id.clone(),
                            state: EngineRunState::Cancelled,
                            evidence_obtained: 0,
                        }),
                );
                *cancellation = CancellationState::Confirmed;
                break;
            }
            progress.push(ProgressEvent::new(
                progress.len() as u32,
                ProgressPhase::Executing,
                index as u32,
                total,
                elapsed,
                Some(task.engine.clone()),
                "engine task started",
            )?);
            let outcome = runner.run(task, cancellation);
            let (state, evidence, task_elapsed) = match outcome {
                EngineTaskOutcome::Completed {
                    observations: task_observations,
                    elapsed_ms,
                } => {
                    if task_observations.iter().any(|observation| {
                        observation.validate().is_err()
                            || observation.engine != task.engine
                            || observation.target_id != task.target_id
                    }) {
                        return Err(DomainError::new(
                            "observations",
                            ValidationErrorKind::InvalidFormat,
                        ));
                    }
                    let evidence = task_observations.len() as u32;
                    observations.extend(task_observations);
                    (EngineRunState::Passed, evidence, elapsed_ms)
                }
                EngineTaskOutcome::Failed { reason, elapsed_ms } => {
                    validation::bounded_text("engine_failure", &reason, 512)?;
                    (EngineRunState::Failed, 0, elapsed_ms)
                }
                EngineTaskOutcome::TimedOut { elapsed_ms } => {
                    (EngineRunState::Failed, 0, elapsed_ms)
                }
                EngineTaskOutcome::Cancelled {
                    elapsed_ms,
                    cleanup_confirmed: confirmed,
                } => {
                    cleanup_confirmed &= confirmed;
                    *cancellation = if confirmed {
                        CancellationState::Confirmed
                    } else {
                        CancellationState::CleanupPending
                    };
                    (EngineRunState::Cancelled, 0, elapsed_ms)
                }
            };
            elapsed = elapsed.saturating_add(task_elapsed);
            results.push(EngineCoverage {
                engine: task.engine.clone(),
                target_id: task.target_id.clone(),
                state,
                evidence_obtained: evidence,
            });
            progress.push(ProgressEvent::new(
                progress.len() as u32,
                if state == EngineRunState::Cancelled {
                    ProgressPhase::Cancelling
                } else {
                    ProgressPhase::Executing
                },
                (index + 1) as u32,
                total,
                elapsed,
                Some(task.engine.clone()),
                "engine task finished",
            )?);
            if state == EngineRunState::Cancelled {
                results.extend(
                    self.plan.tasks[index + 1..]
                        .iter()
                        .map(|pending| EngineCoverage {
                            engine: pending.engine.clone(),
                            target_id: pending.target_id.clone(),
                            state: EngineRunState::Cancelled,
                            evidence_obtained: 0,
                        }),
                );
                break;
            }
        }
        let expected = self
            .plan
            .tasks
            .iter()
            .map(|task| CoverageTask {
                engine: task.engine.clone(),
                target_id: task.target_id.clone(),
            })
            .collect();
        let coverage = ScanCoverage::new(expected, results)?;
        let passed = coverage.passed_count();
        let state = if !cleanup_confirmed || *cancellation == CancellationState::CleanupPending {
            ScanState::Failed
        } else if *cancellation == CancellationState::Confirmed {
            ScanState::Cancelled
        } else if coverage.is_complete() {
            ScanState::Completed
        } else if passed > 0 {
            ScanState::Partial
        } else {
            ScanState::Failed
        };
        progress.push(ProgressEvent::new(
            progress.len() as u32,
            ProgressPhase::Finalizing,
            total,
            total,
            elapsed,
            None,
            "scan job finalized",
        )?);
        Ok(ScanJobResult {
            scan_id: self.plan.scan_id.clone(),
            state,
            coverage,
            observations,
            progress,
            cleanup_confirmed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeRunner {
        outcomes: Vec<EngineTaskOutcome>,
    }
    impl EngineTaskRunner for FakeRunner {
        fn run(&mut self, _: &EngineTask, _: &mut CancellationState) -> EngineTaskOutcome {
            self.outcomes.remove(0)
        }
    }

    fn scan_id() -> ScanId {
        ScanId::new("018f4c2a-1d3b-7abc-8def-0123456789ab").unwrap()
    }
    fn target_id() -> TargetId {
        TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789ac").unwrap()
    }
    fn plan() -> ScanPlan {
        ScanPlan::new(
            scan_id(),
            vec![
                EngineTask::new(EngineId::new("a").unwrap(), target_id(), 1_000).unwrap(),
                EngineTask::new(EngineId::new("b").unwrap(), target_id(), 1_000).unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn all_pass_is_completed_and_progress_is_bounded_ordered_without_eta() {
        let mut runner = FakeRunner {
            outcomes: vec![
                EngineTaskOutcome::Completed {
                    observations: vec![],
                    elapsed_ms: 10,
                },
                EngineTaskOutcome::Completed {
                    observations: vec![],
                    elapsed_ms: 20,
                },
            ],
        };
        let result = ScanJob::new(plan())
            .execute(&mut runner, &mut CancellationState::Active)
            .unwrap();
        assert_eq!(result.state, ScanState::Completed);
        assert!(
            result
                .progress
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence
                    && pair[0].elapsed_ms <= pair[1].elapsed_ms)
        );
        assert!(
            result.progress.iter().all(|event| event.eta_ms.is_none()
                && event.percent.is_some_and(|percent| percent <= 100))
        );
    }

    #[test]
    fn one_engine_on_two_targets_produces_two_coverage_tasks() {
        let second_target = TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789ad").unwrap();
        let plan = ScanPlan::new(
            scan_id(),
            vec![
                EngineTask::new(EngineId::new("a").unwrap(), target_id(), 1_000).unwrap(),
                EngineTask::new(EngineId::new("a").unwrap(), second_target, 1_000).unwrap(),
            ],
        )
        .unwrap();
        let mut runner = FakeRunner {
            outcomes: vec![
                EngineTaskOutcome::Completed {
                    observations: vec![],
                    elapsed_ms: 1,
                },
                EngineTaskOutcome::Completed {
                    observations: vec![],
                    elapsed_ms: 1,
                },
            ],
        };
        let result = ScanJob::new(plan)
            .execute(&mut runner, &mut CancellationState::Active)
            .unwrap();
        assert_eq!(result.coverage.expected_tasks().len(), 2);
        assert_eq!(result.coverage.engine_results().len(), 2);
        assert!(result.coverage.is_complete());
    }

    #[test]
    fn one_failure_is_partial_and_all_fail_is_failed() {
        let mut partial = FakeRunner {
            outcomes: vec![
                EngineTaskOutcome::Failed {
                    reason: "synthetic".into(),
                    elapsed_ms: 1,
                },
                EngineTaskOutcome::Completed {
                    observations: vec![],
                    elapsed_ms: 1,
                },
            ],
        };
        assert_eq!(
            ScanJob::new(plan())
                .execute(&mut partial, &mut CancellationState::Active)
                .unwrap()
                .state,
            ScanState::Partial
        );
        let mut failed = FakeRunner {
            outcomes: vec![
                EngineTaskOutcome::TimedOut { elapsed_ms: 1 },
                EngineTaskOutcome::TimedOut { elapsed_ms: 1 },
            ],
        };
        assert_eq!(
            ScanJob::new(plan())
                .execute(&mut failed, &mut CancellationState::Active)
                .unwrap()
                .state,
            ScanState::Failed
        );
    }

    #[test]
    fn cancel_requires_cleanup_confirmation() {
        let mut cancelled = FakeRunner {
            outcomes: vec![EngineTaskOutcome::Cancelled {
                elapsed_ms: 1,
                cleanup_confirmed: true,
            }],
        };
        let result = ScanJob::new(plan())
            .execute(&mut cancelled, &mut CancellationState::Active)
            .unwrap();
        assert_eq!(result.state, ScanState::Cancelled);
        assert!(result.cleanup_confirmed);
        let mut orphan = FakeRunner {
            outcomes: vec![EngineTaskOutcome::Cancelled {
                elapsed_ms: 1,
                cleanup_confirmed: false,
            }],
        };
        let result = ScanJob::new(plan())
            .execute(&mut orphan, &mut CancellationState::Active)
            .unwrap();
        assert_eq!(result.state, ScanState::Failed);
        assert!(!result.cleanup_confirmed);
    }

    #[test]
    fn pre_cancel_runs_no_tasks() {
        let mut runner = FakeRunner { outcomes: vec![] };
        let result = ScanJob::new(plan())
            .execute(&mut runner, &mut CancellationState::Requested)
            .unwrap();
        assert_eq!(result.state, ScanState::Cancelled);
        assert_eq!(result.coverage.passed_count(), 0);
    }
}
