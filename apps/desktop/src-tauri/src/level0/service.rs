use super::*;
use edy_core::{EngineRunState, ScanState, UnavailableCheck};

pub struct ScanService<C, E, S, G, X, K, R> {
    clock: C,
    event_sink: E,
    storage: S,
    registry: G,
    executor: X,
    correlation: K,
    reports: R,
}

impl<C, E, S, G, X, K, R> ScanService<C, E, S, G, X, K, R>
where
    C: Clock,
    E: EventSink,
    S: ScanRepository,
    G: EngineRegistry,
    X: EngineExecutor,
    K: CorrelationPort,
    R: ReportGenerator,
{
    pub fn new(
        clock: C,
        event_sink: E,
        storage: S,
        registry: G,
        executor: X,
        correlation: K,
        reports: R,
    ) -> Self {
        Self {
            clock,
            event_sink,
            storage,
            registry,
            executor,
            correlation,
            reports,
        }
    }

    pub fn into_parts(self) -> (C, E, S, G, X, K, R) {
        (
            self.clock,
            self.event_sink,
            self.storage,
            self.registry,
            self.executor,
            self.correlation,
            self.reports,
        )
    }

    pub fn run_synthetic(
        &mut self,
        request: SyntheticScanRequest,
    ) -> Result<ScanOutcome, ServiceError> {
        let scan_id = request.scan_id.clone();
        let result = self.run_synthetic_inner(request);
        if result.is_err() {
            self.best_effort_fail(&scan_id);
        }
        result
    }

    fn run_synthetic_inner(
        &mut self,
        request: SyntheticScanRequest,
    ) -> Result<ScanOutcome, ServiceError> {
        if request.timeout_ms == 0 || request.timeout_ms > 600_000 {
            return Err(ServiceError::new(
                "timeout_invalid",
                "Synthetic scan timeout is outside the allowed range",
            ));
        }
        if !matches!(
            request.target.kind(),
            edy_core::TargetKind::Repository | edy_core::TargetKind::File
        ) {
            return Err(ServiceError::new(
                "target_not_synthetic",
                "Only controlled synthetic targets are accepted",
            ));
        }

        let created_at = self.clock.now()?;
        self.storage.create(StoredScan::queued(
            request.scan_id.clone(),
            request.target.clone(),
            created_at.clone(),
        ))?;
        self.emit(
            &request.scan_id,
            created_at,
            PipelineEventKind::ScanCreated,
            None,
            None,
        )?;

        if request.cancellation.is_requested() {
            let at = self.clock.now()?;
            self.storage
                .transition(&request.scan_id, ScanState::CancellationRequested, &at)?;
            return self.finish_without_result(
                &request.scan_id,
                ScanState::Cancelled,
                at,
                PipelineEventKind::ScanCancelled,
                true,
            );
        }

        let engines = match self.registry.engines_for(&request.target) {
            Ok(engines) if !engines.is_empty() && engines.len() <= 64 => engines,
            Ok(_) => {
                let error = ServiceError::new(
                    "scan_plan_invalid",
                    "Synthetic scan plan has no bounded engine tasks",
                );
                self.best_effort_fail(&request.scan_id);
                return Err(error);
            }
            Err(error) => {
                self.best_effort_fail(&request.scan_id);
                return Err(error);
            }
        };
        if engines.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            let error = ServiceError::new(
                "scan_plan_invalid",
                "Synthetic scan plan is not uniquely ordered",
            );
            self.best_effort_fail(&request.scan_id);
            return Err(error);
        }

        let preparing_at = self.clock.now()?;
        self.storage
            .transition(&request.scan_id, ScanState::Preparing, &preparing_at)?;
        let started_at = self.clock.now()?;
        self.storage
            .transition(&request.scan_id, ScanState::Running, &started_at)?;
        self.emit(
            &request.scan_id,
            started_at,
            PipelineEventKind::ScanStarted,
            None,
            None,
        )?;

        let mut runs = Vec::with_capacity(engines.len());
        let mut bundles = Vec::new();
        let unavailable: Vec<UnavailableCheck> = Vec::new();
        let mut cleanup_confirmed = true;

        for (index, engine) in engines.iter().enumerate() {
            if request.cancellation.is_requested() {
                self.persist_cancelled_remaining(&request.scan_id, &engines[index..], &mut runs)?;
                let at = self.clock.now()?;
                self.storage
                    .transition(&request.scan_id, ScanState::CancellationRequested, &at)?;
                return self.finish_without_result(
                    &request.scan_id,
                    ScanState::Cancelled,
                    at,
                    PipelineEventKind::ScanCancelled,
                    cleanup_confirmed,
                );
            }

            let engine_at = self.clock.now()?;
            if !engine.available {
                let run = StoredEngineRun {
                    engine: engine.clone(),
                    state: EngineRunState::Skipped,
                    elapsed_ms: 0,
                    observation_count: 0,
                    cleanup_confirmed: true,
                };
                self.storage
                    .persist_engine_run(&request.scan_id, run.clone())?;
                runs.push(run);
                self.emit(
                    &request.scan_id,
                    engine_at,
                    PipelineEventKind::EngineFailed,
                    Some(engine.id.clone()),
                    Some("engine unavailable for synthetic check".into()),
                )?;
                continue;
            }

            self.emit(
                &request.scan_id,
                engine_at,
                PipelineEventKind::EngineStarted,
                Some(engine.id.clone()),
                None,
            )?;
            let result = match self.executor.execute(
                engine,
                &request.target,
                request.timeout_ms,
                &request.cancellation,
            ) {
                Ok(result) => result,
                Err(error) => {
                    self.best_effort_fail(&request.scan_id);
                    return Err(error);
                }
            };
            let completed_at = self.clock.now()?;
            self.emit(
                &request.scan_id,
                completed_at.clone(),
                PipelineEventKind::EngineProgress,
                Some(engine.id.clone()),
                Some("synthetic engine task returned".into()),
            )?;

            match result {
                ExecutionResult::Completed {
                    bundles: task_bundles,
                    elapsed_ms,
                } if elapsed_ms <= request.timeout_ms && !request.cancellation.is_requested() => {
                    validate_bundles(engine, &request.target, &task_bundles)?;
                    bundles.extend(task_bundles.clone());
                    let observations = bundles
                        .iter()
                        .map(|bundle| bundle.observation.clone())
                        .collect::<Vec<_>>();
                    let findings = match self.correlation.correlate_findings(
                        &request.scan_id,
                        &request.target,
                        &observations,
                        &completed_at,
                    ) {
                        Ok(findings) => findings,
                        Err(error) => {
                            self.best_effort_fail(&request.scan_id);
                            return Err(error);
                        }
                    };
                    for finding in findings {
                        let observed_by_current_engine = task_bundles
                            .iter()
                            .any(|bundle| finding.evidence_ids().contains(bundle.evidence.id()));
                        let evidence = bundles
                            .iter()
                            .filter(|bundle| finding.evidence_ids().contains(bundle.evidence.id()))
                            .map(|bundle| bundle.evidence.clone())
                            .collect::<Vec<_>>();
                        self.storage.persist_finding_with_evidence(
                            &request.scan_id,
                            finding.clone(),
                            evidence,
                        )?;
                        if observed_by_current_engine {
                            self.emit(
                                &request.scan_id,
                                completed_at.clone(),
                                PipelineEventKind::FindingObserved,
                                Some(engine.id.clone()),
                                Some(finding.fingerprint().as_str().into()),
                            )?;
                        }
                    }
                    let run = StoredEngineRun {
                        engine: engine.clone(),
                        state: EngineRunState::Passed,
                        elapsed_ms,
                        observation_count: task_bundles.len() as u32,
                        cleanup_confirmed: true,
                    };
                    self.storage
                        .persist_engine_run(&request.scan_id, run.clone())?;
                    runs.push(run);
                    self.emit(
                        &request.scan_id,
                        completed_at,
                        PipelineEventKind::EngineCompleted,
                        Some(engine.id.clone()),
                        None,
                    )?;
                }
                ExecutionResult::Completed { elapsed_ms, .. }
                | ExecutionResult::TimedOut { elapsed_ms } => {
                    let run = StoredEngineRun {
                        engine: engine.clone(),
                        state: EngineRunState::Failed,
                        elapsed_ms,
                        observation_count: 0,
                        cleanup_confirmed: true,
                    };
                    self.storage
                        .persist_engine_run(&request.scan_id, run.clone())?;
                    runs.push(run);
                    self.emit(
                        &request.scan_id,
                        completed_at,
                        PipelineEventKind::EngineFailed,
                        Some(engine.id.clone()),
                        Some("engine timeout".into()),
                    )?;
                }
                ExecutionResult::Failed {
                    safe_reason,
                    elapsed_ms,
                } => {
                    if safe_reason.is_empty() || safe_reason.len() > 512 {
                        self.best_effort_fail(&request.scan_id);
                        return Err(ServiceError::new(
                            "engine_failure_invalid",
                            "Engine failure detail was refused",
                        ));
                    }
                    let run = StoredEngineRun {
                        engine: engine.clone(),
                        state: EngineRunState::Failed,
                        elapsed_ms,
                        observation_count: 0,
                        cleanup_confirmed: true,
                    };
                    self.storage
                        .persist_engine_run(&request.scan_id, run.clone())?;
                    runs.push(run);
                    self.emit(
                        &request.scan_id,
                        completed_at,
                        PipelineEventKind::EngineFailed,
                        Some(engine.id.clone()),
                        Some(safe_reason),
                    )?;
                }
                ExecutionResult::Cancelled {
                    elapsed_ms,
                    cleanup_confirmed: cleanup,
                } => {
                    cleanup_confirmed &= cleanup;
                    let run = StoredEngineRun {
                        engine: engine.clone(),
                        state: EngineRunState::Cancelled,
                        elapsed_ms,
                        observation_count: 0,
                        cleanup_confirmed: cleanup,
                    };
                    self.storage
                        .persist_engine_run(&request.scan_id, run.clone())?;
                    runs.push(run);
                    self.persist_cancelled_remaining(
                        &request.scan_id,
                        &engines[index + 1..],
                        &mut runs,
                    )?;
                    request.cancellation.request();
                    self.storage.transition(
                        &request.scan_id,
                        ScanState::CancellationRequested,
                        &completed_at,
                    )?;
                    return if cleanup_confirmed {
                        self.finish_without_result(
                            &request.scan_id,
                            ScanState::Cancelled,
                            completed_at,
                            PipelineEventKind::ScanCancelled,
                            true,
                        )
                    } else {
                        self.finish_without_result(
                            &request.scan_id,
                            ScanState::Failed,
                            completed_at,
                            PipelineEventKind::ScanFailed,
                            false,
                        )
                    };
                }
            }
        }

        let coverage = coverage_from_runs(&request.target, &engines, &runs)?;
        let passed = coverage.passed_count();
        let terminal = if coverage.is_complete() {
            ScanState::Completed
        } else if passed > 0 {
            ScanState::Partial
        } else {
            ScanState::Failed
        };
        if terminal == ScanState::Failed {
            let at = self.clock.now()?;
            return self.finish_without_result(
                &request.scan_id,
                ScanState::Failed,
                at,
                PipelineEventKind::ScanFailed,
                cleanup_confirmed,
            );
        }

        let observations = bundles
            .iter()
            .map(|bundle| bundle.observation.clone())
            .collect::<Vec<_>>();
        let snapshot = self.storage.load(&request.scan_id)?;
        let verdict = match self.correlation.evaluate_verdict(
            &snapshot.findings,
            &observations,
            &coverage,
            &unavailable,
        ) {
            Ok(verdict) => verdict,
            Err(error) => {
                self.best_effort_fail(&request.scan_id);
                return Err(error);
            }
        };
        let finished_at = self.clock.now()?;
        let final_kind = if terminal == ScanState::Completed {
            PipelineEventKind::ScanCompleted
        } else {
            PipelineEventKind::ScanPartial
        };
        let final_event = self.make_event(
            &request.scan_id,
            finished_at.clone(),
            final_kind,
            None,
            None,
        )?;
        let mut report_events = snapshot.events.clone();
        report_events.push(final_event.clone());
        let report_input = ReportInput {
            scan_id: request.scan_id.clone(),
            state: terminal,
            coverage: coverage.clone(),
            findings: snapshot.findings,
            verdict: verdict.clone(),
            events: report_events,
        };
        let report_json = match self.reports.generate(&report_input) {
            Ok(report) => report,
            Err(error) => {
                self.best_effort_fail(&request.scan_id);
                return Err(error);
            }
        };
        self.storage.finalize(
            &request.scan_id,
            FinalSnapshot {
                state: terminal,
                at: finished_at,
                coverage: Some(coverage.clone()),
                verdict: Some(verdict.clone()),
                report_json: Some(report_json.clone()),
                event: final_event.clone(),
            },
        )?;
        self.event_sink.emit(&final_event)?;
        Ok(ScanOutcome {
            scan_id: request.scan_id,
            state: terminal,
            coverage: Some(coverage),
            verdict: Some(verdict),
            report_json: Some(report_json),
            cleanup_confirmed,
        })
    }

    fn persist_cancelled_remaining(
        &mut self,
        scan_id: &edy_core::ScanId,
        engines: &[EngineDescriptor],
        runs: &mut Vec<StoredEngineRun>,
    ) -> Result<(), ServiceError> {
        for engine in engines {
            let run = StoredEngineRun {
                engine: engine.clone(),
                state: EngineRunState::Cancelled,
                elapsed_ms: 0,
                observation_count: 0,
                cleanup_confirmed: true,
            };
            self.storage.persist_engine_run(scan_id, run.clone())?;
            runs.push(run);
        }
        Ok(())
    }

    fn emit(
        &mut self,
        scan_id: &edy_core::ScanId,
        at: edy_core::Timestamp,
        kind: PipelineEventKind,
        engine: Option<edy_core::EngineId>,
        safe_detail: Option<String>,
    ) -> Result<(), ServiceError> {
        let event = self.make_event(scan_id, at, kind, engine, safe_detail)?;
        self.storage.persist_event(event.clone())?;
        self.event_sink.emit(&event)
    }

    fn make_event(
        &self,
        scan_id: &edy_core::ScanId,
        at: edy_core::Timestamp,
        kind: PipelineEventKind,
        engine: Option<edy_core::EngineId>,
        safe_detail: Option<String>,
    ) -> Result<PipelineEvent, ServiceError> {
        if safe_detail.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 512 || value.contains(['\r', '\n', '\0'])
        }) {
            return Err(ServiceError::new(
                "event_detail_invalid",
                "Event detail was refused",
            ));
        }
        let sequence = self.storage.load(scan_id)?.events.len() as u32;
        Ok(PipelineEvent {
            sequence,
            scan_id: scan_id.clone(),
            at,
            kind,
            engine,
            safe_detail,
        })
    }

    fn finish_without_result(
        &mut self,
        scan_id: &edy_core::ScanId,
        terminal: ScanState,
        at: edy_core::Timestamp,
        kind: PipelineEventKind,
        cleanup_confirmed: bool,
    ) -> Result<ScanOutcome, ServiceError> {
        let event = self.make_event(scan_id, at.clone(), kind, None, None)?;
        self.storage.finalize(
            scan_id,
            FinalSnapshot {
                state: terminal,
                at,
                coverage: None,
                verdict: None,
                report_json: None,
                event: event.clone(),
            },
        )?;
        self.event_sink.emit(&event)?;
        Ok(ScanOutcome {
            scan_id: scan_id.clone(),
            state: terminal,
            coverage: None,
            verdict: None,
            report_json: None,
            cleanup_confirmed,
        })
    }

    fn best_effort_fail(&mut self, scan_id: &edy_core::ScanId) {
        let Ok(scan) = self.storage.load(scan_id) else {
            return;
        };
        if scan.state.is_terminal() {
            return;
        }
        let Ok(at) = self.clock.now() else {
            return;
        };
        let mut current = scan.state;
        if current == ScanState::Queued
            && self
                .storage
                .transition(scan_id, ScanState::Preparing, &at)
                .is_ok()
        {
            current = ScanState::Preparing;
        }
        if (current == ScanState::CancellationRequested
            || current == ScanState::Preparing
            || current == ScanState::Running)
            && let Ok(event) = self.make_event(
                scan_id,
                at.clone(),
                PipelineEventKind::ScanFailed,
                None,
                None,
            )
        {
            let _ = self.storage.finalize(
                scan_id,
                FinalSnapshot {
                    state: ScanState::Failed,
                    at,
                    coverage: None,
                    verdict: None,
                    report_json: None,
                    event: event.clone(),
                },
            );
            let _ = self.event_sink.emit(&event);
        }
    }
}

fn validate_bundles(
    engine: &EngineDescriptor,
    target: &edy_core::Target,
    bundles: &[ObservationBundle],
) -> Result<(), ServiceError> {
    if bundles.len() > 10_000 {
        return Err(ServiceError::new(
            "engine_output_too_large",
            "Synthetic engine output exceeded the allowed limit",
        ));
    }
    if bundles.iter().any(|bundle| {
        bundle.observation.validate().is_err()
            || bundle.observation.engine != engine.id
            || bundle.observation.target_id != *target.id()
            || bundle.observation.evidence_id != *bundle.evidence.id()
            || !bundle.evidence.is_redacted()
    }) {
        return Err(ServiceError::new(
            "engine_output_invalid",
            "Synthetic engine output was refused",
        ));
    }
    Ok(())
}
