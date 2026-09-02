use super::*;
use edy_core::{
    CorrelationEngine, FindingId, FindingIdSource, RiskSignals, ScanId, ScanState, Timestamp,
    VerdictModel,
};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default)]
pub struct InMemoryEventSink {
    events: Arc<Mutex<Vec<PipelineEvent>>>,
    fail_next: Arc<Mutex<bool>>,
}

impl InMemoryEventSink {
    pub fn events(&self) -> Vec<PipelineEvent> {
        self.events.lock().expect("event lock poisoned").clone()
    }

    pub fn fail_next(&self) {
        *self.fail_next.lock().expect("event lock poisoned") = true;
    }
}

impl EventSink for InMemoryEventSink {
    fn emit(&mut self, event: &PipelineEvent) -> Result<(), ServiceError> {
        let mut fail = self
            .fail_next
            .lock()
            .map_err(|_| ServiceError::new("event_sink_failed", "Event delivery is unavailable"))?;
        if std::mem::take(&mut *fail) {
            return Err(ServiceError::new(
                "event_sink_failed",
                "Event delivery is unavailable",
            ));
        }
        drop(fail);
        self.events
            .lock()
            .map_err(|_| ServiceError::new("event_sink_failed", "Event delivery is unavailable"))?
            .push(event.clone());
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryFailurePoint {
    Create,
    Transition,
    Event,
    EngineRun,
    FindingEvidence,
    Finalize,
    Load,
}

#[derive(Debug, Default)]
struct RepositoryState {
    scans: BTreeMap<String, StoredScan>,
    fail_next: Option<RepositoryFailurePoint>,
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryScanRepository {
    state: Arc<Mutex<RepositoryState>>,
}

impl InMemoryScanRepository {
    /// Returns a second repository handle, equivalent to reopening the same durable store.
    pub fn reopen(&self) -> Self {
        self.clone()
    }

    pub fn fail_next(&self, point: RepositoryFailurePoint) {
        self.state
            .lock()
            .expect("repository lock poisoned")
            .fail_next = Some(point);
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, RepositoryState>, ServiceError> {
        self.state
            .lock()
            .map_err(|_| ServiceError::new("storage_unavailable", "Scan storage is unavailable"))
    }

    fn check_failure(
        state: &mut RepositoryState,
        point: RepositoryFailurePoint,
    ) -> Result<(), ServiceError> {
        if state.fail_next == Some(point) {
            state.fail_next = None;
            return Err(ServiceError::new(
                "storage_write_failed",
                "Scan state could not be persisted",
            ));
        }
        Ok(())
    }
}

impl ScanRepository for InMemoryScanRepository {
    fn create(&mut self, scan: StoredScan) -> Result<(), ServiceError> {
        let mut state = self.state()?;
        Self::check_failure(&mut state, RepositoryFailurePoint::Create)?;
        let key = scan.scan_id.as_str().to_owned();
        if state.scans.insert(key, scan).is_some() {
            return Err(ServiceError::new("scan_exists", "Scan already exists"));
        }
        Ok(())
    }

    fn transition(
        &mut self,
        scan_id: &ScanId,
        next: ScanState,
        at: &Timestamp,
    ) -> Result<(), ServiceError> {
        let mut state = self.state()?;
        Self::check_failure(&mut state, RepositoryFailurePoint::Transition)?;
        let scan = state
            .scans
            .get_mut(scan_id.as_str())
            .ok_or_else(|| ServiceError::new("scan_not_found", "Scan was not found"))?;
        scan.state = scan.state.transition(next).map_err(|_| {
            ServiceError::new(
                "invalid_scan_transition",
                "Scan state transition was refused",
            )
        })?;
        if next == ScanState::Running {
            scan.started_at = Some(at.clone());
        }
        if next.is_terminal() {
            scan.finished_at = Some(at.clone());
        }
        Ok(())
    }

    fn persist_event(&mut self, event: PipelineEvent) -> Result<(), ServiceError> {
        let mut state = self.state()?;
        Self::check_failure(&mut state, RepositoryFailurePoint::Event)?;
        let scan = state
            .scans
            .get_mut(event.scan_id.as_str())
            .ok_or_else(|| ServiceError::new("scan_not_found", "Scan was not found"))?;
        if event.sequence != scan.events.len() as u32 {
            return Err(ServiceError::new(
                "event_sequence_invalid",
                "Event sequence is incoherent",
            ));
        }
        scan.events.push(event);
        Ok(())
    }

    fn persist_engine_run(
        &mut self,
        scan_id: &ScanId,
        run: StoredEngineRun,
    ) -> Result<(), ServiceError> {
        let mut state = self.state()?;
        Self::check_failure(&mut state, RepositoryFailurePoint::EngineRun)?;
        let scan = state
            .scans
            .get_mut(scan_id.as_str())
            .ok_or_else(|| ServiceError::new("scan_not_found", "Scan was not found"))?;
        if scan
            .engine_runs
            .iter()
            .any(|item| item.engine.id == run.engine.id)
        {
            return Err(ServiceError::new(
                "engine_run_duplicate",
                "Engine run was already persisted",
            ));
        }
        scan.engine_runs.push(run);
        Ok(())
    }

    fn persist_finding_with_evidence(
        &mut self,
        scan_id: &ScanId,
        finding: edy_core::Finding,
        evidence: Vec<edy_core::Evidence>,
    ) -> Result<(), ServiceError> {
        let mut state = self.state()?;
        Self::check_failure(&mut state, RepositoryFailurePoint::FindingEvidence)?;
        let scan = state
            .scans
            .get_mut(scan_id.as_str())
            .ok_or_else(|| ServiceError::new("scan_not_found", "Scan was not found"))?;
        if evidence.is_empty()
            || evidence
                .iter()
                .any(|item| !finding.evidence_ids().contains(item.id()))
        {
            return Err(ServiceError::new(
                "finding_evidence_invalid",
                "Finding evidence transaction is incoherent",
            ));
        }

        // Stage the entire transaction before publishing it.
        let mut staged_findings = scan.findings.clone();
        let mut staged_evidence = scan.evidence.clone();
        for item in evidence {
            staged_evidence.insert(item.id().as_str().to_owned(), item);
        }
        if let Some(existing) = staged_findings
            .iter_mut()
            .find(|item| item.fingerprint() == finding.fingerprint())
        {
            // Domain correlation already provides the merged view. Preserve first identity and
            // history while accepting only monotonic observation metadata.
            if finding.id() == existing.id() && finding.last_seen() >= existing.last_seen() {
                *existing = finding;
            }
        } else {
            staged_findings.push(finding);
            staged_findings.sort_by(|left, right| left.fingerprint().cmp(right.fingerprint()));
        }
        scan.findings = staged_findings;
        scan.evidence = staged_evidence;
        Ok(())
    }

    fn finalize(
        &mut self,
        scan_id: &ScanId,
        finalization: FinalSnapshot,
    ) -> Result<(), ServiceError> {
        let mut state = self.state()?;
        Self::check_failure(&mut state, RepositoryFailurePoint::Finalize)?;
        let scan = state
            .scans
            .get_mut(scan_id.as_str())
            .ok_or_else(|| ServiceError::new("scan_not_found", "Scan was not found"))?;
        let terminal = scan.state.transition(finalization.state).map_err(|_| {
            ServiceError::new("invalid_scan_transition", "Scan finalization was refused")
        })?;
        if matches!(terminal, ScanState::Completed | ScanState::Partial)
            && (finalization.coverage.is_none()
                || finalization.verdict.is_none()
                || finalization.report_json.is_none())
        {
            return Err(ServiceError::new(
                "final_snapshot_incomplete",
                "Completed scan snapshot is incomplete",
            ));
        }
        if matches!(terminal, ScanState::Failed | ScanState::Cancelled)
            && (finalization.verdict.is_some() || finalization.report_json.is_some())
        {
            return Err(ServiceError::new(
                "unsafe_terminal_result",
                "Failed or cancelled scan cannot expose a final verdict",
            ));
        }
        if finalization.event.scan_id != *scan_id
            || finalization.event.sequence != scan.events.len() as u32
            || finalization.event.at != finalization.at
        {
            return Err(ServiceError::new(
                "event_sequence_invalid",
                "Final event is incoherent",
            ));
        }
        scan.state = terminal;
        scan.finished_at = Some(finalization.at);
        scan.coverage = finalization.coverage;
        scan.verdict = finalization.verdict;
        scan.report_json = finalization.report_json;
        scan.events.push(finalization.event);
        Ok(())
    }

    fn load(&self, scan_id: &ScanId) -> Result<StoredScan, ServiceError> {
        let mut state = self.state()?;
        Self::check_failure(&mut state, RepositoryFailurePoint::Load)?;
        state
            .scans
            .get(scan_id.as_str())
            .cloned()
            .ok_or_else(|| ServiceError::new("scan_not_found", "Scan was not found"))
    }
}

#[derive(Debug, Clone)]
pub struct StaticEngineRegistry {
    engines: Vec<EngineDescriptor>,
    fail: bool,
}

impl StaticEngineRegistry {
    pub fn new(mut engines: Vec<EngineDescriptor>) -> Self {
        engines.sort_by(|left, right| left.id.cmp(&right.id));
        Self {
            engines,
            fail: false,
        }
    }

    pub fn failing(mut self) -> Self {
        self.fail = true;
        self
    }
}

impl EngineRegistry for StaticEngineRegistry {
    fn engines_for(&self, _: &edy_core::Target) -> Result<Vec<EngineDescriptor>, ServiceError> {
        if self.fail {
            Err(ServiceError::new(
                "engine_registry_failed",
                "Engine registry is unavailable",
            ))
        } else {
            Ok(self.engines.clone())
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScriptedExecutor {
    outcomes: VecDeque<Result<ExecutionResult, ServiceError>>,
    executed: Arc<Mutex<Vec<String>>>,
    cancel_on_call: Option<usize>,
}

impl ScriptedExecutor {
    pub fn new(outcomes: impl IntoIterator<Item = ExecutionResult>) -> Self {
        Self {
            outcomes: outcomes.into_iter().map(Ok).collect(),
            executed: Arc::new(Mutex::new(Vec::new())),
            cancel_on_call: None,
        }
    }

    pub fn cancel_on_call(mut self, call: usize) -> Self {
        self.cancel_on_call = Some(call);
        self
    }

    pub fn executed(&self) -> Vec<String> {
        self.executed
            .lock()
            .expect("executor lock poisoned")
            .clone()
    }
}

impl EngineExecutor for ScriptedExecutor {
    fn execute(
        &mut self,
        engine: &EngineDescriptor,
        _: &edy_core::Target,
        _: u64,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionResult, ServiceError> {
        let call = {
            let mut executed = self.executed.lock().map_err(|_| {
                ServiceError::new("executor_failed", "Synthetic executor is unavailable")
            })?;
            executed.push(engine.id.as_str().to_owned());
            executed.len()
        };
        if self.cancel_on_call == Some(call) {
            cancellation.request();
        }
        self.outcomes.pop_front().unwrap_or_else(|| {
            Err(ServiceError::new(
                "executor_script_exhausted",
                "Synthetic executor input is exhausted",
            ))
        })
    }
}

#[derive(Debug, Default)]
pub struct CoreCorrelation {
    pub fail: bool,
}

impl CoreCorrelation {
    pub fn failing() -> Self {
        Self { fail: true }
    }
}

struct SyntheticFindingIds<'a>(&'a mut u64);

impl FindingIdSource for SyntheticFindingIds<'_> {
    fn next_id(&mut self) -> FindingId {
        *self.0 += 1;
        FindingId::new(format!("018f4c2a-1d3b-7abc-8def-{:012x}", *self.0))
            .expect("synthetic UUIDv7 template is valid")
    }
}

impl CorrelationPort for CoreCorrelation {
    fn correlate_findings(
        &mut self,
        scan_id: &edy_core::ScanId,
        target: &edy_core::Target,
        observations: &[edy_core::EngineObservation],
        observed_at: &edy_core::Timestamp,
    ) -> Result<Vec<edy_core::Finding>, ServiceError> {
        if self.fail {
            return Err(ServiceError::new(
                "correlation_failed",
                "Finding correlation could not be completed",
            ));
        }
        // IDs are stable for the same deterministically sorted correlation groups. The service
        // can therefore upsert a later merged view without replacing finding identity.
        let mut next_id = 0;
        CorrelationEngine::correlate(
            scan_id,
            target,
            observations,
            observed_at,
            &mut SyntheticFindingIds(&mut next_id),
        )
        .map_err(|_| {
            ServiceError::new(
                "correlation_failed",
                "Finding correlation could not be completed",
            )
        })
    }

    fn evaluate_verdict(
        &mut self,
        findings: &[edy_core::Finding],
        observations: &[edy_core::EngineObservation],
        coverage: &edy_core::ScanCoverage,
        unavailable: &[edy_core::UnavailableCheck],
    ) -> Result<edy_core::Verdict, ServiceError> {
        if self.fail {
            return Err(ServiceError::new(
                "correlation_failed",
                "Scan verdict could not be calculated",
            ));
        }
        VerdictModel::evaluate(
            findings,
            observations,
            coverage,
            unavailable,
            &RiskSignals::default(),
        )
        .map_err(|_| {
            ServiceError::new("correlation_failed", "Scan verdict could not be calculated")
        })
    }
}

#[derive(Debug, Default)]
pub struct DeterministicJsonReportGenerator {
    pub fail: bool,
}

impl ReportGenerator for DeterministicJsonReportGenerator {
    fn generate(&mut self, input: &ReportInput) -> Result<String, ServiceError> {
        if self.fail {
            return Err(ServiceError::new(
                "report_failed",
                "Scan report could not be generated",
            ));
        }
        serde_json::to_string(input)
            .map_err(|_| ServiceError::new("report_failed", "Scan report could not be generated"))
    }
}
