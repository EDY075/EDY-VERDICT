use edy_core::{
    EngineCoverage, EngineId, EngineObservation, Evidence, Finding, ScanCoverage, ScanId,
    ScanState, Target, Timestamp, UnavailableCheck, Verdict,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    pub code: &'static str,
    pub safe_message: &'static str,
}

impl ServiceError {
    pub const fn new(code: &'static str, safe_message: &'static str) -> Self {
        Self { code, safe_message }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message)
    }
}

impl std::error::Error for ServiceError {}

pub trait Clock {
    fn now(&mut self) -> Result<Timestamp, ServiceError>;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&mut self) -> Result<Timestamp, ServiceError> {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ServiceError::new("clock_unavailable", "System clock is unavailable"))?
            .as_secs();
        Timestamp::new(format_utc(seconds)).map_err(|_| {
            ServiceError::new(
                "clock_invalid",
                "System clock returned an invalid timestamp",
            )
        })
    }
}

fn format_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

// Howard Hinnant's public-domain civil calendar conversion, shifted to Unix epoch.
fn civil_from_days(days_since_epoch: i64) -> (i64, u64, u64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u64, day as u64)
}

#[derive(Debug, Clone)]
pub struct FakeClock {
    values: std::collections::VecDeque<Timestamp>,
}

impl FakeClock {
    pub fn new(values: impl IntoIterator<Item = Timestamp>) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }
}

impl Clock for FakeClock {
    fn now(&mut self) -> Result<Timestamp, ServiceError> {
        self.values.pop_front().ok_or_else(|| {
            ServiceError::new("clock_exhausted", "Deterministic clock input is exhausted")
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PipelineEventKind {
    ScanCreated,
    ScanStarted,
    EngineStarted,
    EngineProgress,
    FindingObserved,
    EngineCompleted,
    EngineFailed,
    ScanCompleted,
    ScanPartial,
    ScanCancelled,
    ScanFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PipelineEvent {
    pub sequence: u32,
    pub scan_id: ScanId,
    pub at: Timestamp,
    pub kind: PipelineEventKind,
    pub engine: Option<EngineId>,
    pub safe_detail: Option<String>,
}

pub trait EventSink {
    fn emit(&mut self, event: &PipelineEvent) -> Result<(), ServiceError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineDescriptor {
    pub id: EngineId,
    pub version: String,
    pub available: bool,
}

pub trait EngineRegistry {
    fn engines_for(&self, target: &Target) -> Result<Vec<EngineDescriptor>, ServiceError>;
}

#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn request(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservationBundle {
    pub observation: EngineObservation,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionResult {
    Completed {
        bundles: Vec<ObservationBundle>,
        elapsed_ms: u64,
    },
    Failed {
        safe_reason: String,
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

pub trait EngineExecutor {
    fn execute(
        &mut self,
        engine: &EngineDescriptor,
        target: &Target,
        timeout_ms: u64,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionResult, ServiceError>;
}

pub trait CorrelationPort {
    fn correlate_findings(
        &mut self,
        scan_id: &ScanId,
        target: &Target,
        observations: &[EngineObservation],
        observed_at: &Timestamp,
    ) -> Result<Vec<Finding>, ServiceError>;

    fn evaluate_verdict(
        &mut self,
        findings: &[Finding],
        observations: &[EngineObservation],
        coverage: &ScanCoverage,
        unavailable: &[UnavailableCheck],
    ) -> Result<Verdict, ServiceError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportInput {
    pub scan_id: ScanId,
    pub state: ScanState,
    pub coverage: ScanCoverage,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
    pub events: Vec<PipelineEvent>,
}

pub trait ReportGenerator {
    fn generate(&mut self, input: &ReportInput) -> Result<String, ServiceError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredEngineRun {
    pub engine: EngineDescriptor,
    pub state: edy_core::EngineRunState,
    pub elapsed_ms: u64,
    pub observation_count: u32,
    pub cleanup_confirmed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredScan {
    pub scan_id: ScanId,
    pub target: Target,
    pub state: ScanState,
    pub created_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
    pub engine_runs: Vec<StoredEngineRun>,
    pub findings: Vec<Finding>,
    pub evidence: BTreeMap<String, Evidence>,
    pub coverage: Option<ScanCoverage>,
    pub verdict: Option<Verdict>,
    pub report_json: Option<String>,
    pub events: Vec<PipelineEvent>,
}

impl StoredScan {
    pub fn queued(scan_id: ScanId, target: Target, created_at: Timestamp) -> Self {
        Self {
            scan_id,
            target,
            state: ScanState::Queued,
            created_at,
            started_at: None,
            finished_at: None,
            engine_runs: Vec::new(),
            findings: Vec::new(),
            evidence: BTreeMap::new(),
            coverage: None,
            verdict: None,
            report_json: None,
            events: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FinalSnapshot {
    pub state: ScanState,
    pub at: Timestamp,
    pub coverage: Option<ScanCoverage>,
    pub verdict: Option<Verdict>,
    pub report_json: Option<String>,
    pub event: PipelineEvent,
}

pub trait ScanRepository {
    fn create(&mut self, scan: StoredScan) -> Result<(), ServiceError>;
    fn transition(
        &mut self,
        scan_id: &ScanId,
        state: ScanState,
        at: &Timestamp,
    ) -> Result<(), ServiceError>;
    fn persist_event(&mut self, event: PipelineEvent) -> Result<(), ServiceError>;
    fn persist_engine_run(
        &mut self,
        scan_id: &ScanId,
        run: StoredEngineRun,
    ) -> Result<(), ServiceError>;
    /// This operation is an atomic finding + evidence transaction.
    fn persist_finding_with_evidence(
        &mut self,
        scan_id: &ScanId,
        finding: Finding,
        evidence: Vec<Evidence>,
    ) -> Result<(), ServiceError>;
    /// Final state, coverage, verdict and immutable report become visible atomically.
    fn finalize(
        &mut self,
        scan_id: &ScanId,
        finalization: FinalSnapshot,
    ) -> Result<(), ServiceError>;
    fn load(&self, scan_id: &ScanId) -> Result<StoredScan, ServiceError>;
    fn list(&self, offset: u32, limit: u32) -> Result<Vec<StoredScan>, ServiceError>;
    fn count(&self) -> Result<u32, ServiceError>;
}

pub struct StorageEventSink<R> {
    repository: R,
}

impl<R> StorageEventSink<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn into_inner(self) -> R {
        self.repository
    }
}

impl<R: ScanRepository> EventSink for StorageEventSink<R> {
    fn emit(&mut self, event: &PipelineEvent) -> Result<(), ServiceError> {
        self.repository.persist_event(event.clone())
    }
}

#[derive(Debug, Clone)]
pub struct SyntheticScanRequest {
    pub(crate) scan_id: ScanId,
    pub(crate) target: Target,
    pub(crate) timeout_ms: u64,
    pub(crate) cancellation: CancellationToken,
}

impl SyntheticScanRequest {
    /// Constructs the sole Level 0 target from a backend-controlled project root. No caller-
    /// supplied target path crosses the IPC boundary.
    pub fn target_a(
        scan_id: ScanId,
        target_id: edy_core::TargetId,
        project_root: &std::path::Path,
        timeout_ms: u64,
        cancellation: CancellationToken,
    ) -> Result<Self, ServiceError> {
        if !project_root.is_absolute()
            || project_root
                .file_name()
                .is_none_or(|name| name != "EDY-VERDICT")
        {
            return Err(ServiceError::new(
                "project_root_invalid",
                "Controlled synthetic fixture root is invalid",
            ));
        }
        let fixture = project_root.join("_intake").join("synthetic-target-A");
        let locator =
            edy_core::TargetLocator::new_local_path(fixture.to_string_lossy()).map_err(|_| {
                ServiceError::new(
                    "synthetic_target_invalid",
                    "Controlled synthetic target is invalid",
                )
            })?;
        let target =
            Target::new(target_id, edy_core::TargetKind::Repository, locator).map_err(|_| {
                ServiceError::new(
                    "synthetic_target_invalid",
                    "Controlled synthetic target is invalid",
                )
            })?;
        Ok(Self {
            scan_id,
            target,
            timeout_ms,
            cancellation,
        })
    }

    pub fn scan_id(&self) -> &ScanId {
        &self.scan_id
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanOutcome {
    pub scan_id: ScanId,
    pub state: ScanState,
    pub coverage: Option<ScanCoverage>,
    pub verdict: Option<Verdict>,
    pub report_json: Option<String>,
    pub cleanup_confirmed: bool,
}

pub fn coverage_from_runs(
    target: &Target,
    engines: &[EngineDescriptor],
    runs: &[StoredEngineRun],
) -> Result<ScanCoverage, ServiceError> {
    let expected = engines
        .iter()
        .map(|engine| edy_core::CoverageTask {
            engine: engine.id.clone(),
            target_id: target.id().clone(),
        })
        .collect();
    let actual = engines
        .iter()
        .map(|engine| {
            runs.iter().find(|run| run.engine.id == engine.id).map_or(
                EngineCoverage {
                    engine: engine.id.clone(),
                    target_id: target.id().clone(),
                    state: edy_core::EngineRunState::Skipped,
                    evidence_obtained: 0,
                },
                |run| EngineCoverage {
                    engine: engine.id.clone(),
                    target_id: target.id().clone(),
                    state: run.state,
                    evidence_obtained: run.observation_count,
                },
            )
        })
        .collect();
    ScanCoverage::new(expected, actual)
        .map_err(|_| ServiceError::new("coverage_invalid", "Scan coverage is incoherent"))
}
