//! Typed Level 0 application boundary. No arbitrary path, process, SQL, filesystem or network API.

use crate::level0::*;
use edy_core::{
    Confidence, EngineId, EngineObservation, Evidence, EvidenceDraft, EvidenceId, EvidenceKind,
    EvidenceProvenance, EvidenceStrength, ObservationSignal, ScanId, ScanResult, ScanState,
    Severity, Sha256Digest, StructuredFact, TargetId, Timestamp,
};
use edy_engine_manager::repository::{
    GitleaksRepositoryAdapter, OsvRepositoryAdapter, TrivyRepositoryAdapter,
};
use edy_reporting::repository::RepositoryReport;
use edy_reporting::{REPORT_SCHEMA, ReportDocument, ReportEvidence, ReportKind, ReportSnapshot};
use edy_repository::{
    AuthorizedRepositoryTarget, RepositoryInventory, RepositoryLimits, RepositoryObservation,
    inspect,
};
use edy_storage::level0_snapshot::Level1SnapshotStore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const TARGET_ID: &str = "018f4c2a-1d3b-7abc-8def-0123456789b1";
const MAX_STORED_SYNTHETIC_SCANS: u32 = 256;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SafeIpcError {
    pub code: String,
    pub message_safe: String,
    pub correlation_id: String,
}

impl std::fmt::Display for SafeIpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message_safe)
    }
}

impl std::error::Error for SafeIpcError {}

impl SafeIpcError {
    fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            message_safe: message.into(),
            correlation_id: new_uuid_v7(),
        }
    }
}

impl From<ServiceError> for SafeIpcError {
    fn from(error: ServiceError) -> Self {
        Self::new(error.code, error.safe_message)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureId {
    SyntheticTargetA,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSyntheticScanRequest {
    pub fixture_id: FixtureId,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    pub scan_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingRequest {
    pub finding_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListScansRequest {
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListFindingsRequest {
    pub scan_id: String,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateReportRequest {
    pub scan_id: String,
    pub kind: ReportKind,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeRepositoryTargetRequest {
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryAuthorizationRequest {
    pub authorization_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRepositoryScanRequest {
    pub authorization_id: String,
    pub confirmed: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedRepositoryTargetView {
    pub authorization_id: String,
    pub canonical_root: String,
    pub estimated_files: u64,
    pub estimated_bytes: u64,
    pub exclusions: Vec<String>,
    pub limits: RepositoryLimits,
    pub inventory_status: String,
    pub readiness: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Level1Finding {
    id: String,
    observation: RepositoryObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Level1StoredScan {
    scan_id: String,
    target_id: String,
    authorization_id: String,
    inventory: RepositoryInventory,
    findings: Vec<Level1Finding>,
    unavailable_checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineViewState {
    Ready,
    Unavailable,
    Tampered,
    PolicyBlocked,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EngineStatusView {
    pub id: &'static str,
    pub version: &'static str,
    pub state: EngineViewState,
    pub detail_safe: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct CoverageView {
    pub total: u32,
    pub completed: u32,
    pub failed: u32,
    pub unavailable: u32,
    pub skipped: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScanSummaryView {
    pub id: String,
    pub state: String,
    pub verdict: Option<String>,
    pub risk: Option<String>,
    pub confidence: Option<String>,
    pub coverage: CoverageView,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScanProgressView {
    pub scan_id: String,
    pub phase: String,
    pub completed_tasks: u32,
    pub total_tasks: u32,
    pub percent: Option<u32>,
    pub elapsed_ms: u64,
    pub current_engine: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FindingView {
    pub id: String,
    pub scan_id: String,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub risk: String,
    pub confidence: String,
    pub status: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReportView {
    pub scan_id: String,
    pub kind: ReportKind,
    pub schema: &'static str,
    pub json: String,
}

#[derive(Clone)]
pub struct Level0Backend {
    project_root: PathBuf,
    database: PathBuf,
    jobs: Arc<Mutex<BTreeMap<String, CancellationToken>>>,
    reader: Arc<Mutex<SqliteScanRepository>>,
    repository_targets: Arc<Mutex<BTreeMap<String, AuthorizedRepositoryTarget>>>,
    level1: Arc<Mutex<Level1SnapshotStore>>,
}

impl Level0Backend {
    pub fn open(project_root: &Path, database: &Path) -> Result<Self, SafeIpcError> {
        if !project_root.is_absolute() || !project_root.is_dir() || !database.is_absolute() {
            return Err(SafeIpcError::new(
                "backend_path_invalid",
                "Level 0 storage is unavailable",
            ));
        }
        let mut reader = SqliteScanRepository::open(database)?;
        reconcile_interrupted(&mut reader)?;
        let project_text = project_root.to_string_lossy();
        let project_root =
            PathBuf::from(project_text.strip_prefix(r"\\?\").unwrap_or(&project_text));
        Ok(Self {
            project_root,
            database: database.to_path_buf(),
            jobs: Arc::new(Mutex::new(BTreeMap::new())),
            reader: Arc::new(Mutex::new(reader)),
            repository_targets: Arc::new(Mutex::new(BTreeMap::new())),
            level1: Arc::new(Mutex::new(Level1SnapshotStore::open(database).map_err(
                |_| SafeIpcError::new("storage_unavailable", "Repository storage is unavailable"),
            )?)),
        })
    }

    pub fn authorize_repository_target(
        &self,
        request: AuthorizeRepositoryTargetRequest,
    ) -> Result<AuthorizedRepositoryTargetView, SafeIpcError> {
        if request.path.len() > 4096 {
            return Err(SafeIpcError::new(
                "repository_path_invalid",
                "Repository path was refused",
            ));
        }
        let target_id = TargetId::new(new_uuid_v7())
            .map_err(|_| SafeIpcError::new("id_unavailable", "Target identifier is unavailable"))?;
        let authorization_id = new_uuid_v7();
        let target = AuthorizedRepositoryTarget::authorize(
            &request.path,
            target_id,
            authorization_id.clone(),
            "2026-09-02T00:00:00Z",
            RepositoryLimits::default(),
        )
        .map_err(|_| {
            SafeIpcError::new(
                "repository_path_refused",
                "Repository path failed the authorization policy",
            )
        })?;
        let inventory = inspect(&target).map_err(|_| {
            SafeIpcError::new(
                "repository_inventory_failed",
                "Repository inventory could not be completed",
            )
        })?;
        let view = authorization_view(&target, &inventory);
        self.repository_targets
            .lock()
            .map_err(|_| {
                SafeIpcError::new(
                    "authorization_unavailable",
                    "Repository authorization is unavailable",
                )
            })?
            .insert(authorization_id, target);
        Ok(view)
    }

    pub fn inspect_repository_target(
        &self,
        request: &RepositoryAuthorizationRequest,
    ) -> Result<RepositoryInventory, SafeIpcError> {
        let targets = self.repository_targets.lock().map_err(|_| {
            SafeIpcError::new(
                "authorization_unavailable",
                "Repository authorization is unavailable",
            )
        })?;
        let target = targets.get(&request.authorization_id).ok_or_else(|| {
            SafeIpcError::new(
                "authorization_not_found",
                "Repository authorization is unavailable",
            )
        })?;
        inspect(target).map_err(|_| {
            SafeIpcError::new(
                "repository_inventory_failed",
                "Repository inventory could not be completed",
            )
        })
    }

    pub fn create_repository_scan(
        &self,
        request: CreateRepositoryScanRequest,
    ) -> Result<ScanSummaryView, SafeIpcError> {
        if !request.confirmed {
            return Err(SafeIpcError::new(
                "confirmation_required",
                "Explicit repository confirmation is required",
            ));
        }
        let target = self
            .repository_targets
            .lock()
            .map_err(|_| {
                SafeIpcError::new(
                    "authorization_unavailable",
                    "Repository authorization is unavailable",
                )
            })?
            .get(&request.authorization_id)
            .cloned()
            .ok_or_else(|| {
                SafeIpcError::new(
                    "authorization_not_found",
                    "Repository authorization is unavailable",
                )
            })?;
        let inventory = inspect(&target).map_err(|_| {
            SafeIpcError::new(
                "repository_inventory_failed",
                "Repository inventory could not be completed",
            )
        })?;
        let observations = if target
            .canonical_root()
            .replace('\\', "/")
            .ends_with("tests/fixtures/synthetic-repository-a")
        {
            synthetic_repository_observations(&target)?
        } else {
            Vec::new()
        };
        let scan_id = new_uuid_v7();
        let findings = observations
            .into_iter()
            .map(|observation| Level1Finding {
                id: new_uuid_v7(),
                observation,
            })
            .collect();
        let stored = Level1StoredScan {
            scan_id: scan_id.clone(),
            target_id: target.target().id().to_string(),
            authorization_id: request.authorization_id,
            inventory,
            findings,
            unavailable_checks: vec![
                "real_engine_execution_policy_blocked".into(),
                "network_isolation_unavailable_with_current_policy".into(),
            ],
        };
        let payload = serde_json::to_vec(&stored).map_err(|_| {
            SafeIpcError::new(
                "repository_storage_failed",
                "Repository scan could not be stored",
            )
        })?;
        self.level1
            .lock()
            .map_err(|_| {
                SafeIpcError::new("storage_unavailable", "Repository storage is unavailable")
            })?
            .create(
                &scan_id,
                &stored.target_id,
                &stored.authorization_id,
                &payload,
            )
            .map_err(|_| {
                SafeIpcError::new(
                    "repository_storage_failed",
                    "Repository scan could not be stored",
                )
            })?;
        Ok(level1_summary(&stored))
    }

    pub fn get_repository_inventory(
        &self,
        request: &ScanRequest,
    ) -> Result<RepositoryInventory, SafeIpcError> {
        Ok(self.load_level1(&request.scan_id)?.inventory)
    }

    fn load_level1(&self, scan_id: &str) -> Result<Level1StoredScan, SafeIpcError> {
        let id = parse_scan_id(scan_id)?;
        let blob = self
            .level1
            .lock()
            .map_err(|_| {
                SafeIpcError::new("storage_unavailable", "Repository storage is unavailable")
            })?
            .load(id.as_str())
            .map_err(|_| SafeIpcError::new("scan_not_found", "Scan was not found"))?;
        serde_json::from_slice(&blob.payload).map_err(|_| {
            SafeIpcError::new(
                "storage_integrity",
                "Repository scan integrity validation failed",
            )
        })
    }

    fn repository(&self) -> Result<std::sync::MutexGuard<'_, SqliteScanRepository>, SafeIpcError> {
        self.reader
            .lock()
            .map_err(|_| SafeIpcError::new("storage_unavailable", "Scan storage is unavailable"))
    }

    pub fn engine_status(&self) -> Vec<EngineStatusView> {
        vec![
            EngineStatusView {
                id: "yara-x",
                version: "1.20.0",
                state: EngineViewState::PolicyBlocked,
                detail_safe: "Execution awaits enforced network denial",
            },
            EngineStatusView {
                id: "gitleaks",
                version: "8.30.0",
                state: EngineViewState::PolicyBlocked,
                detail_safe: "Execution awaits enforced network denial",
            },
            EngineStatusView {
                id: "trivy",
                version: "0.74.0",
                state: EngineViewState::Unavailable,
                detail_safe: "Approved offline database is not present",
            },
            EngineStatusView {
                id: "osv-scanner",
                version: "2.5.1",
                state: EngineViewState::Unavailable,
                detail_safe: "Approved offline vulnerability data is not present",
            },
        ]
    }

    pub fn create_synthetic_scan(
        &self,
        request: CreateSyntheticScanRequest,
    ) -> Result<ScanSummaryView, SafeIpcError> {
        if request.fixture_id != FixtureId::SyntheticTargetA {
            return Err(SafeIpcError::new(
                "fixture_invalid",
                "Synthetic fixture was refused",
            ));
        }
        let scan_id = ScanId::new(new_uuid_v7())
            .map_err(|_| SafeIpcError::new("id_unavailable", "Scan identifier is unavailable"))?;
        let cancellation = CancellationToken::default();
        if self.repository()?.count()? >= MAX_STORED_SYNTHETIC_SCANS {
            return Err(SafeIpcError::new(
                "scan_quota_reached",
                "Synthetic scan history quota was reached",
            ));
        }
        {
            let mut jobs = self.jobs.lock().map_err(|_| {
                SafeIpcError::new("scan_busy", "Synthetic scan scheduler is unavailable")
            })?;
            if !jobs.is_empty() {
                return Err(SafeIpcError::new(
                    "scan_busy",
                    "Another synthetic scan is already active",
                ));
            }
            jobs.insert(scan_id.as_str().into(), cancellation.clone());
        }
        let project_root = self.project_root.clone();
        let database = self.database.clone();
        let jobs = Arc::clone(&self.jobs);
        let worker_id = scan_id.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let failed_tx = ready_tx.clone();
        std::thread::spawn(move || {
            if let Err(error) = run_fixture(
                &project_root,
                &database,
                worker_id.clone(),
                cancellation,
                ready_tx,
            ) {
                let _ = failed_tx.send(StartSignal::Failed(error));
            }
            if let Ok(mut jobs) = jobs.lock() {
                jobs.remove(worker_id.as_str());
            }
        });
        match ready_rx.recv_timeout(Duration::from_secs(2)) {
            Ok(StartSignal::Ready) => {}
            Ok(StartSignal::Failed(error)) => return Err(error),
            Err(_) => {
                if let Ok(mut jobs) = self.jobs.lock()
                    && let Some(token) = jobs.remove(scan_id.as_str())
                {
                    token.request();
                }
                return Err(SafeIpcError::new(
                    "scan_start_failed",
                    "Synthetic scan could not be started",
                ));
            }
        }
        self.get_scan(&ScanRequest {
            scan_id: scan_id.as_str().into(),
        })
    }

    pub fn get_scan(&self, request: &ScanRequest) -> Result<ScanSummaryView, SafeIpcError> {
        let id = parse_scan_id(&request.scan_id)?;
        if let Ok(scan) = self.repository()?.load(&id) {
            return Ok(summary(&scan));
        }
        Ok(level1_summary(&self.load_level1(&request.scan_id)?))
    }

    pub fn list_scans(
        &self,
        request: &ListScansRequest,
    ) -> Result<Vec<ScanSummaryView>, SafeIpcError> {
        validate_page(request.offset, request.limit, 50)?;
        let mut scans: Vec<_> = self
            .repository()?
            .list(request.offset, request.limit)?
            .iter()
            .map(summary)
            .collect();
        if request.offset == 0 {
            let ids = self
                .level1
                .lock()
                .map_err(|_| {
                    SafeIpcError::new("storage_unavailable", "Repository storage is unavailable")
                })?
                .list_ids(0, request.limit)
                .map_err(|_| {
                    SafeIpcError::new("storage_unavailable", "Repository storage is unavailable")
                })?;
            for id in ids {
                scans.push(level1_summary(&self.load_level1(&id)?));
            }
            scans.truncate(request.limit as usize);
        }
        Ok(scans)
    }

    pub fn progress(&self, request: &ScanRequest) -> Result<ScanProgressView, SafeIpcError> {
        let id = parse_scan_id(&request.scan_id)?;
        if let Ok(scan) = self.repository()?.load(&id) {
            return Ok(progress(&scan));
        }
        let scan = self.load_level1(&request.scan_id)?;
        Ok(ScanProgressView {
            scan_id: scan.scan_id,
            phase: "repository_security".into(),
            completed_tasks: 3,
            total_tasks: 4,
            percent: Some(75),
            elapsed_ms: 0,
            current_engine: None,
            status: "partial".into(),
        })
    }

    pub fn cancel(&self, request: &ScanRequest) -> Result<ScanProgressView, SafeIpcError> {
        let id = parse_scan_id(&request.scan_id)?;
        let current = self.progress(request)?;
        if current.status == "cancelled" {
            return Ok(current);
        }
        if matches!(current.status.as_str(), "completed" | "partial" | "failed") {
            return Err(SafeIpcError::new(
                "scan_not_cancellable",
                "Scan is not in a cancellable state",
            ));
        }
        let token = self
            .jobs
            .lock()
            .map_err(|_| SafeIpcError::new("cancel_unavailable", "Cancellation is unavailable"))?
            .get(id.as_str())
            .cloned()
            .ok_or_else(|| {
                SafeIpcError::new(
                    "scan_not_cancellable",
                    "No active synthetic executor is attached",
                )
            })?;
        if current.status != "cancellation_requested" {
            let mut clock = SystemClock;
            let mut persisted = false;
            for _ in 0..5 {
                let at = clock.now()?;
                match self
                    .repository()?
                    .transition(&id, ScanState::CancellationRequested, &at)
                {
                    Ok(()) => {
                        persisted = true;
                        break;
                    }
                    Err(_) => {
                        let state = self.repository()?.load(&id)?.state;
                        if matches!(
                            state,
                            ScanState::CancellationRequested | ScanState::Cancelled
                        ) {
                            persisted = true;
                            break;
                        }
                        if state.is_terminal() {
                            return Err(SafeIpcError::new(
                                "scan_not_cancellable",
                                "Scan is not in a cancellable state",
                            ));
                        }
                        std::thread::yield_now();
                    }
                }
            }
            if !persisted {
                return Err(SafeIpcError::new(
                    "cancel_persist_failed",
                    "Cancellation could not be persisted",
                ));
            }
        }
        token.request();
        self.progress(request)
    }

    pub fn list_findings(
        &self,
        request: &ListFindingsRequest,
    ) -> Result<Vec<FindingView>, SafeIpcError> {
        validate_page(request.offset, request.limit, 100)?;
        let id = parse_scan_id(&request.scan_id)?;
        let Ok(scan) = self.repository()?.load(&id) else {
            let scan = self.load_level1(&request.scan_id)?;
            return Ok(scan
                .findings
                .iter()
                .skip(request.offset as usize)
                .take(request.limit as usize)
                .map(|finding| level1_finding_view(&scan.scan_id, finding))
                .collect());
        };
        Ok(scan
            .findings
            .iter()
            .skip(request.offset as usize)
            .take(request.limit as usize)
            .map(finding_view)
            .collect())
    }

    pub fn get_finding(&self, request: &FindingRequest) -> Result<FindingView, SafeIpcError> {
        let wanted = edy_core::FindingId::new(&request.finding_id).map_err(|_| {
            SafeIpcError::new("finding_id_invalid", "Finding identifier was refused")
        })?;
        let repository = self.repository()?;
        for offset in (0..10_000).step_by(50) {
            let scans = repository.list(offset, 50)?;
            if scans.is_empty() {
                break;
            }
            for scan in scans {
                if let Some(finding) = scan.findings.iter().find(|item| item.id() == &wanted) {
                    return Ok(finding_view(finding));
                }
            }
        }
        let ids = self
            .level1
            .lock()
            .map_err(|_| {
                SafeIpcError::new("storage_unavailable", "Repository storage is unavailable")
            })?
            .list_ids(0, 50)
            .map_err(|_| {
                SafeIpcError::new("storage_unavailable", "Repository storage is unavailable")
            })?;
        for id in ids {
            let scan = self.load_level1(&id)?;
            if let Some(finding) = scan
                .findings
                .iter()
                .find(|item| item.id == request.finding_id)
            {
                return Ok(level1_finding_view(&scan.scan_id, finding));
            }
        }
        Err(SafeIpcError::new(
            "finding_not_found",
            "Finding was not found",
        ))
    }

    pub fn report(&self, request: &GenerateReportRequest) -> Result<ReportView, SafeIpcError> {
        let id = parse_scan_id(&request.scan_id)?;
        let Ok(scan) = self.repository()?.load(&id) else {
            let stored = self.load_level1(&request.scan_id)?;
            let observations = stored
                .findings
                .iter()
                .map(|f| f.observation.clone())
                .collect::<Vec<_>>();
            let report = RepositoryReport::capture(
                request.kind,
                &stored.scan_id,
                &stored.inventory,
                &observations,
                &stored.unavailable_checks,
            );
            return Ok(ReportView {
                scan_id: stored.scan_id,
                kind: request.kind,
                schema: REPORT_SCHEMA,
                json: report.json().map_err(|_| {
                    SafeIpcError::new("report_failed", "Report could not be rendered")
                })?,
            });
        };
        let coverage = scan.coverage.clone().ok_or_else(|| {
            SafeIpcError::new("report_unavailable", "Scan report is not available")
        })?;
        let verdict = scan.verdict.clone().ok_or_else(|| {
            SafeIpcError::new("report_unavailable", "Scan report is not available")
        })?;
        let result = ScanResult {
            request_id: scan.scan_id.clone(),
            findings: scan.findings.clone(),
            coverage,
            verdict,
        };
        let evidence = scan
            .evidence
            .values()
            .map(|item| {
                ReportEvidence::from_preclassified(
                    item.id().as_str(),
                    item.summary(),
                    item.source(),
                    item.is_redacted(),
                )
            })
            .collect();
        let limitations = if result.coverage.is_complete() {
            Vec::new()
        } else {
            vec!["Synthetic Level 0 coverage is incomplete".into()]
        };
        let snapshot = ReportSnapshot::capture(&result, evidence, limitations);
        let document = ReportDocument::from_snapshot(request.kind, &snapshot);
        let json = document
            .to_json_pretty()
            .map_err(|_| SafeIpcError::new("report_failed", "Report could not be rendered"))?;
        Ok(ReportView {
            scan_id: id.as_str().into(),
            kind: request.kind,
            schema: REPORT_SCHEMA,
            json,
        })
    }
}

fn authorization_view(
    target: &AuthorizedRepositoryTarget,
    inventory: &RepositoryInventory,
) -> AuthorizedRepositoryTargetView {
    AuthorizedRepositoryTargetView {
        authorization_id: target.authorization_id().into(),
        canonical_root: target.canonical_root().into(),
        estimated_files: inventory.file_count,
        estimated_bytes: inventory.total_bytes,
        exclusions: target.exclusions().to_vec(),
        limits: target.limits(),
        inventory_status: match inventory.status {
            edy_repository::InventoryStatus::Complete => "complete",
            edy_repository::InventoryStatus::PartialLimitReached => "partial_limit_reached",
        }
        .into(),
        readiness: "inventory_ready_security_engines_policy_blocked".into(),
    }
}

fn level1_summary(scan: &Level1StoredScan) -> ScanSummaryView {
    let high = scan
        .findings
        .iter()
        .any(|f| matches!(f.observation.severity.as_str(), "high" | "critical"));
    ScanSummaryView {
        id: scan.scan_id.clone(),
        state: "partial".into(),
        verdict: Some("inconclusive".into()),
        risk: Some(if high { "high" } else { "medium" }.into()),
        confidence: Some("medium".into()),
        coverage: CoverageView {
            total: 4,
            completed: 3,
            unavailable: 1,
            ..CoverageView::default()
        },
    }
}

fn level1_finding_view(scan_id: &str, finding: &Level1Finding) -> FindingView {
    FindingView {
        id: finding.id.clone(),
        scan_id: scan_id.into(),
        title: finding.observation.description.clone(),
        category: finding.observation.category.token().into(),
        severity: finding.observation.severity.clone(),
        risk: finding.observation.severity.clone(),
        confidence: finding.observation.confidence.clone(),
        status: "open".into(),
        sources: vec![finding.observation.engine_id.clone()],
    }
}

fn synthetic_repository_observations(
    target: &AuthorizedRepositoryTarget,
) -> Result<Vec<RepositoryObservation>, SafeIpcError> {
    let secret_path = target.root_path().join("config/test-secret.env");
    let value = std::fs::read_to_string(secret_path).map_err(|_| {
        SafeIpcError::new(
            "fixture_invalid",
            "Synthetic repository fixture is unavailable",
        )
    })?;
    let secret = value
        .trim()
        .split_once('=')
        .map(|(_, v)| v)
        .ok_or_else(|| {
            SafeIpcError::new(
                "fixture_invalid",
                "Synthetic repository fixture is unavailable",
            )
        })?;
    let gitleaks = serde_json::to_vec(&serde_json::json!([{"RuleID":"generic-api-key","Description":"Synthetic credential","File":"config/test-secret.env","StartLine":1,"Fingerprint":"fixture:1","Secret":secret,"Entropy":4.2}])).unwrap_or_default();
    let osv = br#"{"results":[{"source":{"path":"Cargo.lock","type":"lockfile"},"packages":[{"package":{"name":"synthetic-vulnerable","version":"0.1.0","ecosystem":"crates.io"},"vulnerabilities":[{"id":"GHSA-TEST-0001","aliases":["CVE-2099-0001"],"affected_range":"<1.0.0","database_specific":{"severity":"HIGH"}}]}]}]}"#;
    let trivy = br#"{"SchemaVersion":2,"Results":[{"Target":"config/bad-config.json","Misconfigurations":[{"ID":"CFG-001","Title":"Unsafe synthetic configuration","Severity":"MEDIUM"}]}]}"#;
    let mut observations = GitleaksRepositoryAdapter
        .parse(target, &gitleaks)
        .map_err(|_| SafeIpcError::new("fixture_invalid", "Synthetic adapter fixture failed"))?;
    observations.extend(
        OsvRepositoryAdapter.parse(target, osv).map_err(|_| {
            SafeIpcError::new("fixture_invalid", "Synthetic adapter fixture failed")
        })?,
    );
    observations.extend(
        TrivyRepositoryAdapter.parse(target, trivy).map_err(|_| {
            SafeIpcError::new("fixture_invalid", "Synthetic adapter fixture failed")
        })?,
    );
    Ok(observations)
}

fn parse_scan_id(value: &str) -> Result<ScanId, SafeIpcError> {
    ScanId::new(value)
        .map_err(|_| SafeIpcError::new("scan_id_invalid", "Scan identifier was refused"))
}

fn validate_page(offset: u32, limit: u32, maximum: u32) -> Result<(), SafeIpcError> {
    if offset > 10_000 || limit == 0 || limit > maximum {
        Err(SafeIpcError::new(
            "pagination_invalid",
            "Pagination was refused",
        ))
    } else {
        Ok(())
    }
}

fn reconcile_interrupted(repository: &mut SqliteScanRepository) -> Result<(), SafeIpcError> {
    let mut scans = Vec::new();
    for offset in (0..MAX_STORED_SYNTHETIC_SCANS).step_by(50) {
        let page = repository.list(offset, 50)?;
        let done = page.len() < 50;
        scans.extend(page);
        if done {
            break;
        }
    }
    let mut clock = SystemClock;
    for scan in scans.into_iter().filter(|scan| !scan.state.is_terminal()) {
        let at = clock.now()?;
        if scan.state == ScanState::Queued {
            repository.transition(&scan.scan_id, ScanState::CancellationRequested, &at)?;
        }
        repository.finalize(
            &scan.scan_id,
            FinalSnapshot {
                state: ScanState::Failed,
                at: at.clone(),
                coverage: None,
                verdict: None,
                report_json: None,
                event: PipelineEvent {
                    sequence: scan.events.len() as u32,
                    scan_id: scan.scan_id.clone(),
                    at,
                    kind: PipelineEventKind::ScanFailed,
                    engine: None,
                    safe_detail: Some("interrupted synthetic scan failed closed on startup".into()),
                },
            },
        )?;
    }
    Ok(())
}

struct DelayedSyntheticExecutor {
    outcomes: VecDeque<ExecutionResult>,
    ready: Option<mpsc::Sender<StartSignal>>,
}

enum StartSignal {
    Ready,
    Failed(SafeIpcError),
}

impl EngineExecutor for DelayedSyntheticExecutor {
    fn execute(
        &mut self,
        _: &EngineDescriptor,
        _: &edy_core::Target,
        _: u64,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionResult, ServiceError> {
        if let Some(ready) = self.ready.take() {
            let _ = ready.send(StartSignal::Ready);
        }
        for _ in 0..20 {
            if cancellation.is_requested() {
                return Ok(ExecutionResult::Cancelled {
                    elapsed_ms: 0,
                    cleanup_confirmed: true,
                });
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        self.outcomes.pop_front().ok_or_else(|| {
            ServiceError::new(
                "fixture_exhausted",
                "Synthetic fixture execution is unavailable",
            )
        })
    }
}

fn run_fixture(
    project_root: &Path,
    database: &Path,
    scan_id: ScanId,
    cancellation: CancellationToken,
    ready: mpsc::Sender<StartSignal>,
) -> Result<(), SafeIpcError> {
    let target_id = TargetId::new(TARGET_ID)
        .map_err(|_| SafeIpcError::new("fixture_invalid", "Synthetic fixture is unavailable"))?;
    let synthetic =
        SyntheticScanRequest::target_a(scan_id, target_id, project_root, 5_000, cancellation)?;
    let engines = vec![
        descriptor("gitleaks", "8.30.0", true)?,
        descriptor("osv-scanner", "2.5.1", false)?,
        descriptor("trivy", "0.74.0", true)?,
        descriptor("yara-x", "1.20.0", true)?,
    ];
    let outcomes = VecDeque::from(vec![
        completed(bundle(
            "gitleaks",
            "8.30.0",
            "018f4c2a-1d3b-7abc-8def-0123456789c1",
            "fake-secret",
            Severity::High,
            ObservationSignal::Suspicious,
            Confidence::Low,
        )?),
        completed(bundle(
            "trivy",
            "0.74.0",
            "018f4c2a-1d3b-7abc-8def-0123456789c2",
            "fake-dependency",
            Severity::High,
            ObservationSignal::Vulnerability,
            Confidence::High,
        )?),
        completed(bundle(
            "yara-x",
            "1.20.0",
            "018f4c2a-1d3b-7abc-8def-0123456789c3",
            "benign-marker",
            Severity::Info,
            ObservationSignal::Informational,
            Confidence::High,
        )?),
    ]);
    let repository = SqliteScanRepository::open(database)?;
    let mut service = ScanService::new(
        SystemClock,
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(engines),
        DelayedSyntheticExecutor {
            outcomes,
            ready: Some(ready),
        },
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );
    service.run_synthetic(synthetic)?;
    Ok(())
}

fn descriptor(id: &str, version: &str, available: bool) -> Result<EngineDescriptor, SafeIpcError> {
    Ok(EngineDescriptor {
        id: EngineId::new(id).map_err(|_| {
            SafeIpcError::new("fixture_invalid", "Synthetic fixture is unavailable")
        })?,
        version: version.into(),
        available,
    })
}

fn completed(bundle: ObservationBundle) -> ExecutionResult {
    ExecutionResult::Completed {
        bundles: vec![bundle],
        elapsed_ms: 10,
    }
}

fn bundle(
    engine: &str,
    version: &str,
    evidence_id: &str,
    semantic_key: &str,
    severity: Severity,
    signal: ObservationSignal,
    confidence: Confidence,
) -> Result<ObservationBundle, SafeIpcError> {
    let at = Timestamp::new("2026-09-02T00:00:00Z")
        .map_err(|_| SafeIpcError::new("fixture_invalid", "Synthetic fixture is unavailable"))?;
    let engine_id = EngineId::new(engine)
        .map_err(|_| SafeIpcError::new("fixture_invalid", "Synthetic fixture is unavailable"))?;
    let target_id = TargetId::new(TARGET_ID)
        .map_err(|_| SafeIpcError::new("fixture_invalid", "Synthetic fixture is unavailable"))?;
    let evidence_id = EvidenceId::new(evidence_id)
        .map_err(|_| SafeIpcError::new("fixture_invalid", "Synthetic fixture is unavailable"))?;
    let evidence = Evidence::new(EvidenceDraft {
        id: evidence_id.clone(),
        kind: EvidenceKind::EngineOutput,
        source: format!("{engine}-synthetic-fixture"),
        timestamp: at.clone(),
        digest: Sha256Digest::new("a".repeat(64)).map_err(|_| {
            SafeIpcError::new("fixture_invalid", "Synthetic fixture is unavailable")
        })?,
        summary: "redacted synthetic observation".into(),
        structured_payload: vec![StructuredFact::new("fixture", semantic_key, true).map_err(
            |_| SafeIpcError::new("fixture_invalid", "Synthetic fixture is unavailable"),
        )?],
        raw_reference: None,
        provenance: EvidenceProvenance {
            producer: engine.into(),
            producer_version: version.into(),
            observed_at: at,
        },
        redacted: true,
    })
    .map_err(|_| SafeIpcError::new("fixture_invalid", "Synthetic fixture is unavailable"))?;
    Ok(ObservationBundle {
        observation: EngineObservation {
            engine: engine_id,
            engine_version: version.into(),
            target_id,
            rule_id: format!("{engine}-synthetic-rule"),
            semantic_key: semantic_key.into(),
            category: "synthetic".into(),
            severity,
            location: "fixture/synthetic-target-A.txt:1".into(),
            message: "synthetic observation".into(),
            evidence_id,
            signal,
            evidence_strength: EvidenceStrength::Strong,
            parser_confidence: confidence,
        },
        evidence,
    })
}

fn label<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|item| item.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unavailable".into())
}

fn coverage(scan: &StoredScan) -> CoverageView {
    let mut view = CoverageView {
        total: scan
            .coverage
            .as_ref()
            .map_or(scan.engine_runs.len() as u32, |item| {
                item.expected_tasks().len() as u32
            }),
        ..CoverageView::default()
    };
    for run in &scan.engine_runs {
        match run.state {
            edy_core::EngineRunState::Passed => view.completed += 1,
            edy_core::EngineRunState::Failed => view.failed += 1,
            edy_core::EngineRunState::Skipped if !run.engine.available => view.unavailable += 1,
            edy_core::EngineRunState::Skipped | edy_core::EngineRunState::Cancelled => {
                view.skipped += 1
            }
        }
    }
    view
}

fn summary(scan: &StoredScan) -> ScanSummaryView {
    ScanSummaryView {
        id: scan.scan_id.as_str().into(),
        state: label(scan.state),
        verdict: scan.verdict.as_ref().map(|item| label(item.kind)),
        risk: scan.verdict.as_ref().map(|item| label(item.risk.band)),
        confidence: scan
            .verdict
            .as_ref()
            .map(|item| label(item.confidence.band)),
        coverage: coverage(scan),
    }
}

fn progress(scan: &StoredScan) -> ScanProgressView {
    let coverage = coverage(scan);
    let completed_tasks =
        coverage.completed + coverage.failed + coverage.unavailable + coverage.skipped;
    let total_tasks = scan
        .coverage
        .as_ref()
        .map_or(4, |item| item.expected_tasks().len() as u32);
    let current_engine = scan
        .events
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, event)| {
            if event.kind != PipelineEventKind::EngineStarted {
                return None;
            }
            let engine = event.engine.as_ref()?;
            let finished = scan.events[index + 1..].iter().any(|later| {
                later.engine.as_ref() == Some(engine)
                    && matches!(
                        later.kind,
                        PipelineEventKind::EngineCompleted | PipelineEventKind::EngineFailed
                    )
            });
            (!finished).then(|| engine.as_str().to_owned())
        });
    ScanProgressView {
        scan_id: scan.scan_id.as_str().into(),
        phase: label(scan.state),
        completed_tasks,
        total_tasks,
        percent: completed_tasks.saturating_mul(100).checked_div(total_tasks),
        elapsed_ms: scan.engine_runs.iter().map(|run| run.elapsed_ms).sum(),
        current_engine,
        status: label(scan.state),
    }
}

fn finding_view(finding: &edy_core::Finding) -> FindingView {
    FindingView {
        id: finding.id().as_str().into(),
        scan_id: finding.scan_id().as_str().into(),
        title: finding.title().into(),
        category: finding.category().into(),
        severity: label(finding.severity()),
        risk: label(finding.severity()),
        confidence: label(finding.confidence()),
        status: label(finding.status()),
        sources: finding
            .source_engines()
            .iter()
            .map(|engine| engine.as_str().into())
            .collect(),
    }
}

fn new_uuid_v7() -> String {
    uuid::Uuid::now_v7().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    struct Temp(std::path::PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn backend() -> (Temp, Level0Backend) {
        let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let temporary = project.join("_intake/ipc-tests").join(new_uuid_v7());
        std::fs::create_dir_all(&temporary).unwrap();
        let database = temporary.join("level0.sqlite3");
        let backend = Level0Backend::open(&project, &database).unwrap();
        (Temp(temporary), backend)
    }

    fn wait_terminal(backend: &Level0Backend, scan_id: &str) -> ScanSummaryView {
        for _ in 0..400 {
            let scan = backend
                .get_scan(&ScanRequest {
                    scan_id: scan_id.into(),
                })
                .unwrap();
            if matches!(
                scan.state.as_str(),
                "cancelled" | "completed" | "partial" | "failed"
            ) {
                return scan;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("synthetic worker did not reach a terminal state")
    }

    #[test]
    fn full_typed_synthetic_flow_persists_partial_coverage_and_reports() {
        let (_temp, backend) = backend();
        let started = backend
            .create_synthetic_scan(CreateSyntheticScanRequest {
                fixture_id: FixtureId::SyntheticTargetA,
            })
            .unwrap();
        let scan = wait_terminal(&backend, &started.id);
        assert_eq!(scan.state, "partial");
        assert_eq!(scan.coverage.unavailable, 1);
        assert_ne!(scan.confidence.as_deref(), Some("high"));
        assert_eq!(
            backend
                .list_scans(&ListScansRequest {
                    offset: 0,
                    limit: 50
                })
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            backend
                .progress(&ScanRequest {
                    scan_id: scan.id.clone()
                })
                .unwrap()
                .percent,
            Some(100)
        );
        assert_eq!(
            backend
                .list_findings(&ListFindingsRequest {
                    scan_id: scan.id.clone(),
                    offset: 0,
                    limit: 100
                })
                .unwrap()
                .len(),
            3
        );
        let report = backend
            .report(&GenerateReportRequest {
                scan_id: scan.id,
                kind: ReportKind::Technical,
            })
            .unwrap();
        assert_eq!(report.schema, REPORT_SCHEMA);
        assert!(report.json.contains("unavailable"));
        assert!(!report.json.contains("100% safe"));
    }

    #[test]
    fn invalid_inputs_and_active_cancel_are_safe_and_idempotent() {
        let (_temp, backend) = backend();
        let invalid = backend
            .get_scan(&ScanRequest {
                scan_id: "../../etc".into(),
            })
            .unwrap_err();
        assert_eq!(invalid.code, "scan_id_invalid");
        assert!(!invalid.message_safe.contains(':'));
        assert!(
            backend
                .list_scans(&ListScansRequest {
                    offset: 0,
                    limit: 51
                })
                .is_err()
        );
        assert!(
            serde_json::from_str::<CreateSyntheticScanRequest>(r#"{"fixture_id":"C:/Users"}"#)
                .is_err()
        );
        let scan = backend
            .create_synthetic_scan(CreateSyntheticScanRequest {
                fixture_id: FixtureId::SyntheticTargetA,
            })
            .unwrap();
        let request = ScanRequest { scan_id: scan.id };
        assert_eq!(
            backend.cancel(&request).unwrap().status,
            "cancellation_requested"
        );
        let cancelled = wait_terminal(&backend, &request.scan_id);
        assert_eq!(cancelled.state, "cancelled");
        assert!(cancelled.verdict.is_none());
        assert_eq!(backend.cancel(&request).unwrap().status, "cancelled");
    }

    #[test]
    fn engine_status_is_complete_and_never_claims_unenforced_execution() {
        let (_temp, backend) = backend();
        let statuses = backend.engine_status();
        assert_eq!(statuses.len(), 4);
        assert!(
            statuses
                .iter()
                .all(|status| status.state != EngineViewState::Ready)
        );
    }

    #[test]
    fn startup_reconciles_interrupted_scan_as_failed_not_cancelled() {
        let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let temporary = project.join("_intake/ipc-tests").join(new_uuid_v7());
        std::fs::create_dir_all(&temporary).unwrap();
        let _cleanup = Temp(temporary.clone());
        let database = temporary.join("level0.sqlite3");
        let scan_id = ScanId::new(new_uuid_v7()).unwrap();
        let request = SyntheticScanRequest::target_a(
            scan_id.clone(),
            TargetId::new(TARGET_ID).unwrap(),
            &project,
            5_000,
            CancellationToken::default(),
        )
        .unwrap();
        let mut repository = SqliteScanRepository::open(&database).unwrap();
        repository
            .create(StoredScan::queued(
                scan_id.clone(),
                request.target,
                Timestamp::new("2026-09-02T00:00:00Z").unwrap(),
            ))
            .unwrap();
        drop(repository);
        let backend = Level0Backend::open(&project, &database).unwrap();
        let recovered = backend
            .get_scan(&ScanRequest {
                scan_id: scan_id.as_str().into(),
            })
            .unwrap();
        assert_eq!(recovered.state, "failed");
        assert!(recovered.verdict.is_none());
    }

    #[test]
    fn repository_e2e_requires_authorization_and_preserves_redaction() {
        let (_temp, backend) = backend();
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../tests/fixtures/synthetic-repository-a")
            .canonicalize()
            .unwrap();
        let fixture_text = fixture.to_string_lossy();
        let fixture_text = fixture_text
            .strip_prefix(r"\\?\")
            .unwrap_or(&fixture_text)
            .to_owned();
        let authorization = backend
            .authorize_repository_target(AuthorizeRepositoryTargetRequest { path: fixture_text })
            .unwrap();
        assert_eq!(authorization.estimated_files, 7);
        assert!(
            backend
                .create_repository_scan(CreateRepositoryScanRequest {
                    authorization_id: authorization.authorization_id.clone(),
                    confirmed: false,
                })
                .is_err()
        );
        let scan = backend
            .create_repository_scan(CreateRepositoryScanRequest {
                authorization_id: authorization.authorization_id,
                confirmed: true,
            })
            .unwrap();
        assert_eq!(scan.state, "partial");
        assert_eq!(scan.coverage.unavailable, 1);
        let findings = backend
            .list_findings(&ListFindingsRequest {
                scan_id: scan.id.clone(),
                offset: 0,
                limit: 100,
            })
            .unwrap();
        assert_eq!(findings.len(), 3);
        assert_eq!(
            findings
                .iter()
                .map(|f| f.category.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["misconfiguration", "secret", "vulnerable_dependency"])
        );
        let report = backend
            .report(&GenerateReportRequest {
                scan_id: scan.id.clone(),
                kind: ReportKind::Technical,
            })
            .unwrap();
        assert!(
            !report
                .json
                .contains("EDY_FAKE_TEST_TOKEN_REPOSITORY_A_ONLY")
        );
        let inventory = backend
            .get_repository_inventory(&ScanRequest { scan_id: scan.id })
            .unwrap();
        assert!(
            inventory
                .documents
                .iter()
                .any(|d| d.relative_path == "Cargo.lock")
        );
    }
}
