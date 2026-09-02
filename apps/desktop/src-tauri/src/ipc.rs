//! Typed Level 0 application boundary. No arbitrary path, process, SQL, filesystem or network API.

use crate::level0::*;
use edy_core::{
    Confidence, EngineId, EngineObservation, Evidence, EvidenceDraft, EvidenceId, EvidenceKind,
    EvidenceProvenance, EvidenceStrength, ObservationSignal, ScanId, ScanResult, ScanState,
    Severity, Sha256Digest, StructuredFact, TargetId, Timestamp,
};
use edy_engine_manager::file_security::{
    AuthorizedFileTarget, DEFAULT_MAX_FILE_SIZE, FileAnalysis, FileSecurityErrorKind,
    FileTargetPreview, analyze_authorized_file, authorize_file_target, inspect_file_target,
    normalize_file_analysis,
};
use edy_engine_manager::repository::{
    GitleaksRepositoryAdapter, OsvRepositoryAdapter, TrivyRepositoryAdapter,
};
use edy_reporting::file::FileReport;
use edy_reporting::repository::RepositoryReport;
use edy_reporting::{REPORT_SCHEMA, ReportDocument, ReportEvidence, ReportKind, ReportSnapshot};
use edy_repository::{
    AuthorizedRepositoryTarget, CorrelatedRepositoryFinding, LicenseState,
    RepositoryEvidenceReference, RepositoryInventory, RepositoryLimits, RepositoryObservation,
    aggregate_repository_posture, correlate_repository_observations, inspect, inspect_revalidated,
    normalize_license_state,
};
use edy_storage::level0_snapshot::{Level1SnapshotStore, Level2SnapshotStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectFileTargetRequest {
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeFileTargetRequest {
    pub preview_id: String,
    pub confirmed: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FileTargetPreviewView {
    pub preview_id: String,
    #[serde(flatten)]
    pub preview: FileTargetPreview,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFileScanRequest {
    pub authorization_id: String,
    pub confirmed: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedFileTargetView {
    pub authorization_id: String,
    pub canonical_path: String,
    pub size: u64,
    pub detected_type: String,
    pub proposed_checks: Vec<String>,
    pub policy_limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileAnalysisView {
    pub scan_id: String,
    pub state: String,
    pub progress: ScanProgressView,
    pub analysis: Option<FileAnalysis>,
    pub terminal_error: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepositoryAuthorizationSession {
    target: AuthorizedRepositoryTarget,
    preview_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileAuthorizationSession {
    target: AuthorizedFileTarget,
    preview: FileTargetPreview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Level2StoredScan {
    scan_id: String,
    target_id: String,
    authorization_id: String,
    canonical_target_id: String,
    state: String,
    progress: ScanProgressView,
    analysis: Option<FileAnalysis>,
    terminal_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Level1StoredScan {
    scan_id: String,
    target_id: String,
    authorization_id: String,
    state: String,
    progress: ScanProgressView,
    inventory: RepositoryInventory,
    observations: Vec<RepositoryObservation>,
    findings: Vec<CorrelatedRepositoryFinding>,
    evidence: Vec<RepositoryEvidenceReference>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    pub affected_component: String,
    pub rule_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub remediation_guidance: String,
    pub limitations: Vec<String>,
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
    repository_targets: Arc<Mutex<BTreeMap<String, RepositoryAuthorizationSession>>>,
    file_targets: Arc<Mutex<BTreeMap<String, FileAuthorizationSession>>>,
    file_previews: Arc<Mutex<BTreeMap<String, FileTargetPreview>>>,
    level1: Arc<Mutex<Level1SnapshotStore>>,
    level2: Arc<Mutex<Level2SnapshotStore>>,
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
        let mut level2 = Level2SnapshotStore::open(database).map_err(|_| {
            SafeIpcError::new(
                "storage_unavailable",
                "File analysis storage is unavailable",
            )
        })?;
        reconcile_interrupted_level2(&mut level2)?;
        Ok(Self {
            project_root,
            database: database.to_path_buf(),
            jobs: Arc::new(Mutex::new(BTreeMap::new())),
            reader: Arc::new(Mutex::new(reader)),
            repository_targets: Arc::new(Mutex::new(BTreeMap::new())),
            file_targets: Arc::new(Mutex::new(BTreeMap::new())),
            file_previews: Arc::new(Mutex::new(BTreeMap::new())),
            level1: Arc::new(Mutex::new(Level1SnapshotStore::open(database).map_err(
                |_| SafeIpcError::new("storage_unavailable", "Repository storage is unavailable"),
            )?)),
            level2: Arc::new(Mutex::new(level2)),
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
            .insert(
                authorization_id,
                RepositoryAuthorizationSession {
                    target,
                    preview_fingerprint: inventory.structural_fingerprint.clone(),
                },
            );
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
        let session = targets.get(&request.authorization_id).ok_or_else(|| {
            SafeIpcError::new(
                "authorization_not_found",
                "Repository authorization is unavailable",
            )
        })?;
        inspect_revalidated(&session.target, &session.preview_fingerprint).map_err(|error| {
            if error.code() == "revalidation_required" {
                SafeIpcError::new(
                    "repository_revalidation_required",
                    "Repository changed; authorization must be renewed",
                )
            } else {
                SafeIpcError::new(
                    "repository_inventory_failed",
                    "Repository inventory could not be completed",
                )
            }
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
        let session = self
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
        let inventory = inspect_revalidated(&session.target, &session.preview_fingerprint)
            .map_err(|error| {
                if error.code() == "revalidation_required" {
                    SafeIpcError::new(
                        "repository_revalidation_required",
                        "Repository changed; authorization must be renewed",
                    )
                } else {
                    SafeIpcError::new(
                        "repository_inventory_failed",
                        "Repository inventory could not be completed",
                    )
                }
            })?;
        let scan_id = new_uuid_v7();
        let unavailable_checks = vec![
            "real_engine_execution_policy_blocked".into(),
            "network_isolation_unavailable_with_current_policy".into(),
        ];
        let stored = Level1StoredScan {
            scan_id: scan_id.clone(),
            target_id: session.target.target().id().to_string(),
            authorization_id: request.authorization_id,
            state: "preparing".into(),
            progress: ScanProgressView {
                scan_id: scan_id.clone(),
                phase: "inventory".into(),
                completed_tasks: 0,
                total_tasks: 7,
                percent: Some(0),
                elapsed_ms: 0,
                current_engine: None,
                status: "preparing".into(),
            },
            inventory,
            observations: Vec::new(),
            findings: Vec::new(),
            evidence: Vec::new(),
            unavailable_checks,
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
        let cancellation = CancellationToken::default();
        self.jobs
            .lock()
            .map_err(|_| SafeIpcError::new("scan_busy", "Scan scheduler is unavailable"))?
            .insert(scan_id.clone(), cancellation.clone());
        let level1 = Arc::clone(&self.level1);
        let jobs = Arc::clone(&self.jobs);
        let worker_scan_id = scan_id.clone();
        std::thread::spawn(move || {
            let mut worker_scan = stored;
            if run_repository_fixture(&level1, session, &mut worker_scan, cancellation).is_err() {
                worker_scan.state = "failed".into();
                worker_scan.progress.status = "failed".into();
                worker_scan.progress.current_engine = None;
                let _ = replace_level1_snapshot(&level1, &worker_scan);
            }
            if let Ok(mut active) = jobs.lock() {
                active.remove(&worker_scan_id);
            }
        });
        self.get_scan(&ScanRequest { scan_id })
    }

    pub fn inspect_file_target(
        &self,
        request: InspectFileTargetRequest,
    ) -> Result<FileTargetPreviewView, SafeIpcError> {
        if request.path.len() > 4096 {
            return Err(SafeIpcError::new(
                "file_path_invalid",
                "File path was refused",
            ));
        }
        let preview = inspect_file_target(&request.path, DEFAULT_MAX_FILE_SIZE)
            .map_err(file_security_error)?;
        let preview_id = new_uuid_v7();
        let mut previews = self
            .file_previews
            .lock()
            .map_err(|_| SafeIpcError::new("preview_unavailable", "File preview is unavailable"))?;
        // Keep only a bounded, process-local set. No preview survives an application restart.
        if previews.len() >= 64 {
            return Err(SafeIpcError::new(
                "preview_limit",
                "File preview session limit reached",
            ));
        }
        previews.insert(preview_id.clone(), preview.clone());
        Ok(FileTargetPreviewView {
            preview_id,
            preview,
        })
    }

    pub fn authorize_file_target(
        &self,
        request: AuthorizeFileTargetRequest,
    ) -> Result<AuthorizedFileTargetView, SafeIpcError> {
        if !request.confirmed {
            return Err(SafeIpcError::new(
                "confirmation_required",
                "Explicit file authorization is required",
            ));
        }
        parse_scan_id(&request.preview_id)?;
        let preview = self
            .file_previews
            .lock()
            .map_err(|_| SafeIpcError::new("preview_unavailable", "File preview is unavailable"))?
            .remove(&request.preview_id)
            .ok_or_else(|| {
                SafeIpcError::new("preview_not_found", "A fresh file preview is required")
            })?;
        let authorization_id = new_uuid_v7();
        let target = authorize_file_target(
            authorization_id.clone(),
            &preview.requested_path,
            SystemClock.now()?.to_string(),
            DEFAULT_MAX_FILE_SIZE,
        )
        .map_err(file_security_error)?;
        if preview.identity != target.identity || preview.canonical_path != target.canonical_path {
            return Err(SafeIpcError::new(
                "target_changed",
                "File changed; authorization must be renewed",
            ));
        }
        let view = AuthorizedFileTargetView {
            authorization_id: authorization_id.clone(),
            canonical_path: target.canonical_path.clone(),
            size: target.identity.size,
            detected_type: label(preview.detected_type),
            proposed_checks: preview.proposed_checks.clone(),
            policy_limitations: preview.policy_limitations.clone(),
        };
        let mut targets = self.file_targets.lock().map_err(|_| {
            SafeIpcError::new(
                "authorization_unavailable",
                "File authorization is unavailable",
            )
        })?;
        if targets.len() >= 64 {
            return Err(SafeIpcError::new(
                "authorization_limit",
                "File authorization session limit reached",
            ));
        }
        targets.insert(
            authorization_id,
            FileAuthorizationSession { target, preview },
        );
        Ok(view)
    }

    pub fn create_file_scan(
        &self,
        request: CreateFileScanRequest,
    ) -> Result<ScanSummaryView, SafeIpcError> {
        if !request.confirmed {
            return Err(SafeIpcError::new(
                "confirmation_required",
                "Explicit file scan confirmation is required",
            ));
        }
        parse_scan_id(&request.authorization_id)?;
        let session = self
            .file_targets
            .lock()
            .map_err(|_| {
                SafeIpcError::new(
                    "authorization_unavailable",
                    "File authorization is unavailable",
                )
            })?
            .remove(&request.authorization_id)
            .ok_or_else(|| {
                SafeIpcError::new(
                    "authorization_not_found",
                    "File authorization is unavailable",
                )
            })?;
        if session.preview.identity != session.target.identity {
            return Err(SafeIpcError::new(
                "target_changed",
                "File changed; authorization must be renewed",
            ));
        }
        let scan_id = new_uuid_v7();
        let target_id = new_uuid_v7();
        let canonical_target_id = format!(
            "{:x}",
            Sha256::digest(
                session
                    .target
                    .canonical_path
                    .to_ascii_lowercase()
                    .as_bytes()
            )
        );
        let stored = Level2StoredScan {
            scan_id: scan_id.clone(),
            target_id: target_id.clone(),
            authorization_id: request.authorization_id,
            canonical_target_id: canonical_target_id.clone(),
            state: "preparing".into(),
            progress: ScanProgressView {
                scan_id: scan_id.clone(),
                phase: "authorization_revalidation".into(),
                completed_tasks: 0,
                total_tasks: 8,
                percent: Some(0),
                elapsed_ms: 0,
                current_engine: None,
                status: "preparing".into(),
            },
            analysis: None,
            terminal_error: None,
        };
        let payload = serde_json::to_vec(&stored).map_err(|_| {
            SafeIpcError::new("file_storage_failed", "File scan could not be stored")
        })?;
        self.level2
            .lock()
            .map_err(|_| {
                SafeIpcError::new(
                    "storage_unavailable",
                    "File analysis storage is unavailable",
                )
            })?
            .create(
                &scan_id,
                &target_id,
                &stored.authorization_id,
                &canonical_target_id,
                &payload,
            )
            .map_err(|_| {
                SafeIpcError::new("file_storage_failed", "File scan could not be stored")
            })?;
        let cancellation = CancellationToken::default();
        self.jobs
            .lock()
            .map_err(|_| SafeIpcError::new("scan_busy", "Scan scheduler is unavailable"))?
            .insert(scan_id.clone(), cancellation.clone());
        let store = Arc::clone(&self.level2);
        let jobs = Arc::clone(&self.jobs);
        let worker_id = scan_id.clone();
        std::thread::spawn(move || {
            let mut worker = stored;
            if run_file_analysis(&store, &session.target, &mut worker, cancellation).is_err() {
                worker.analysis = None;
                worker.state = "failed".into();
                worker.progress.status = "failed".into();
                worker.progress.phase = "persistence_or_correlation_failed".into();
                worker.progress.percent = None;
                worker.progress.current_engine = None;
                worker.terminal_error = Some("FILE_ANALYSIS_NOT_COMMITTED".into());
                // Best effort only when storage itself is unavailable; never publish a verdict.
                let _ = replace_level2_snapshot(&store, &worker);
            }
            if let Ok(mut active) = jobs.lock() {
                active.remove(&worker_id);
            }
        });
        self.get_scan(&ScanRequest { scan_id })
    }

    pub fn get_file_analysis(
        &self,
        request: &ScanRequest,
    ) -> Result<FileAnalysisView, SafeIpcError> {
        let stored = self.load_level2(&request.scan_id)?;
        Ok(FileAnalysisView {
            scan_id: stored.scan_id,
            state: stored.state,
            progress: stored.progress,
            analysis: stored.analysis,
            terminal_error: stored.terminal_error,
        })
    }

    fn load_level2(&self, scan_id: &str) -> Result<Level2StoredScan, SafeIpcError> {
        let id = parse_scan_id(scan_id)?;
        let blob = self
            .level2
            .lock()
            .map_err(|_| {
                SafeIpcError::new(
                    "storage_unavailable",
                    "File analysis storage is unavailable",
                )
            })?
            .load(id.as_str())
            .map_err(|_| SafeIpcError::new("scan_not_found", "Scan was not found"))?;
        serde_json::from_slice(&blob.payload).map_err(|_| {
            SafeIpcError::new(
                "storage_integrity",
                "File analysis integrity validation failed",
            )
        })
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
        if let Ok(scan) = self.load_level1(&request.scan_id) {
            return Ok(level1_summary(&scan));
        }
        Ok(level2_summary(&self.load_level2(&request.scan_id)?))
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
            let ids = self
                .level2
                .lock()
                .map_err(|_| {
                    SafeIpcError::new(
                        "storage_unavailable",
                        "File analysis storage is unavailable",
                    )
                })?
                .list_ids(0, request.limit)
                .map_err(|_| {
                    SafeIpcError::new(
                        "storage_unavailable",
                        "File analysis storage is unavailable",
                    )
                })?;
            for id in ids {
                scans.push(level2_summary(&self.load_level2(&id)?));
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
        if let Ok(scan) = self.load_level1(&request.scan_id) {
            return Ok(scan.progress);
        }
        Ok(self.load_level2(&request.scan_id)?.progress)
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
        if let Ok(mut level1) = self.load_level1(&request.scan_id) {
            level1.state = "cancellation_requested".into();
            level1.progress.status = "cancellation_requested".into();
            replace_level1_snapshot(&self.level1, &level1)?;
            token.request();
            return Ok(level1.progress);
        }
        if let Ok(mut level2) = self.load_level2(&request.scan_id) {
            level2.state = "cancellation_requested".into();
            level2.progress.status = "cancellation_requested".into();
            replace_level2_snapshot(&self.level2, &level2)?;
            token.request();
            return Ok(level2.progress);
        }
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
            if let Ok(scan) = self.load_level1(&request.scan_id) {
                return Ok(scan
                    .findings
                    .iter()
                    .skip(request.offset as usize)
                    .take(request.limit as usize)
                    .map(|finding| level1_finding_view(&scan.scan_id, finding))
                    .collect());
            }
            let scan = self.load_level2(&request.scan_id)?;
            return Ok(scan
                .analysis
                .as_ref()
                .map(|analysis| {
                    analysis
                        .findings
                        .iter()
                        .skip(request.offset as usize)
                        .take(request.limit as usize)
                        .map(|finding| level2_finding_view(&scan.scan_id, finding))
                        .collect()
                })
                .unwrap_or_default());
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
        let level2_ids = self
            .level2
            .lock()
            .map_err(|_| {
                SafeIpcError::new(
                    "storage_unavailable",
                    "File analysis storage is unavailable",
                )
            })?
            .list_ids(0, 50)
            .map_err(|_| {
                SafeIpcError::new(
                    "storage_unavailable",
                    "File analysis storage is unavailable",
                )
            })?;
        for id in level2_ids {
            let scan = self.load_level2(&id)?;
            if let Some(finding) = scan.analysis.as_ref().and_then(|analysis| {
                analysis
                    .findings
                    .iter()
                    .find(|finding| finding.fingerprint == request.finding_id)
            }) {
                return Ok(level2_finding_view(&scan.scan_id, finding));
            }
        }
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
            if let Ok(stored) = self.load_level1(&request.scan_id) {
                if stored.state != "partial" && stored.state != "completed" {
                    return Err(SafeIpcError::new(
                        "report_unavailable",
                        "Report is unavailable until repository processing reaches a reportable terminal state",
                    ));
                }
                let report = RepositoryReport::capture(
                    request.kind,
                    &stored.scan_id,
                    &stored.inventory,
                    &stored.findings,
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
            }
            let stored = self.load_level2(&request.scan_id)?;
            let analysis = stored.analysis.as_ref().ok_or_else(|| {
                SafeIpcError::new(
                    "report_unavailable",
                    "Report is unavailable until file analysis reaches a reportable terminal state",
                )
            })?;
            let report = FileReport::capture(request.kind, &stored.scan_id, analysis);
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
        .any(|finding| matches!(finding.severity.as_str(), "high" | "critical"));
    ScanSummaryView {
        id: scan.scan_id.clone(),
        state: scan.state.clone(),
        verdict: if scan.state == "partial" {
            Some("inconclusive".into())
        } else {
            None
        },
        risk: if scan.state == "partial" {
            Some(if high { "high" } else { "medium" }.into())
        } else {
            None
        },
        confidence: if scan.state == "partial" {
            Some("medium".into())
        } else {
            None
        },
        coverage: CoverageView {
            total: 7,
            completed: if scan.state == "partial" {
                5
            } else {
                scan.progress.completed_tasks
            },
            unavailable: if scan.state == "partial" { 2 } else { 0 },
            ..CoverageView::default()
        },
    }
}

fn level1_finding_view(scan_id: &str, finding: &CorrelatedRepositoryFinding) -> FindingView {
    FindingView {
        id: finding.id.clone(),
        scan_id: scan_id.into(),
        title: finding.description.clone(),
        category: finding.category.clone(),
        severity: finding.severity.clone(),
        risk: finding.severity.clone(),
        confidence: finding.confidence.clone(),
        status: finding.status.clone(),
        sources: finding.supporting_sources.clone(),
        affected_component: finding.affected_component.clone(),
        rule_ids: finding.rule_ids.clone(),
        evidence_ids: finding.evidence_ids.clone(),
        remediation_guidance: finding.remediation_guidance.clone(),
        limitations: finding.limitations.clone(),
    }
}

fn level2_summary(scan: &Level2StoredScan) -> ScanSummaryView {
    let Some(analysis) = &scan.analysis else {
        return ScanSummaryView {
            id: scan.scan_id.clone(),
            state: scan.state.clone(),
            verdict: None,
            risk: None,
            confidence: None,
            coverage: CoverageView {
                total: 6,
                completed: 0,
                failed: u32::from(scan.state == "failed"),
                unavailable: 0,
                skipped: if scan.state == "cancelled" { 6 } else { 0 },
            },
        };
    };
    use edy_engine_manager::file_security::CheckState;
    let checks = [
        analysis.coverage.hashing,
        analysis.coverage.classification,
        analysis.coverage.pe_inspection,
        analysis.coverage.authenticode,
        analysis.coverage.yara,
        analysis.coverage.reputation,
    ];
    ScanSummaryView {
        id: scan.scan_id.clone(),
        state: scan.state.clone(),
        verdict: Some(analysis.verdict.disposition.clone()),
        risk: Some(label(analysis.verdict.risk)),
        confidence: Some(label(analysis.verdict.confidence)),
        coverage: CoverageView {
            total: 6,
            completed: checks
                .iter()
                .filter(|state| **state == CheckState::Completed)
                .count() as u32,
            failed: checks
                .iter()
                .filter(|state| **state == CheckState::Failed)
                .count() as u32,
            unavailable: checks
                .iter()
                .filter(|state| matches!(state, CheckState::PolicyBlocked | CheckState::NotChecked))
                .count() as u32,
            skipped: checks
                .iter()
                .filter(|state| **state == CheckState::NotApplicable)
                .count() as u32,
        },
    }
}

fn level2_finding_view(
    scan_id: &str,
    finding: &edy_engine_manager::file_security::FileSecurityFinding,
) -> FindingView {
    FindingView {
        id: finding.fingerprint.clone(),
        scan_id: scan_id.into(),
        title: finding.title.clone(),
        category: label(finding.category),
        severity: label(finding.severity),
        risk: label(finding.severity),
        confidence: label(finding.confidence),
        status: "open".into(),
        sources: vec![finding.source.clone()],
        affected_component: "authorized_file_identity".into(),
        rule_ids: vec![finding.rule_id.clone()],
        evidence_ids: finding.evidence.clone(),
        remediation_guidance:
            "Review the evidence and re-authorize the explicit file before verification.".into(),
        limitations: vec![
            "A signature is evidence, not a safety guarantee.".into(),
            "YARA-X real execution is unavailable by execution policy.".into(),
            "Reputation was not checked.".into(),
        ],
    }
}

fn file_security_error(
    error: edy_engine_manager::file_security::FileSecurityError,
) -> SafeIpcError {
    let (code, message) = match error.kind() {
        FileSecurityErrorKind::InvalidPath => ("file_path_invalid", "File path was refused"),
        FileSecurityErrorKind::Missing => ("file_not_found", "File was not found"),
        FileSecurityErrorKind::NotRegularFile => (
            "not_regular_file",
            "Only one explicit regular file is accepted",
        ),
        FileSecurityErrorKind::NotLocalFixedFilesystem => (
            "not_local_fixed_filesystem",
            "Only a local fixed filesystem file is accepted",
        ),
        FileSecurityErrorKind::LimitExceeded => {
            ("limit_exceeded", "File exceeds the configured size policy")
        }
        FileSecurityErrorKind::NotReadable => ("file_not_readable", "File is not readable"),
        FileSecurityErrorKind::ReparsePoint => (
            "reparse_point_refused",
            "Linked or reparse targets are refused",
        ),
        FileSecurityErrorKind::TargetChanged => (
            "target_changed",
            "File changed; authorization must be renewed",
        ),
        FileSecurityErrorKind::Cancelled => ("cancelled", "File analysis was cancelled"),
        FileSecurityErrorKind::Io => ("file_io_failed", "File analysis failed safely"),
    };
    SafeIpcError::new(code, message)
}

fn synthetic_repository_observations(
    target: &AuthorizedRepositoryTarget,
    inventory: &RepositoryInventory,
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
    let trivy = br#"{"SchemaVersion":2,"Results":[{"Target":"Cargo.lock","Vulnerabilities":[{"VulnerabilityID":"CVE-2099-0001","PkgName":"crates.io:synthetic-vulnerable","InstalledVersion":"0.1.0","FixedVersion":"1.0.0","Severity":"HIGH"}],"Licenses":[{"Name":"MIT","PkgName":"crates.io:synthetic-vulnerable","Category":"detected"}]},{"Target":"config/bad-config.json","Misconfigurations":[{"ID":"CFG-001","Title":"Unsafe synthetic configuration","Severity":"MEDIUM"}]}]}"#;
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
    for observation in observations
        .iter_mut()
        .filter(|item| item.category == edy_repository::RepositoryFindingCategory::License)
    {
        normalize_license_state(
            observation,
            LicenseState::Detected,
            &["engine observation", "package metadata"],
        );
    }
    observations.extend(aggregate_repository_posture(
        target,
        inventory,
        &BTreeSet::from(["rust".into()]),
        true,
    ));
    Ok(observations)
}

fn run_repository_fixture(
    store: &Arc<Mutex<Level1SnapshotStore>>,
    session: RepositoryAuthorizationSession,
    scan: &mut Level1StoredScan,
    cancellation: CancellationToken,
) -> Result<(), SafeIpcError> {
    let phases = [
        ("inventory", None),
        ("planning", None),
        ("secret_checks", Some("fake-gitleaks")),
        ("dependency_checks", Some("fake-osv-trivy")),
        ("config_checks", Some("fake-trivy")),
        ("correlation", None),
        ("reporting", None),
    ];
    for (index, (phase, engine)) in phases.iter().enumerate() {
        for _ in 0..8 {
            if cancellation.is_requested() {
                scan.state = "cancelled".into();
                scan.progress.status = "cancelled".into();
                scan.progress.current_engine = None;
                replace_level1_snapshot(store, scan)?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(3));
        }
        if *phase == "correlation" {
            let current = match inspect_revalidated(&session.target, &session.preview_fingerprint) {
                Ok(current) => current,
                Err(_) => {
                    scan.state = "failed".into();
                    scan.progress.phase = "revalidation_required".into();
                    scan.progress.status = "failed".into();
                    scan.progress.current_engine = None;
                    replace_level1_snapshot(store, scan)?;
                    return Ok(());
                }
            };
            scan.inventory = current;
            scan.observations = if session
                .target
                .canonical_root()
                .replace('\\', "/")
                .ends_with("tests/fixtures/synthetic-repository-a")
            {
                synthetic_repository_observations(&session.target, &scan.inventory)?
            } else {
                Vec::new()
            };
            let correlation = correlate_repository_observations(
                ScanId::new(&scan.scan_id).map_err(|_| {
                    SafeIpcError::new("id_unavailable", "Scan identifier is unavailable")
                })?,
                &session.target,
                &scan.observations,
                &scan.unavailable_checks,
                Timestamp::new("2026-09-02T13:00:01Z").map_err(|_| {
                    SafeIpcError::new("timestamp_unavailable", "Scan timestamp is unavailable")
                })?,
            )
            .map_err(|_| {
                SafeIpcError::new(
                    "repository_correlation_failed",
                    "Repository observations could not be correlated safely",
                )
            })?;
            scan.findings = correlation.findings;
            scan.evidence = correlation.evidence;
            scan.unavailable_checks = correlation.unavailable_sources;
        }
        scan.progress.phase = (*phase).into();
        scan.progress.completed_tasks = (index + 1) as u32;
        scan.progress.percent = Some(((index + 1) as u32 * 100) / phases.len() as u32);
        scan.progress.elapsed_ms = ((index + 1) as u64) * 24;
        scan.progress.current_engine = engine.map(str::to_owned);
        scan.state = if index + 1 == phases.len() {
            "partial"
        } else {
            "running"
        }
        .into();
        scan.progress.status = scan.state.clone();
        replace_level1_snapshot(store, scan)?;
    }
    Ok(())
}

fn replace_level1_snapshot(
    store: &Arc<Mutex<Level1SnapshotStore>>,
    scan: &Level1StoredScan,
) -> Result<(), SafeIpcError> {
    let payload = serde_json::to_vec(scan).map_err(|_| {
        SafeIpcError::new(
            "repository_storage_failed",
            "Repository scan could not be stored",
        )
    })?;
    let mut store = store.lock().map_err(|_| {
        SafeIpcError::new("storage_unavailable", "Repository storage is unavailable")
    })?;
    let revision = store
        .load(&scan.scan_id)
        .map_err(|_| SafeIpcError::new("storage_unavailable", "Repository storage is unavailable"))?
        .revision;
    store
        .replace(&scan.scan_id, revision, &payload)
        .map_err(|_| {
            SafeIpcError::new("storage_unavailable", "Repository storage is unavailable")
        })?;
    Ok(())
}

struct FileFindingIds;

impl edy_core::FindingIdSource for FileFindingIds {
    fn next_id(&mut self) -> edy_core::FindingId {
        edy_core::FindingId::new(new_uuid_v7()).expect("application generates UUID v7")
    }
}

fn run_file_analysis(
    store: &Arc<Mutex<Level2SnapshotStore>>,
    target: &AuthorizedFileTarget,
    scan: &mut Level2StoredScan,
    cancellation: CancellationToken,
) -> Result<(), SafeIpcError> {
    let started_at = std::time::Instant::now();
    scan.state = "running".into();
    scan.progress.phase = "secure_open".into();
    scan.progress.status = "running".into();
    scan.progress.completed_tasks = 1;
    scan.progress.percent = Some(12);
    replace_level2_snapshot(store, scan)?;
    scan.progress.phase = "streaming_hashes".into();
    scan.progress.completed_tasks = 2;
    scan.progress.percent = Some(25);
    replace_level2_snapshot(store, scan)?;
    match analyze_authorized_file(target, || cancellation.is_requested()) {
        Ok(mut analysis) => {
            normalize_file_analysis(
                &mut analysis,
                &parse_scan_id(&scan.scan_id)?,
                &SystemClock.now()?,
                &mut FileFindingIds,
            )
            .map_err(|_| {
                SafeIpcError::new("correlation_failed", "File evidence was not accepted")
            })?;
            scan.analysis = Some(analysis);
            scan.state = "partial".into();
            scan.progress.phase = "reporting".into();
            scan.progress.completed_tasks = 8;
            scan.progress.percent = Some(100);
            scan.progress.status = "partial".into();
            scan.progress.current_engine = None;
            scan.terminal_error = None;
        }
        Err(error) if error.kind() == FileSecurityErrorKind::Cancelled => {
            scan.state = "cancelled".into();
            scan.progress.phase = "cancelled".into();
            scan.progress.status = "cancelled".into();
            scan.progress.percent = None;
            scan.progress.current_engine = None;
            scan.terminal_error = Some("CANCELLED".into());
        }
        Err(error) if error.kind() == FileSecurityErrorKind::TargetChanged => {
            scan.state = "failed".into();
            scan.progress.phase = "target_changed".into();
            scan.progress.status = "failed".into();
            scan.progress.percent = None;
            scan.progress.current_engine = None;
            scan.terminal_error = Some("TARGET_CHANGED".into());
        }
        Err(_) => {
            scan.state = "failed".into();
            scan.progress.phase = "analysis_failed".into();
            scan.progress.status = "failed".into();
            scan.progress.percent = None;
            scan.progress.current_engine = None;
            scan.terminal_error = Some("FILE_ANALYSIS_FAILED".into());
        }
    }
    scan.progress.elapsed_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    replace_level2_snapshot(store, scan)
}

fn replace_level2_snapshot(
    store: &Arc<Mutex<Level2SnapshotStore>>,
    scan: &Level2StoredScan,
) -> Result<(), SafeIpcError> {
    let payload = serde_json::to_vec(scan)
        .map_err(|_| SafeIpcError::new("file_storage_failed", "File scan could not be stored"))?;
    let mut store = store.lock().map_err(|_| {
        SafeIpcError::new(
            "storage_unavailable",
            "File analysis storage is unavailable",
        )
    })?;
    let current = store
        .load(&scan.scan_id)
        .map_err(|_| SafeIpcError::new("file_storage_failed", "File scan could not be stored"))?;
    store
        .replace(&scan.scan_id, current.revision, &payload)
        .map_err(|_| SafeIpcError::new("file_storage_failed", "File scan could not be stored"))?;
    Ok(())
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

fn reconcile_interrupted_level2(store: &mut Level2SnapshotStore) -> Result<(), SafeIpcError> {
    let failure = || SafeIpcError::new("storage_integrity", "File scan recovery failed closed");
    for offset in (0..MAX_STORED_SYNTHETIC_SCANS).step_by(50) {
        let page = store.list_ids(offset, 50).map_err(|_| failure())?;
        for id in &page {
            let blob = store.load(id).map_err(|_| failure())?;
            let mut scan: Level2StoredScan =
                serde_json::from_slice(&blob.payload).map_err(|_| failure())?;
            if matches!(
                scan.state.as_str(),
                "preparing" | "queued" | "running" | "cancellation_requested"
            ) {
                scan.state = "failed".into();
                scan.analysis = None;
                scan.progress.status = "failed".into();
                scan.progress.phase = "interrupted".into();
                scan.progress.percent = None;
                scan.progress.current_engine = None;
                scan.terminal_error = Some("INTERRUPTED_REAUTHORIZE_REQUIRED".into());
                let payload = serde_json::to_vec(&scan).map_err(|_| failure())?;
                store
                    .replace(id, blob.revision, &payload)
                    .map_err(|_| failure())?;
            }
        }
        if page.len() < 50 {
            break;
        }
    }
    Ok(())
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
    let sources = finding
        .source_engines()
        .iter()
        .map(|engine| engine.as_str().into())
        .collect::<Vec<_>>();
    FindingView {
        id: finding.id().as_str().into(),
        scan_id: finding.scan_id().as_str().into(),
        title: finding.title().into(),
        category: finding.category().into(),
        severity: label(finding.severity()),
        risk: label(finding.severity()),
        confidence: label(finding.confidence()),
        status: label(finding.status()),
        sources,
        affected_component: finding.target_id().to_string(),
        rule_ids: finding.rule_ids().to_vec(),
        evidence_ids: finding
            .evidence_ids()
            .iter()
            .map(ToString::to_string)
            .collect(),
        remediation_guidance:
            "Review the evidence, apply the smallest safe change, and verify by rescanning.".into(),
        limitations: vec![
            "Synthetic Level 0 evidence does not claim production scanning readiness.".into(),
        ],
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
        let (temp, backend) = backend();
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
        let started = backend
            .create_repository_scan(CreateRepositoryScanRequest {
                authorization_id: authorization.authorization_id,
                confirmed: true,
            })
            .unwrap();
        assert!(matches!(started.state.as_str(), "preparing" | "running"));
        let scan = wait_terminal(&backend, &started.id);
        assert_eq!(scan.state, "partial");
        assert_eq!(scan.coverage.unavailable, 2);
        let findings = backend
            .list_findings(&ListFindingsRequest {
                scan_id: scan.id.clone(),
                offset: 0,
                limit: 100,
            })
            .unwrap();
        assert_eq!(findings.len(), 5);
        assert_eq!(
            findings
                .iter()
                .map(|f| f.category.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "license",
                "misconfiguration",
                "secret",
                "supply_chain",
                "vulnerable_dependency",
            ])
        );
        let vulnerability = findings
            .iter()
            .find(|finding| finding.category == "vulnerable_dependency")
            .unwrap();
        assert_eq!(vulnerability.sources, vec!["osv-scanner", "trivy"]);
        assert_eq!(vulnerability.evidence_ids.len(), 2);
        let report = backend
            .report(&GenerateReportRequest {
                scan_id: scan.id.clone(),
                kind: ReportKind::Technical,
            })
            .unwrap();
        let report_json: serde_json::Value = serde_json::from_str(&report.json).unwrap();
        assert_eq!(report_json["vulnerable_dependency_count"], 1);
        assert_eq!(report_json["findings"].as_array().unwrap().len(), 5);
        let full_secret = std::fs::read_to_string(fixture.join("config/test-secret.env"))
            .unwrap()
            .trim()
            .split_once('=')
            .unwrap()
            .1
            .to_owned();
        assert!(!report.json.contains(&full_secret));
        assert!(
            !serde_json::to_string(&findings)
                .unwrap()
                .contains(&full_secret)
        );
        let database_bytes = std::fs::read(temp.0.join("level0.sqlite3")).unwrap();
        assert!(
            !database_bytes
                .windows(full_secret.len())
                .any(|window| window == full_secret.as_bytes())
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

    #[test]
    fn repository_change_after_preview_requires_fresh_authorization() {
        let (temp, backend) = backend();
        let repository = temp.0.join("mutable-repository");
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::write(repository.join("safe.txt"), "before").unwrap();
        let repository_text = repository.to_string_lossy();
        let repository_text = repository_text
            .strip_prefix(r"\\?\")
            .unwrap_or(&repository_text)
            .to_owned();
        let authorization = backend
            .authorize_repository_target(AuthorizeRepositoryTargetRequest {
                path: repository_text,
            })
            .unwrap();
        std::fs::write(repository.join("safe.txt"), "after-and-different-size").unwrap();
        let error = backend
            .create_repository_scan(CreateRepositoryScanRequest {
                authorization_id: authorization.authorization_id,
                confirmed: true,
            })
            .unwrap_err();
        assert_eq!(error.code, "repository_revalidation_required");
        assert_eq!(
            error.message_safe,
            "Repository changed; authorization must be renewed"
        );
    }

    #[test]
    fn repository_cancellation_is_persisted_without_a_final_verdict() {
        let (_temp, backend) = backend();
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../tests/fixtures/synthetic-repository-a")
            .canonicalize()
            .unwrap();
        let fixture_text = fixture.to_string_lossy();
        let authorization = backend
            .authorize_repository_target(AuthorizeRepositoryTargetRequest {
                path: fixture_text
                    .strip_prefix(r"\\?\")
                    .unwrap_or(&fixture_text)
                    .into(),
            })
            .unwrap();
        let started = backend
            .create_repository_scan(CreateRepositoryScanRequest {
                authorization_id: authorization.authorization_id,
                confirmed: true,
            })
            .unwrap();
        let requested = backend
            .cancel(&ScanRequest {
                scan_id: started.id.clone(),
            })
            .unwrap();
        assert_eq!(requested.status, "cancellation_requested");
        let cancelled = wait_terminal(&backend, &started.id);
        assert_eq!(cancelled.state, "cancelled");
        assert!(cancelled.verdict.is_none());
        assert!(
            backend
                .report(&GenerateReportRequest {
                    scan_id: started.id,
                    kind: ReportKind::Executive,
                })
                .is_err()
        );
    }

    #[test]
    fn level2_preview_is_required_single_use_and_bound_to_identity() {
        let (temp, backend) = backend();
        let file = temp.0.join("preview-bound.bin");
        std::fs::write(&file, b"before").unwrap();
        assert!(
            serde_json::from_str::<AuthorizeFileTargetRequest>(
                r#"{"path":"D:/anything.bin","confirmed":true}"#
            )
            .is_err()
        );
        let unknown = backend
            .authorize_file_target(AuthorizeFileTargetRequest {
                preview_id: new_uuid_v7(),
                confirmed: true,
            })
            .unwrap_err();
        assert_eq!(unknown.code, "preview_not_found");
        let preview = backend
            .inspect_file_target(InspectFileTargetRequest {
                path: display_test_path(&file),
            })
            .unwrap();
        std::fs::write(&file, b"changed-after-displayed-preview").unwrap();
        let request = AuthorizeFileTargetRequest {
            preview_id: preview.preview_id,
            confirmed: true,
        };
        assert_eq!(
            backend
                .authorize_file_target(request.clone())
                .unwrap_err()
                .code,
            "target_changed"
        );
        assert_eq!(
            backend.authorize_file_target(request).unwrap_err().code,
            "preview_not_found"
        );
        let fresh = backend
            .inspect_file_target(InspectFileTargetRequest {
                path: display_test_path(&file),
            })
            .unwrap();
        let request = AuthorizeFileTargetRequest {
            preview_id: fresh.preview_id,
            confirmed: true,
        };
        let authorization = backend.authorize_file_target(request.clone()).unwrap();
        assert_eq!(
            backend.authorize_file_target(request).unwrap_err().code,
            "preview_not_found"
        );
        let scan_request = CreateFileScanRequest {
            authorization_id: authorization.authorization_id,
            confirmed: true,
        };
        let scan = backend.create_file_scan(scan_request.clone()).unwrap();
        assert_eq!(
            backend.create_file_scan(scan_request).unwrap_err().code,
            "authorization_not_found"
        );
        wait_terminal(&backend, &scan.id);
    }

    #[test]
    fn level2_file_e2e_requires_preview_authorization_and_preserves_partial_coverage() {
        let (temp, backend) = backend();
        let file = temp.0.join("benign-text.txt");
        let contents = b"EDY_LEVEL2_RAW_FILE_BYTES benign text only";
        std::fs::write(&file, contents).unwrap();
        let path = display_test_path(&file);
        let preview = backend
            .inspect_file_target(InspectFileTargetRequest { path: path.clone() })
            .unwrap();
        assert_eq!(preview.preview.identity.size, contents.len() as u64);
        assert_eq!(
            preview.preview.detected_type,
            edy_engine_manager::file_security::FileClassification::GenericFile
        );
        assert!(
            backend
                .authorize_file_target(AuthorizeFileTargetRequest {
                    preview_id: preview.preview_id.clone(),
                    confirmed: false,
                })
                .is_err()
        );
        let authorization = backend
            .authorize_file_target(AuthorizeFileTargetRequest {
                preview_id: preview.preview_id,
                confirmed: true,
            })
            .unwrap();
        assert!(
            backend
                .create_file_scan(CreateFileScanRequest {
                    authorization_id: authorization.authorization_id.clone(),
                    confirmed: false,
                })
                .is_err()
        );
        let started = backend
            .create_file_scan(CreateFileScanRequest {
                authorization_id: authorization.authorization_id,
                confirmed: true,
            })
            .unwrap();
        let completed = wait_terminal(&backend, &started.id);
        assert_eq!(completed.state, "partial");
        assert_eq!(completed.verdict.as_deref(), Some("insufficient_coverage"));
        assert_eq!(completed.coverage.unavailable, 2);
        let view = backend
            .get_file_analysis(&ScanRequest {
                scan_id: completed.id.clone(),
            })
            .unwrap();
        let analysis = view.analysis.unwrap();
        assert_eq!(analysis.hashes.bytes_hashed, contents.len() as u64);
        assert_eq!(
            analysis.classification,
            edy_engine_manager::file_security::FileClassification::GenericFile
        );
        assert_eq!(
            analysis.authenticode.cryptographic_status,
            edy_engine_manager::file_security::AuthenticodeStatus::Unsigned
        );
        assert!(analysis.findings.is_empty());
        assert_eq!(analysis.reputation.status, "not_checked");
        let report = backend
            .report(&GenerateReportRequest {
                scan_id: completed.id,
                kind: ReportKind::Technical,
            })
            .unwrap();
        assert!(report.json.contains("unavailable_by_execution_policy"));
        assert!(!report.json.contains("EDY_LEVEL2_RAW_FILE_BYTES"));
        let database = std::fs::read(temp.0.join("level0.sqlite3")).unwrap();
        let marker = b"EDY_LEVEL2_RAW_FILE_BYTES";
        assert!(
            !database
                .windows(marker.len())
                .any(|window| window == marker)
        );
    }

    #[test]
    fn level2_target_change_invalidates_analysis_without_a_verdict() {
        let (temp, backend) = backend();
        let file = temp.0.join("changed-target.bin");
        std::fs::write(&file, b"before").unwrap();
        let authorization = backend
            .authorize_file_target(AuthorizeFileTargetRequest {
                preview_id: backend
                    .inspect_file_target(InspectFileTargetRequest {
                        path: display_test_path(&file),
                    })
                    .unwrap()
                    .preview_id,
                confirmed: true,
            })
            .unwrap();
        std::fs::write(&file, b"after-and-different-size").unwrap();
        let started = backend
            .create_file_scan(CreateFileScanRequest {
                authorization_id: authorization.authorization_id,
                confirmed: true,
            })
            .unwrap();
        let terminal = wait_terminal(&backend, &started.id);
        assert_eq!(terminal.state, "failed");
        assert!(terminal.verdict.is_none());
        let view = backend
            .get_file_analysis(&ScanRequest {
                scan_id: started.id,
            })
            .unwrap();
        assert_eq!(view.terminal_error.as_deref(), Some("TARGET_CHANGED"));
        assert!(view.analysis.is_none());
    }

    #[test]
    fn level2_streaming_cancellation_persists_no_final_verdict() {
        let (temp, backend) = backend();
        let file = temp.0.join("cancel-target.bin");
        std::fs::write(&file, vec![7_u8; 8 * 1024 * 1024]).unwrap();
        let authorization = backend
            .authorize_file_target(AuthorizeFileTargetRequest {
                preview_id: backend
                    .inspect_file_target(InspectFileTargetRequest {
                        path: display_test_path(&file),
                    })
                    .unwrap()
                    .preview_id,
                confirmed: true,
            })
            .unwrap();
        let started = backend
            .create_file_scan(CreateFileScanRequest {
                authorization_id: authorization.authorization_id,
                confirmed: true,
            })
            .unwrap();
        let request = ScanRequest {
            scan_id: started.id,
        };
        assert_eq!(
            backend.cancel(&request).unwrap().status,
            "cancellation_requested"
        );
        let terminal = wait_terminal(&backend, &request.scan_id);
        assert_eq!(terminal.state, "cancelled");
        assert!(terminal.verdict.is_none());
        assert!(
            backend
                .get_file_analysis(&request)
                .unwrap()
                .analysis
                .is_none()
        );
    }

    #[test]
    fn level2_synthetic_pe_and_malformed_binary_flow_through_core_storage_and_reports() {
        let (temp, backend) = backend();
        let mut pe = vec![0_u8; 512];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&128_u32.to_le_bytes());
        pe[128..132].copy_from_slice(b"PE\0\0");
        pe[132..134].copy_from_slice(&0x8664_u16.to_le_bytes());
        pe[148..150].copy_from_slice(&240_u16.to_le_bytes());
        pe[150..152].copy_from_slice(&0x22_u16.to_le_bytes());
        pe[152..154].copy_from_slice(&0x20b_u16.to_le_bytes());
        for (name, bytes, malformed) in [
            ("minimal-pe-synthetic.bin", pe, false),
            (
                "malformed-pe.bin",
                b"MZ malformed synthetic fixture".to_vec(),
                true,
            ),
            ("benign-binary.dat", vec![0, 1, 2, 3, 0xff], false),
        ] {
            let path = temp.0.join(name);
            std::fs::write(&path, bytes).unwrap();
            let preview = backend
                .inspect_file_target(InspectFileTargetRequest {
                    path: display_test_path(&path),
                })
                .unwrap();
            let auth = backend
                .authorize_file_target(AuthorizeFileTargetRequest {
                    preview_id: preview.preview_id,
                    confirmed: true,
                })
                .unwrap();
            let scan = backend
                .create_file_scan(CreateFileScanRequest {
                    authorization_id: auth.authorization_id,
                    confirmed: true,
                })
                .unwrap();
            let terminal = wait_terminal(&backend, &scan.id);
            assert_eq!(terminal.state, "partial");
            assert_eq!(
                terminal.coverage.completed
                    + terminal.coverage.failed
                    + terminal.coverage.unavailable
                    + terminal.coverage.skipped,
                6
            );
            let stored = backend
                .get_file_analysis(&ScanRequest {
                    scan_id: scan.id.clone(),
                })
                .unwrap();
            let analysis = stored.analysis.unwrap();
            assert_ne!(analysis.verdict.disposition, "malicious");
            assert!(analysis.verdict.confidence_score < 75);
            if malformed {
                assert!(analysis.pe_error.is_some());
                assert_eq!(analysis.findings.len(), 1);
                assert_eq!(terminal.coverage.failed, 1);
            }
            for kind in [
                ReportKind::Executive,
                ReportKind::Technical,
                ReportKind::Developer,
            ] {
                let report = backend
                    .report(&GenerateReportRequest {
                        scan_id: scan.id.clone(),
                        kind,
                    })
                    .unwrap();
                assert!(report.json.contains("not_checked"));
                assert!(!report.json.contains("MZ malformed synthetic fixture"));
            }
        }
    }

    #[test]
    fn interrupted_file_scan_fails_closed_on_reopen() {
        let (temp, backend) = backend();
        let id = new_uuid_v7();
        let target_id = new_uuid_v7();
        let authorization_id = new_uuid_v7();
        let scan = Level2StoredScan {
            scan_id: id.clone(),
            target_id: target_id.clone(),
            authorization_id: authorization_id.clone(),
            canonical_target_id: "a".repeat(64),
            state: "preparing".into(),
            analysis: None,
            terminal_error: None,
            progress: ScanProgressView {
                scan_id: id.clone(),
                phase: "secure_open".into(),
                completed_tasks: 0,
                total_tasks: 8,
                percent: Some(0),
                elapsed_ms: 0,
                current_engine: None,
                status: "preparing".into(),
            },
        };
        backend
            .level2
            .lock()
            .unwrap()
            .create(
                &id,
                &target_id,
                &authorization_id,
                &scan.canonical_target_id,
                &serde_json::to_vec(&scan).unwrap(),
            )
            .unwrap();
        let project = backend.project_root.clone();
        drop(backend);
        let reopened = Level0Backend::open(&project, &temp.0.join("level0.sqlite3")).unwrap();
        let result = reopened
            .get_file_analysis(&ScanRequest { scan_id: id })
            .unwrap();
        assert_eq!(result.state, "failed");
        assert!(result.analysis.is_none());
        assert_eq!(
            result.terminal_error.as_deref(),
            Some("INTERRUPTED_REAUTHORIZE_REQUIRED")
        );
    }

    fn display_test_path(path: &Path) -> String {
        let canonical = path.canonicalize().unwrap();
        let value = canonical.to_string_lossy();
        value.strip_prefix(r"\\?\").unwrap_or(&value).into()
    }
}
