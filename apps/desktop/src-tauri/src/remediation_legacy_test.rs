//! Historical reversible lifecycle, retained only as test source. Not a production module.

use crate::ipc::SafeIpcError;
use edy_remediation::{
    RecoveryClassification, RemediationActionKind, RemediationActionState,
    RemediationAuthorization, RemediationPreview, RemediationReceipt, RemediationService,
    RemediationSnapshot, RollbackReceipt, ServiceError, VerificationResult,
    inspect_recovery_journal,
};
#[cfg(all(feature = "native-e2e", debug_assertions))]
use edy_remediation::{SYNTHETIC_FINDING_LEVEL6, VerificationObservation};
use edy_reporting::remediation::{RemediationAudience, RemediationReport};
use edy_storage::level6_snapshot::Level6SnapshotStore;
use serde::{Deserialize, Serialize};
#[cfg(all(feature = "native-e2e", debug_assertions))]
use std::path::PathBuf;
use std::{path::Path, sync::Mutex};

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    RepositoryConfig,
    InstalledApplication,
    WebConfiguration,
    Secret,
    SuspiciousFile,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRemediationPlanRequest {
    pub finding_id: String,
    pub case_id: Option<String>,
    pub candidate_kind: CandidateKind,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationActionRequest {
    pub action_id: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeRemediationRequest {
    pub action_id: String,
    pub plan_sha256: String,
    pub confirmed: bool,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyRemediationRequest {
    pub action_id: String,
    pub authorization_token: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRemediationRequest {
    pub action_id: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationPageRequest {
    pub offset: u32,
    pub limit: u32,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRemediationRequest {
    pub case_id: String,
    pub offset: u32,
    pub limit: u32,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationReportKind {
    Executive,
    Technical,
    Analyst,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationReportRequest {
    pub action_id: String,
    pub kind: RemediationReportKind,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationView {
    pub authorization: RemediationAuthorization,
    pub authorization_token: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct RemediationPage {
    pub items: Vec<RemediationSnapshot>,
    pub offset: u32,
    pub limit: u32,
}
#[derive(Debug, Clone, Serialize)]
pub struct RemediationReportView {
    pub action_id: String,
    pub kind: RemediationReportKind,
    pub json: String,
    pub html: String,
}

pub struct RemediationBackend {
    service: Mutex<RemediationService>,
    store: Mutex<Level6SnapshotStore>,
    #[cfg(all(feature = "native-e2e", debug_assertions))]
    fixture_root: Option<PathBuf>,
}

impl RemediationBackend {
    pub fn open(database: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut store = Level6SnapshotStore::open(database)?;
        reconcile_interrupted(&mut store)?;
        Ok(Self {
            service: Mutex::new(RemediationService::default()),
            store: Mutex::new(store),
            #[cfg(all(feature = "native-e2e", debug_assertions))]
            fixture_root: None,
        })
    }
    #[cfg(all(feature = "native-e2e", debug_assertions))]
    pub fn open_fixture(
        database: &Path,
        fixture_root: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(fixture_root)?;
        std::fs::write(
            fixture_root.join("security-config.toml"),
            "[security]\ninsecure_test_mode = true\n",
        )?;
        let mut service = RemediationService::default();
        let plan = service.create_synthetic_plan(
            fixture_root,
            SYNTHETIC_FINDING_LEVEL6,
            Some("case-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )?;
        let executable = service.snapshot(&plan.actions[0].action_id)?;
        let guidance = RemediationService::guidance(
            "SYNTHETIC_INSTALLED_APP_LEVEL6",
            Some("case-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            RemediationActionKind::InstalledApplicationUpdate,
            "Synthetic Installed App 1.0",
            vec![
                "Investigate the vendor-supported update; EDY VERDICT will not execute it.".into(),
            ],
            vec![
                "Refresh the installed application inventory and rerun vulnerability checks."
                    .into(),
            ],
        )?;
        let guidance = RemediationService::guidance_snapshot(guidance)?;
        let mut store = Level6SnapshotStore::open(database)?;
        store.save(&executable)?;
        store.save(&guidance)?;
        Ok(Self {
            service: Mutex::new(service),
            store: Mutex::new(store),
            fixture_root: Some(fixture_root.to_path_buf()),
        })
    }

    pub fn create_plan(
        &self,
        request: CreateRemediationPlanRequest,
    ) -> Result<RemediationSnapshot, SafeIpcError> {
        validate_finding_case(&request.finding_id, request.case_id.as_deref())?;
        #[cfg(all(feature = "native-e2e", debug_assertions))]
        if matches!(request.candidate_kind, CandidateKind::RepositoryConfig)
            && request.finding_id == SYNTHETIC_FINDING_LEVEL6
        {
            let root = self
                .fixture_root
                .as_ref()
                .ok_or_else(|| safe_error("rule_unavailable"))?;
            let mut service = self.lock_service()?;
            let plan = service
                .create_synthetic_plan(root, &request.finding_id, request.case_id.as_deref())
                .map_err(map_error)?;
            let snapshot = service
                .snapshot(&plan.actions[0].action_id)
                .map_err(map_error)?;
            self.save(&snapshot)?;
            return Ok(snapshot);
        }
        if matches!(request.candidate_kind, CandidateKind::RepositoryConfig) {
            return Err(safe_error("rule_unavailable"));
        }
        let (kind, guidance, verification) = guidance_for(request.candidate_kind);
        let action = RemediationService::guidance(
            &request.finding_id,
            request.case_id.as_deref(),
            kind,
            "Observed target from the confirmed finding",
            guidance,
            verification,
        )
        .map_err(map_error)?;
        let snapshot = RemediationService::guidance_snapshot(action).map_err(map_error)?;
        self.save(&snapshot)?;
        Ok(snapshot)
    }
    pub fn get(
        &self,
        request: RemediationActionRequest,
    ) -> Result<RemediationSnapshot, SafeIpcError> {
        self.store
            .lock()
            .map_err(|_| safe_error("storage_unavailable"))?
            .get(&request.action_id)
            .map_err(|_| safe_error("action_not_found"))
    }
    pub fn list(&self, request: RemediationPageRequest) -> Result<RemediationPage, SafeIpcError> {
        if request.offset > 10000 || !(1..=100).contains(&request.limit) {
            return Err(safe_error("invalid_request"));
        }
        let items = self
            .store
            .lock()
            .map_err(|_| safe_error("storage_unavailable"))?
            .list(request.offset, request.limit)
            .map_err(|_| safe_error("storage_failed"))?;
        Ok(RemediationPage {
            items,
            offset: request.offset,
            limit: request.limit,
        })
    }
    pub fn list_case(
        &self,
        request: CaseRemediationRequest,
    ) -> Result<RemediationPage, SafeIpcError> {
        validate_case(&request.case_id)?;
        let mut page = self.list(RemediationPageRequest {
            offset: request.offset,
            limit: request.limit,
        })?;
        page.items
            .retain(|item| item.plan.case_id.as_deref() == Some(request.case_id.as_str()));
        Ok(page)
    }
    pub fn preview(
        &self,
        request: RemediationActionRequest,
    ) -> Result<RemediationPreview, SafeIpcError> {
        let mut service = self.lock_service()?;
        let preview = service.preview(&request.action_id).map_err(map_error)?;
        self.save(&service.snapshot(&request.action_id).map_err(map_error)?)?;
        Ok(preview)
    }
    pub fn authorize(
        &self,
        request: AuthorizeRemediationRequest,
    ) -> Result<AuthorizationView, SafeIpcError> {
        if !request.confirmed {
            return Err(safe_error("explicit_confirmation_required"));
        }
        let mut service = self.lock_service()?;
        let grant = service
            .authorize(&request.action_id, &request.plan_sha256, 300)
            .map_err(map_error)?;
        self.save(&service.snapshot(&request.action_id).map_err(map_error)?)?;
        Ok(AuthorizationView {
            authorization: grant.authorization,
            authorization_token: grant.raw_token,
        })
    }
    pub fn apply(
        &self,
        request: ApplyRemediationRequest,
    ) -> Result<RemediationReceipt, SafeIpcError> {
        if request.authorization_token.len() != 64
            || !request
                .authorization_token
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(safe_error("authorization_denied"));
        }
        let mut service = self.lock_service()?;
        let receipt = service
            .apply_with_journal(
                &request.action_id,
                &request.authorization_token,
                |snapshot| self.save(snapshot).map_err(|_| ServiceError::Integrity),
            )
            .map_err(map_error)?;
        self.save(&service.snapshot(&request.action_id).map_err(map_error)?)?;
        Ok(receipt)
    }
    pub fn verify(
        &self,
        request: VerifyRemediationRequest,
    ) -> Result<VerificationResult, SafeIpcError> {
        #[allow(unused_mut)]
        let mut service = self.lock_service()?;
        let snapshot = service.snapshot(&request.action_id).map_err(map_error)?;
        let scanner = snapshot.plan.actions[0].verification.scanner_id.clone();
        #[cfg(not(all(feature = "native-e2e", debug_assertions)))]
        {
            let _ = (service, snapshot, scanner);
            Err(safe_error("scanner_unavailable"))
        }
        #[cfg(all(feature = "native-e2e", debug_assertions))]
        {
            let target_stable_before = service
                .verification_target_stable(&request.action_id)
                .map_err(map_error)?;
            let fingerprints = {
                let root = self
                    .fixture_root
                    .as_ref()
                    .ok_or_else(|| safe_error("scanner_unavailable"))?;
                let bytes = std::fs::read(root.join("security-config.toml"))
                    .map_err(|_| safe_error("scanner_failed"))?;
                let text = std::str::from_utf8(&bytes).map_err(|_| safe_error("scanner_failed"))?;
                let mut values = Vec::new();
                if text.contains("insecure_test_mode = true") {
                    values.push(SYNTHETIC_FINDING_LEVEL6.into());
                }
                if text.contains("introduce_regression = true") {
                    values.push(edy_remediation::SYNTHETIC_REGRESSION_LEVEL6.into());
                }
                values
            };
            let result = service
                .verify(
                    &request.action_id,
                    VerificationObservation {
                        scanner_id: scanner,
                        new_snapshot_id: uuid::Uuid::now_v7().to_string(),
                        observed_fingerprints: fingerprints,
                        required_checks_executed: true,
                        coverage_sufficient: true,
                        target_stable: target_stable_before,
                        contradictory_evidence: false,
                        scanner_error: false,
                        cancelled: false,
                    },
                )
                .map_err(map_error)?;
            self.save(&service.snapshot(&request.action_id).map_err(map_error)?)?;
            Ok(result)
        }
    }
    pub fn rollback(
        &self,
        request: RemediationActionRequest,
    ) -> Result<RollbackReceipt, SafeIpcError> {
        let mut service = self.lock_service()?;
        let result = service
            .rollback_with_journal(&request.action_id, |snapshot| {
                self.save(snapshot).map_err(|_| ServiceError::Integrity)
            })
            .map_err(map_error)?;
        #[cfg(all(feature = "native-e2e", debug_assertions))]
        {
            let root = self
                .fixture_root
                .as_ref()
                .ok_or_else(|| safe_error("scanner_unavailable"))?;
            let text = std::fs::read_to_string(root.join("security-config.toml"))
                .map_err(|_| safe_error("scanner_failed"))?;
            service
                .record_rollback_rescan(
                    &request.action_id,
                    text.contains("insecure_test_mode = true"),
                    true,
                )
                .map_err(map_error)?;
        }
        self.save(&service.snapshot(&request.action_id).map_err(map_error)?)?;
        Ok(result)
    }
    pub fn report(
        &self,
        request: RemediationReportRequest,
    ) -> Result<RemediationReportView, SafeIpcError> {
        let snapshot = self.get(RemediationActionRequest {
            action_id: request.action_id.clone(),
        })?;
        let audience = match request.kind {
            RemediationReportKind::Executive => RemediationAudience::Executive,
            RemediationReportKind::Technical => RemediationAudience::Technical,
            RemediationReportKind::Analyst => RemediationAudience::Analyst,
        };
        let report = RemediationReport::from_snapshot(&snapshot, audience);
        Ok(RemediationReportView {
            action_id: request.action_id,
            kind: request.kind,
            json: report.json().map_err(|_| safe_error("report_failed"))?,
            html: report.html(),
        })
    }
    fn lock_service(&self) -> Result<std::sync::MutexGuard<'_, RemediationService>, SafeIpcError> {
        self.service
            .lock()
            .map_err(|_| safe_error("remediation_unavailable"))
    }
    fn save(&self, snapshot: &RemediationSnapshot) -> Result<(), SafeIpcError> {
        self.store
            .lock()
            .map_err(|_| safe_error("storage_unavailable"))?
            .save(snapshot)
            .map_err(|_| safe_error("storage_failed"))
    }
}

fn reconcile_interrupted(
    store: &mut Level6SnapshotStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut offset = 0;
    loop {
        let batch = store.list(offset, 100)?;
        if batch.is_empty() {
            break;
        }
        let batch_len = batch.len();
        for mut snapshot in batch {
            if !matches!(
                snapshot.state,
                RemediationActionState::Preparing
                    | RemediationActionState::Applying
                    | RemediationActionState::Applied
                    | RemediationActionState::RollingBack
            ) {
                continue;
            }
            let Some(journal) = snapshot.journal.as_mut() else {
                continue;
            };
            let inspection = inspect_recovery_journal(journal).ok();
            let marker = match inspection.as_ref().map(|value| value.classification) {
                Some(RecoveryClassification::OriginalPresent) => {
                    "startup_recovery_original_present"
                }
                Some(RecoveryClassification::PatchedPresent) => "startup_recovery_patched_present",
                _ => "startup_recovery_unknown_state_manual_review",
            };
            journal.manual_review_required = inspection
                .as_ref()
                .is_none_or(|value| value.manual_review_required);
            if snapshot
                .timeline_safe
                .last()
                .is_none_or(|value| value != marker)
            {
                snapshot.timeline_safe.push(marker.into());
            }
            store.save(&snapshot)?;
        }
        if batch_len < 100 {
            break;
        }
        offset += 100;
    }
    Ok(())
}

fn guidance_for(kind: CandidateKind) -> (RemediationActionKind, Vec<String>, Vec<String>) {
    match kind{
    CandidateKind::InstalledApplication=>(RemediationActionKind::InstalledApplicationUpdate,vec!["Investigate the vendor-supported update or uninstall path; EDY VERDICT will not run it.".into()],vec!["Refresh the installed application inventory and rerun the relevant vulnerability checks.".into()]),
    CandidateKind::WebConfiguration=>(RemediationActionKind::RemoteWebConfiguration,vec!["Apply the documented header, cookie, or TLS change on the owned server manually.".into()],vec!["Run a newly authorized passive URL rescan.".into()]),
    CandidateKind::Secret=>(RemediationActionKind::SecretRotation,vec!["Remove the credential from the repository, rotate or revoke it, and inspect history manually.".into()],vec!["Rescan the repository and verify revocation with the provider.".into()]),
    CandidateKind::SuspiciousFile=>(RemediationActionKind::FileDeletionOrQuarantine,vec!["Isolate the host and review the suspicious file using an approved incident-response process.".into()],vec!["Re-authorize and rescan the file or affected host.".into()]),
    CandidateKind::RepositoryConfig=>unreachable!(),}
}
fn validate_finding_case(finding: &str, case_id: Option<&str>) -> Result<(), SafeIpcError> {
    if finding.is_empty() || finding.len() > 128 || finding.chars().any(char::is_control) {
        return Err(safe_error("invalid_request"));
    }
    if let Some(value) = case_id {
        validate_case(value)?;
    }
    Ok(())
}
fn validate_case(value: &str) -> Result<(), SafeIpcError> {
    let suffix = value
        .strip_prefix("case-v1-")
        .ok_or_else(|| safe_error("invalid_request"))?;
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(safe_error("invalid_request"));
    }
    Ok(())
}
fn map_error(error: ServiceError) -> SafeIpcError {
    safe_error(&error.to_string())
}
fn safe_error(code: &str) -> SafeIpcError {
    SafeIpcError {
        code: code.into(),
        message_safe: "Level 6 request could not be completed".into(),
        correlation_id: uuid::Uuid::now_v7().to_string(),
    }
}

#[cfg(all(test, feature = "native-e2e"))]
mod tests {
    use super::*;
    use edy_remediation::{RecoveryJournal, SYNTHETIC_FINDING_LEVEL6};
    use std::fs;

    #[test]
    fn startup_detects_interrupted_action_without_writing_target() {
        let root = std::env::temp_dir().join(format!(
            "edy-level6-startup-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("security-config.toml");
        fs::write(&target, "[security]\ninsecure_test_mode = true\n").unwrap();
        let database = root.join("level6.sqlite3");
        let mut service = RemediationService::default();
        let plan = service
            .create_synthetic_plan(&root, SYNTHETIC_FINDING_LEVEL6, None)
            .unwrap();
        let action = plan.actions[0].clone();
        let mut snapshot = service.snapshot(&action.action_id).unwrap();
        snapshot.state = RemediationActionState::Applying;
        snapshot.journal = Some(RecoveryJournal {
            action_id: action.action_id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            target_safe: action.precondition.canonical_path.clone(),
            repository_root_safe: root.to_string_lossy().replace('\\', "/"),
            original_sha256: action.precondition.expected_sha256.clone(),
            original_stable_identity: action.precondition.stable_identity.clone(),
            patched_sha256: action.verification.expected_post_sha256.clone(),
            backup_id: None,
            backup_sha256: None,
            state: RemediationActionState::Applying,
            manual_review_required: false,
        });
        {
            let mut store = Level6SnapshotStore::open(&database).unwrap();
            store.save(&snapshot).unwrap();
        }
        let before = fs::read(&target).unwrap();
        let backend = RemediationBackend::open(&database).unwrap();
        let recovered = backend
            .get(RemediationActionRequest {
                action_id: action.action_id,
            })
            .unwrap();
        assert_eq!(
            recovered.timeline_safe.last().unwrap(),
            "startup_recovery_original_present"
        );
        assert!(!recovered.journal.unwrap().manual_review_required);
        assert_eq!(fs::read(&target).unwrap(), before);
        drop(backend);
        fs::remove_dir_all(root).unwrap();
    }
}
