//! Production guidance and read-only rescan boundary. No mutating executor is imported.
use crate::ipc::SafeIpcError;
use edy_remediation::*;
use edy_repository::{
    AuthorizedRepositoryTarget, InventoryStatus, RepositoryInventory, RepositoryLimits,
    RepositoryObservation, aggregate_repository_posture, inspect,
};
use edy_storage::manual_remediation::ManualRemediationStore;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRemediationPlanRequest {
    pub run_id: String,
    pub case_id: String,
    pub finding_id: String,
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
pub struct VerifyRemediationRequest {
    pub action_id: String,
    pub authorization_token: String,
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
    pub authorization: VerificationAuthorization,
    pub authorization_token: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct RemediationPage {
    pub items: Vec<ManualSnapshot>,
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
#[derive(Debug, Clone, Serialize)]
pub struct RemediationCandidate {
    pub run_id: String,
    pub case_id: String,
    pub case_title: String,
    pub case_status: edy_core::CaseStatus,
    pub finding_id: String,
}
#[derive(Debug, Clone)]
pub struct RepositoryGuidanceSource {
    pub root: PathBuf,
    pub observation: RepositoryObservation,
}

pub struct RemediationBackend {
    store: Mutex<ManualRemediationStore>,
    running: Mutex<BTreeMap<String, Arc<AtomicBool>>>,
    #[cfg(any(test, all(feature = "native-e2e", debug_assertions)))]
    fixture_root: Option<PathBuf>,
}
impl RemediationBackend {
    pub fn open(database: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut store = ManualRemediationStore::open(database)?;
        store.recover_verifications()?;
        Ok(Self {
            store: Mutex::new(store),
            running: Mutex::new(BTreeMap::new()),
            #[cfg(any(test, all(feature = "native-e2e", debug_assertions)))]
            fixture_root: None,
        })
    }
    pub fn candidates(&self) -> Result<Vec<RemediationCandidate>, SafeIpcError> {
        let store = self.lock()?;
        let mut out = vec![];
        for run in store
            .investigation
            .list_run_ids(0, 100)
            .map_err(storage_error)?
        {
            for case in store
                .investigation
                .list_cases(&run, 0, 100)
                .map_err(storage_error)?
            {
                for finding in &case.finding_ids {
                    if out.len() >= 100 {
                        return Ok(out);
                    }
                    out.push(RemediationCandidate {
                        run_id: run.clone(),
                        case_id: case.case_id.clone(),
                        case_title: safe_manual_text(&case.title_safe, 512),
                        case_status: case.status,
                        finding_id: finding.clone(),
                    });
                }
            }
        }
        Ok(out)
    }
    pub fn source_finding(
        &self,
        request: &CreateRemediationPlanRequest,
    ) -> Result<edy_core::CorrelationFinding, SafeIpcError> {
        self.lock()?
            .finding(&request.run_id, &request.case_id, &request.finding_id)
            .map_err(storage_error)
    }
    pub fn create_plan(
        &self,
        request: CreateRemediationPlanRequest,
        origin: Option<RepositoryGuidanceSource>,
    ) -> Result<ManualSnapshot, SafeIpcError> {
        let finding = self.source_finding(&request)?;
        let mut store = self.lock()?;
        if let Some(existing) = store
            .find_for_member(&request.run_id, &request.case_id, &request.finding_id)
            .map_err(storage_error)?
        {
            return Ok(existing);
        }
        #[cfg(any(test, all(feature = "native-e2e", debug_assertions)))]
        let origin = origin.or_else(|| self.fixture_origin(&request.finding_id).ok().flatten());
        let zero = "0".repeat(64);
        let (kind, root, identity, scanner, fingerprint, guidance, diff, scope) = if let Some(
            origin,
        ) = origin
        {
            let root_text = origin.root.to_string_lossy().replace('\\', "/");
            if safe_manual_text(&root_text, 4096) != root_text {
                return Err(error("target_invalid"));
            }
            let target = authorized_repository(&root_text)?;
            let id = readonly_directory_identity(&target.root_path()).map_err(error)?;
            let baseline = inspect(&target).map_err(|_| error("scan_failed"))?;
            let baseline_findings = inventory_observations(&target, &baseline);
            if baseline.status != InventoryStatus::Complete
                || !baseline.security_events.is_empty()
                || !baseline_findings
                    .iter()
                    .any(|o| o.fingerprint == origin.observation.fingerprint)
            {
                return Err(error("original_finding_requires_fresh_scan"));
            }
            let ecosystem = origin
                .observation
                .package
                .clone()
                .ok_or_else(|| error("scanner_binding_unavailable"))?;
            let manifest_paths: Vec<_> = baseline
                .documents
                .iter()
                .filter(|d| {
                    d.ecosystem == ecosystem
                        && d.kind == edy_repository::RepositoryDocumentKind::Manifest
                })
                .map(|d| d.relative_path.clone())
                .collect();
            let material: Vec<_> = baseline_findings
                .iter()
                .filter(|o| material_finding(o))
                .map(|o| o.fingerprint.clone())
                .collect();
            if manifest_paths.is_empty() || manifest_paths.len() > 64 || material.len() > 64 {
                return Err(error("verification_scope_limit"));
            }
            let scope = Some(ManualVerificationScope {
                ecosystem,
                manifest_paths,
                baseline_material_fingerprints: material,
            });
            let guidance = vec![
                format!(
                    "Review {} for {} using its supported package manager. Generate and review the appropriate lockfile manually.",
                    safe_manual_text(&origin.observation.rule_id, 128),
                    safe_manual_text(
                        origin
                            .observation
                            .package
                            .as_deref()
                            .unwrap_or("repository"),
                        128
                    )
                ),
                MANUAL_DISCLOSURE.into(),
            ];
            let diff=Some("--- a/<package-manager-lockfile>\n+++ b/<package-manager-lockfile>\n@@ suggestion only @@\n+ Generate a nonempty lockfile with the supported package manager; review its full contents manually.\n".into());
            (
                RemediationActionKind::RepositoryInventoryReview,
                target.canonical_root().to_owned(),
                id,
                "edy-inventory".to_string(),
                origin.observation.fingerprint,
                guidance,
                diff,
                scope,
            )
        } else {
            (RemediationActionKind::Unsupported,"Authorized finding target; scanner binding unavailable".into(),finding.target_identity.canonical_value,"unavailable-original-check-family".into(),finding.finding_id.clone(),vec!["Review the original finding guidance and perform any changes outside EDY VERDICT. The required original check is currently unavailable; verification remains inconclusive.".into(),MANUAL_DISCLOSURE.into()],None,None)
        };
        let action=RemediationAction{action_id:String::new(),finding_id:request.finding_id.clone(),case_id:Some(request.case_id.clone()),target_id:finding.target_id,kind,safety_class:kind.required_safety(),rule_id:if scanner=="edy-inventory"{"MANUAL_REPOSITORY_INVENTORY_V1"}else{"MANUAL_GUIDANCE_V1"}.into(),rule_version:1,explanation_safe:"EDY VERDICT generates guidance and performs only the explicitly authorized rescan. It does not modify the target.".into(),precondition:RemediationPrecondition{canonical_path:root,stable_identity:identity,expected_sha256:zero.clone(),expected_size:0,expected_anchor_sha256:zero.clone()},edit:None,verification:VerificationPlan{scanner_id:scanner,original_fingerprint:fingerprint,required_checks:vec!["original finding family with fresh inventory".into()],expected_post_sha256:zero.clone(),coverage_required:true,manual_scope:scope},rollback:RollbackPlan{eligible:false,required_post_sha256:zero,explanation_safe:"Production rollback is policy blocked; no automatic change was performed.".into()}};
        let plan = RemediationPlan {
            plan_id: uuid::Uuid::now_v7().to_string(),
            plan_sha256: String::new(),
            finding_id: request.finding_id,
            case_id: Some(request.case_id),
            created_at_utc: manual_now(),
            actions: vec![action],
        };
        let mut snapshot =
            ManualSnapshot::create(plan, request.run_id, guidance, diff).map_err(error)?;
        store.save(&mut snapshot).map_err(storage_error)?;
        Ok(snapshot)
    }
    pub fn get(&self, request: RemediationActionRequest) -> Result<ManualSnapshot, SafeIpcError> {
        self.lock()?.get(&request.action_id).map_err(storage_error)
    }
    pub fn list(&self, request: RemediationPageRequest) -> Result<RemediationPage, SafeIpcError> {
        Ok(RemediationPage {
            items: self
                .lock()?
                .list(None, request.offset, request.limit)
                .map_err(storage_error)?,
            offset: request.offset,
            limit: request.limit,
        })
    }
    pub fn list_case(
        &self,
        request: CaseRemediationRequest,
    ) -> Result<RemediationPage, SafeIpcError> {
        Ok(RemediationPage {
            items: self
                .lock()?
                .list(Some(&request.case_id), request.offset, request.limit)
                .map_err(storage_error)?,
            offset: request.offset,
            limit: request.limit,
        })
    }
    pub fn preview(
        &self,
        request: RemediationActionRequest,
    ) -> Result<ManualSnapshot, SafeIpcError> {
        let mut store = self.lock()?;
        let mut s = store.get(&request.action_id).map_err(storage_error)?;
        let old = s.state;
        s.review().map_err(error)?;
        if s.state != old {
            store.save(&mut s).map_err(storage_error)?;
        }
        Ok(s)
    }
    pub fn authorize(
        &self,
        request: AuthorizeRemediationRequest,
    ) -> Result<AuthorizationView, SafeIpcError> {
        if !request.confirmed {
            return Err(error("explicit_rescan_confirmation_required"));
        }
        let mut store = self.lock()?;
        let mut s = store.get(&request.action_id).map_err(storage_error)?;
        if s.plan.plan_sha256 != request.plan_sha256 {
            return Err(error("verification_authorization_denied"));
        }
        let raw = s
            .authorize_verification(time::OffsetDateTime::now_utc().unix_timestamp())
            .map_err(error)?;
        store.save(&mut s).map_err(storage_error)?;
        Ok(AuthorizationView {
            authorization: s
                .authorization
                .ok_or_else(|| error("verification_authorization_denied"))?,
            authorization_token: raw,
        })
    }
    pub fn verify(
        &self,
        request: VerifyRemediationRequest,
    ) -> Result<ManualSnapshot, SafeIpcError> {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut running = self
            .running
            .lock()
            .map_err(|_| error("verification_busy"))?;
        if running.contains_key(&request.action_id) {
            return Err(error("verification_busy"));
        }
        let mut s = {
            let mut store = self.lock()?;
            let mut s = store.get(&request.action_id).map_err(storage_error)?;
            s.begin_verification(
                &request.authorization_token,
                time::OffsetDateTime::now_utc().unix_timestamp(),
            )
            .map_err(error)?;
            store.save(&mut s).map_err(storage_error)?;
            s
        };
        running.insert(request.action_id.clone(), cancel.clone());
        drop(running);
        // Test profile delay enables real UI cancellation/restart; no mutating executor feature.
        #[cfg(any(test, all(feature = "native-e2e", debug_assertions)))]
        if self.fixture_root.is_some() {
            for _ in 0..15 {
                if cancel.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        let mut observation = self.rescan(&s, &cancel);
        // Serialize cancellation acknowledgement against final COMMIT. An accepted
        // cancellation can never race a persisted RESOLVED result.
        let mut running = self
            .running
            .lock()
            .map_err(|_| error("verification_busy"))?;
        observation.cancelled |= cancel.load(Ordering::SeqCst);
        let result = (|| {
            s.finish(observation).map_err(error)?;
            self.lock()?.save(&mut s).map_err(storage_error)?;
            Ok(s)
        })();
        running.remove(&request.action_id);
        result
    }
    pub fn cancel(&self, request: RemediationActionRequest) -> Result<bool, SafeIpcError> {
        let running = self
            .running
            .lock()
            .map_err(|_| error("verification_busy"))?;
        if let Some(cancel) = running.get(&request.action_id) {
            cancel.store(true, Ordering::SeqCst);
            Ok(true)
        } else {
            Err(error("verification_not_running"))
        }
    }
    fn rescan(&self, s: &ManualSnapshot, cancel: &AtomicBool) -> FreshVerification {
        let action = &s.plan.actions[0];
        let mut result = FreshVerification {
            scanner_id: action.verification.scanner_id.clone(),
            original_present: true,
            required_checks_executed: false,
            sufficient_coverage: false,
            stable_during_scan: true,
            target_valid: true,
            contradictory: false,
            regression_count: 0,
            cancelled: cancel.load(Ordering::SeqCst),
        };
        if action.verification.scanner_id != "edy-inventory" {
            return result;
        }
        let scanned = (|| {
            let target = authorized_repository(&action.precondition.canonical_path)?;
            if readonly_directory_identity(&target.root_path()).map_err(error)?
                != action.precondition.stable_identity
            {
                return Err(error("target_invalid"));
            }
            let before = inspect(&target).map_err(|_| error("scan_failed"))?;
            let scope = action
                .verification
                .manual_scope
                .as_ref()
                .ok_or_else(|| error("scanner_binding_unavailable"))?;
            let observations = inventory_observations(&target, &before);
            let after = inspect(&target).map_err(|_| error("scan_failed"))?;
            result.stable_during_scan = before.structural_fingerprint
                == after.structural_fingerprint
                && readonly_directory_identity(&target.root_path()).map_err(error)?
                    == action.precondition.stable_identity;
            result.required_checks_executed = true;
            result.sufficient_coverage = before.status == InventoryStatus::Complete
                && after.status == InventoryStatus::Complete
                && before.security_events.is_empty()
                && after.security_events.is_empty()
                && before.oversized_files == 0
                && after.oversized_files == 0
                && !scope.manifest_paths.is_empty()
                && scope.manifest_paths.iter().all(|p| {
                    before.documents.iter().any(|d| {
                        &d.relative_path == p
                            && d.ecosystem == scope.ecosystem
                            && d.kind == edy_repository::RepositoryDocumentKind::Manifest
                    })
                });
            result.original_present = observations
                .iter()
                .any(|o| o.fingerprint == action.verification.original_fingerprint);
            result.regression_count = observations
                .iter()
                .filter(|o| {
                    material_finding(o)
                        && o.fingerprint != action.verification.original_fingerprint
                        && !scope
                            .baseline_material_fingerprints
                            .contains(&o.fingerprint)
                })
                .count() as u32;
            Ok::<_, SafeIpcError>(())
        })();
        if let Err(e) = scanned {
            result.target_valid = e.code != "target_invalid";
            result.required_checks_executed = false;
            result.sufficient_coverage = false;
        }
        result.cancelled = cancel.load(Ordering::SeqCst);
        result
    }
    pub fn report(
        &self,
        request: RemediationReportRequest,
    ) -> Result<RemediationReportView, SafeIpcError> {
        let s = self.get(RemediationActionRequest {
            action_id: request.action_id.clone(),
        })?;
        let report = edy_reporting::remediation::ManualRemediationReport::from_snapshot(&s);
        Ok(RemediationReportView {
            action_id: request.action_id,
            kind: request.kind,
            json: report.json().map_err(|_| error("report_failed"))?,
            html: report.html(),
        })
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ManualRemediationStore>, SafeIpcError> {
        self.store.lock().map_err(|_| error("storage_unavailable"))
    }
}
fn error(code: &str) -> SafeIpcError {
    SafeIpcError {
        code: code.into(),
        message_safe: "Manual guidance or verification request was refused safely".into(),
        correlation_id: uuid::Uuid::now_v7().to_string(),
    }
}
fn storage_error(_: edy_storage::level0_snapshot::SnapshotError) -> SafeIpcError {
    error("manual_storage_integrity")
}
fn authorized_repository(root: &str) -> Result<AuthorizedRepositoryTarget, SafeIpcError> {
    AuthorizedRepositoryTarget::authorize(
        root,
        edy_core::TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789f6")
            .map_err(|_| error("target_invalid"))?,
        uuid::Uuid::now_v7().to_string(),
        manual_now(),
        RepositoryLimits {
            max_files: 10000,
            max_total_bytes: 64 * 1024 * 1024,
            max_file_bytes: 1024 * 1024,
            max_depth: 32,
        },
    )
    .map_err(|_| error("target_invalid"))
}
fn inventory_observations(
    target: &AuthorizedRepositoryTarget,
    inventory: &RepositoryInventory,
) -> Vec<RepositoryObservation> {
    aggregate_repository_posture(
        target,
        inventory,
        &inventory
            .ecosystems
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        false,
    )
}

fn material_finding(o: &RepositoryObservation) -> bool {
    matches!(o.severity.as_str(), "medium" | "high" | "critical")
}

#[cfg(test)]
#[path = "remediation_tests.rs"]
mod tests;

#[cfg(any(test, all(feature = "native-e2e", debug_assertions)))]
impl RemediationBackend {
    pub fn open_fixture(database: &Path, root: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        // The external harness owns fixture writes; startup only reads it.
        let mut backend = Self::open(database)?;
        backend.fixture_root = Some(root.to_path_buf());
        let mut store = backend.lock()?;
        let run = "018f4c2a-1d3b-7abc-8def-0123456789f6";
        if !store
            .investigation
            .list_run_ids(0, 100)?
            .iter()
            .any(|r| r == run)
        {
            // Two actual, externally prepared repositories share the declared
            // synthetic fixture package. Correlation is performed normally.
            let mut findings = Vec::new();
            for fixture_root in [
                root.to_path_buf(),
                root.parent()
                    .ok_or("fixture parent")?
                    .join("synthetic-associated-repo"),
            ] {
                let target = authorized_repository(&fixture_root.to_string_lossy())
                    .map_err(|_| "fixture target invalid")?;
                let inventory = inspect(&target)?;
                let observed = inventory_observations(&target, &inventory);
                findings.extend(
                    observed
                        .iter()
                        .filter(|o| {
                            o.rule_id == "missing-lockfile"
                                || o.rule_id == "vulnerability-data-unavailable"
                        })
                        .map(|o| {
                            let identity = edy_core::StrongIdentity::new(
                                edy_core::IdentifierKind::StableTarget,
                                sha256_hex(target.canonical_root().as_bytes()),
                            )
                            .expect("synthetic identity");
                            edy_core::CorrelationFinding {
                                finding_id: o.fingerprint.clone(),
                                target_id: identity.canonical_value.clone(),
                                target_type: edy_core::TargetType::Repository,
                                target_identity: identity.clone(),
                                affected_identity: edy_core::StrongIdentity::new(
                                    edy_core::IdentifierKind::Purl,
                                    "pkg:npm/controlled-fixture@1.0.0",
                                )
                                .expect("fixture package identity"),
                                vulnerability_id: None,
                                artifact_sha256: None,
                                purl: Some("pkg:npm/controlled-fixture@1.0.0".into()),
                                cpe: None,
                                web_origin: None,
                                web_domain: None,
                                evidence_ids: vec![format!(
                                    "evidence-{}",
                                    sha256_hex(o.fingerprint.as_bytes())
                                )],
                                source_scans: vec![run.into()],
                                severity_points: if o.severity == "medium" { 50 } else { 10 },
                                kev: false,
                                epss_basis_points: None,
                                provider_available: o.rule_id != "vulnerability-data-unavailable",
                                parser_certain: true,
                                conflicting_evidence: false,
                                first_seen: manual_now(),
                                last_seen: manual_now(),
                                occurrence_count: 1,
                                reopened: false,
                            }
                        })
                        .collect::<Vec<_>>(),
                );
            }
            let result = edy_core::correlate_investigation(
                findings.clone(),
                edy_core::GraphLimits::default(),
                || false,
            )?;
            store.investigation.promote(run, &findings, &result)?;
        }
        drop(store);
        Ok(backend)
    }
    fn fixture_origin(
        &self,
        finding: &str,
    ) -> Result<Option<RepositoryGuidanceSource>, SafeIpcError> {
        let Some(root) = &self.fixture_root else {
            return Ok(None);
        };
        let target = authorized_repository(&root.to_string_lossy())?;
        let inventory = inspect(&target).map_err(|_| error("scan_failed"))?;
        Ok(inventory_observations(&target, &inventory)
            .into_iter()
            .find(|o| o.fingerprint == finding && o.rule_id == "missing-lockfile")
            .map(|observation| RepositoryGuidanceSource {
                root: root.clone(),
                observation,
            }))
    }
}
