//! Typed Level 5 application boundary. The webview receives redacted, bounded domain views only.

use crate::ipc::SafeIpcError;
use edy_core::{
    CaseStatus, CorrelationResult, CorrelationRunState, FindingCluster, GraphLimits,
    InvestigationCase, correlate_investigation,
};
#[cfg(all(feature = "native-e2e", debug_assertions))]
use edy_core::{CorrelationFinding, IdentifierKind, StrongIdentity, TargetType};
use edy_reporting::investigation::{InvestigationAudience, InvestigationReport};
use edy_storage::level0_snapshot::Level5SnapshotStore;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[cfg(all(feature = "native-e2e", debug_assertions))]
const FIXTURE_RUN_ID: &str = "018f4c2a-1d3b-7abc-8def-0123456789f0";

#[cfg(all(feature = "native-e2e", debug_assertions))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NativeCorrelationScenario {
    #[default]
    Complete,
    Cancellation,
    Limit,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationPageRequest {
    pub run_id: String,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationItemRequest {
    pub run_id: String,
    pub item_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationRunRequest {
    pub run_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseTransitionRequest {
    pub run_id: String,
    pub case_id: String,
    pub status: CaseStatus,
    pub reason_safe: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationReportKind {
    Executive,
    Technical,
    Analyst,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationReportRequest {
    pub run_id: String,
    pub case_id: String,
    pub kind: InvestigationReportKind,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorrelationSummaryView {
    pub run_id: String,
    pub state: CorrelationRunState,
    pub limit_reached: bool,
    pub replay_match: bool,
    pub nodes: u32,
    pub relationships: u32,
    pub clusters: u32,
    pub cases: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct InvestigationPage<T> {
    pub items: Vec<T>,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct InvestigationReportView {
    pub run_id: String,
    pub case_id: String,
    pub kind: InvestigationReportKind,
    pub json: String,
    pub html: String,
}

pub struct InvestigationBackend {
    store: Mutex<Level5SnapshotStore>,
    cancel_requested: AtomicBool,
    #[cfg(all(feature = "native-e2e", debug_assertions))]
    native_scenario: NativeCorrelationScenario,
}

impl InvestigationBackend {
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            store: Mutex::new(Level5SnapshotStore::open(path)?),
            cancel_requested: AtomicBool::new(false),
            #[cfg(all(feature = "native-e2e", debug_assertions))]
            native_scenario: NativeCorrelationScenario::Complete,
        })
    }

    #[cfg(all(feature = "native-e2e", debug_assertions))]
    pub fn open_fixture(
        path: &Path,
        native_scenario: NativeCorrelationScenario,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let backend = Self {
            store: Mutex::new(Level5SnapshotStore::open(path)?),
            cancel_requested: AtomicBool::new(false),
            native_scenario,
        };
        let mut store = backend.store.lock().map_err(|_| "Level 5 lock failed")?;
        if store.list_run_ids(0, 1)?.is_empty() {
            let observations = fixture_observations();
            let result =
                correlate_investigation(observations.clone(), GraphLimits::default(), || false)?;
            store.promote(FIXTURE_RUN_ID, &observations, &result)?;
        }
        drop(store);
        Ok(backend)
    }

    pub fn run_correlation(&self) -> Result<CorrelationSummaryView, SafeIpcError> {
        self.cancel_requested.store(false, Ordering::SeqCst);
        let store = self.lock()?;
        let run_id = store
            .list_run_ids(0, 1)
            .map_err(|_| safe_error("correlation_unavailable"))?
            .into_iter()
            .next()
            .ok_or_else(|| safe_error("correlation_unavailable"))?;
        let observations = store
            .load_observations(&run_id)
            .map_err(|_| safe_error("correlation_integrity"))?;
        let expected = store
            .load_result(&run_id)
            .map_err(|_| safe_error("correlation_integrity"))?;
        #[cfg(all(feature = "native-e2e", debug_assertions))]
        let limits = if self.native_scenario == NativeCorrelationScenario::Limit {
            GraphLimits {
                nodes_per_run: 1,
                ..GraphLimits::default()
            }
        } else {
            GraphLimits::default()
        };
        #[cfg(not(all(feature = "native-e2e", debug_assertions)))]
        let limits = GraphLimits::default();
        let replay = correlate_investigation(observations, limits, || {
            #[cfg(all(feature = "native-e2e", debug_assertions))]
            if self.native_scenario == NativeCorrelationScenario::Cancellation {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            self.cancel_requested.load(Ordering::SeqCst)
        })
        .map_err(|_| safe_error("correlation_refused"))?;
        let replay_match = replay == expected;
        if replay.state == CorrelationRunState::Complete && !replay_match {
            return Err(safe_error("correlation_mismatch"));
        }
        Ok(summary(&run_id, &replay, replay_match))
    }

    pub fn cancel_correlation(&self) -> bool {
        !self.cancel_requested.swap(true, Ordering::SeqCst)
    }

    pub fn list_clusters(
        &self,
        request: InvestigationPageRequest,
    ) -> Result<InvestigationPage<FindingCluster>, SafeIpcError> {
        validate_page(&request)?;
        let items = self
            .lock()?
            .list_clusters(&request.run_id, request.offset, request.limit)
            .map_err(|_| safe_error("cluster_read_failed"))?;
        Ok(InvestigationPage {
            items,
            offset: request.offset,
            limit: request.limit,
        })
    }
    pub fn get_cluster(
        &self,
        request: InvestigationItemRequest,
    ) -> Result<FindingCluster, SafeIpcError> {
        validate_item(&request, "cluster-v1-")?;
        self.lock()?
            .get_cluster(&request.run_id, &request.item_id)
            .map_err(|_| safe_error("cluster_not_found"))
    }
    pub fn list_cases(
        &self,
        request: InvestigationPageRequest,
    ) -> Result<InvestigationPage<InvestigationCase>, SafeIpcError> {
        validate_page(&request)?;
        let items = self
            .lock()?
            .list_cases(&request.run_id, request.offset, request.limit)
            .map_err(|_| safe_error("case_read_failed"))?;
        Ok(InvestigationPage {
            items,
            offset: request.offset,
            limit: request.limit,
        })
    }
    pub fn get_case(
        &self,
        request: InvestigationItemRequest,
    ) -> Result<InvestigationCase, SafeIpcError> {
        validate_item(&request, "case-v1-")?;
        self.lock()?
            .get_case(&request.run_id, &request.item_id)
            .map_err(|_| safe_error("case_not_found"))
    }
    pub fn graph(&self, run_id: &str) -> Result<CorrelationResult, SafeIpcError> {
        if !valid_uuid(run_id) {
            return Err(safe_error("invalid_request"));
        }
        self.lock()?
            .load_result(run_id)
            .map_err(|_| safe_error("graph_read_failed"))
    }
    pub fn create_case_from_cluster(
        &self,
        request: InvestigationItemRequest,
    ) -> Result<InvestigationCase, SafeIpcError> {
        validate_item(&request, "cluster-v1-")?;
        let mut store = self.lock()?;
        store
            .get_cluster(&request.run_id, &request.item_id)
            .map_err(|_| safe_error("cluster_not_found"))?;
        let mut case = store
            .list_cases(&request.run_id, 0, 100)
            .map_err(|_| safe_error("case_read_failed"))?
            .into_iter()
            .find(|case| case.cluster_ids.contains(&request.item_id))
            .ok_or_else(|| safe_error("case_not_found"))?;
        let timestamp = next_timestamp(&case)?;
        case.transition(
            CaseStatus::Open,
            &timestamp,
            "user",
            "Analyst opened suggested correlation case",
        )
        .map_err(|_| safe_error("case_transition_refused"))?;
        store
            .replace_case(&request.run_id, &case)
            .map_err(|_| safe_error("case_write_failed"))?;
        Ok(case)
    }
    pub fn update_case_status(
        &self,
        request: CaseTransitionRequest,
    ) -> Result<InvestigationCase, SafeIpcError> {
        if !valid_uuid(&request.run_id)
            || !valid_level5_id(&request.case_id, "case-v1-")
            || request.reason_safe.len() > 512
        {
            return Err(safe_error("invalid_request"));
        }
        let mut store = self.lock()?;
        let mut case = store
            .get_case(&request.run_id, &request.case_id)
            .map_err(|_| safe_error("case_not_found"))?;
        let timestamp = next_timestamp(&case)?;
        case.transition(request.status, &timestamp, "user", &request.reason_safe)
            .map_err(|_| safe_error("case_transition_refused"))?;
        store
            .replace_case(&request.run_id, &case)
            .map_err(|_| safe_error("case_write_failed"))?;
        Ok(case)
    }
    pub fn report(
        &self,
        request: InvestigationReportRequest,
    ) -> Result<InvestigationReportView, SafeIpcError> {
        if !valid_uuid(&request.run_id) || !valid_level5_id(&request.case_id, "case-v1-") {
            return Err(safe_error("invalid_request"));
        }
        let case = self
            .lock()?
            .get_case(&request.run_id, &request.case_id)
            .map_err(|_| safe_error("case_not_found"))?;
        let audience = match request.kind {
            InvestigationReportKind::Executive => InvestigationAudience::Executive,
            InvestigationReportKind::Technical => InvestigationAudience::Technical,
            InvestigationReportKind::Analyst => InvestigationAudience::Analyst,
        };
        let report = InvestigationReport::capture_for(&case, audience);
        Ok(InvestigationReportView {
            run_id: request.run_id,
            case_id: request.case_id,
            kind: request.kind,
            json: report.json().map_err(|_| safe_error("report_failed"))?,
            html: report.html(),
        })
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Level5SnapshotStore>, SafeIpcError> {
        self.store
            .lock()
            .map_err(|_| safe_error("storage_unavailable"))
    }
}

fn summary(run_id: &str, result: &CorrelationResult, replay_match: bool) -> CorrelationSummaryView {
    CorrelationSummaryView {
        run_id: run_id.into(),
        state: result.state,
        limit_reached: result.limit_reached,
        replay_match,
        nodes: result.nodes.len() as u32,
        relationships: result.edges.len() as u32,
        clusters: result.clusters.len() as u32,
        cases: result.suggested_cases.len() as u32,
    }
}
fn validate_page(request: &InvestigationPageRequest) -> Result<(), SafeIpcError> {
    if !valid_uuid(&request.run_id)
        || request.offset > 10_000
        || !(1..=100).contains(&request.limit)
    {
        Err(safe_error("invalid_request"))
    } else {
        Ok(())
    }
}
fn validate_item(request: &InvestigationItemRequest, prefix: &str) -> Result<(), SafeIpcError> {
    if !valid_uuid(&request.run_id) || !valid_level5_id(&request.item_id, prefix) {
        Err(safe_error("invalid_request"))
    } else {
        Ok(())
    }
}
fn valid_level5_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}
fn valid_uuid(value: &str) -> bool {
    edy_core::ScanId::new(value).is_ok()
}
fn next_timestamp(case: &InvestigationCase) -> Result<String, SafeIpcError> {
    use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
    let previous = case
        .timeline
        .last()
        .ok_or_else(|| safe_error("case_integrity"))?;
    let previous = OffsetDateTime::parse(&previous.timestamp, &Rfc3339)
        .map_err(|_| safe_error("case_integrity"))?;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|_| safe_error("time_unavailable"))?;
    let timestamp = if now > previous {
        now
    } else {
        previous + Duration::SECOND
    };
    timestamp
        .format(&Rfc3339)
        .map_err(|_| safe_error("time_unavailable"))
}
fn safe_error(code: &str) -> SafeIpcError {
    SafeIpcError {
        code: code.into(),
        message_safe: "Level 5 request could not be completed".into(),
        correlation_id: uuid::Uuid::now_v7().to_string(),
    }
}

#[cfg(all(feature = "native-e2e", debug_assertions))]
fn fixture_observations() -> Vec<CorrelationFinding> {
    let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut observations = vec![
        fixture(
            "repo-finding",
            "repo-target",
            TargetType::Repository,
            Some("CVE-2099-1001"),
            None,
            Some("pkg:npm/edy-safe-fixture@1.0.0"),
            None,
        ),
        fixture(
            "app-finding",
            "app-target",
            TargetType::InstalledApplication,
            Some("CVE-2099-1001"),
            Some(hash),
            None,
            None,
        ),
        fixture(
            "repo-similar-name",
            "repo-target-similar",
            TargetType::Repository,
            None,
            None,
            Some("pkg:npm/edy-safe-fixture-extra@1.0.0"),
            None,
        ),
        fixture(
            "file-finding",
            "file-target",
            TargetType::File,
            None,
            Some(hash),
            None,
            None,
        ),
        fixture(
            "web-a",
            "web-target-a",
            TargetType::WebUrl,
            None,
            None,
            None,
            Some("https://example.synthetic"),
        ),
        fixture(
            "web-b",
            "web-target-b",
            TargetType::WebUrl,
            None,
            None,
            None,
            Some("https://example.synthetic"),
        ),
    ];
    observations[0].last_seen = "2099-01-03T00:00:00Z".into();
    observations[0].occurrence_count = 2;
    observations[0].reopened = true;
    observations
}

#[cfg(all(feature = "native-e2e", debug_assertions))]
fn fixture(
    id: &str,
    target: &str,
    target_type: TargetType,
    cve: Option<&str>,
    hash: Option<&str>,
    purl: Option<&str>,
    origin: Option<&str>,
) -> CorrelationFinding {
    let affected_kind = match target_type {
        TargetType::Repository => IdentifierKind::Purl,
        TargetType::File => IdentifierKind::Sha256,
        TargetType::InstalledApplication => IdentifierKind::MsiProduct,
        TargetType::WebUrl => IdentifierKind::CanonicalUrl,
    };
    let affected = match target_type {
        TargetType::Repository => purl.unwrap(),
        TargetType::File => hash.unwrap(),
        TargetType::InstalledApplication => target,
        TargetType::WebUrl => "https://example.synthetic/path",
    };
    CorrelationFinding {
        finding_id: id.into(),
        target_id: target.into(),
        target_type,
        target_identity: StrongIdentity::new(IdentifierKind::StableTarget, target).unwrap(),
        affected_identity: StrongIdentity::new(affected_kind, affected).unwrap(),
        vulnerability_id: cve.map(str::to_string),
        artifact_sha256: hash.map(str::to_string),
        purl: purl.map(str::to_string),
        cpe: None,
        web_origin: origin.map(str::to_string),
        web_domain: origin.map(|_| "example.synthetic".into()),
        evidence_ids: vec![format!("evidence-{id}")],
        source_scans: vec![format!("scan-{id}")],
        severity_points: 70,
        kev: cve.is_some(),
        epss_basis_points: Some(8000),
        provider_available: true,
        parser_certain: true,
        conflicting_evidence: false,
        first_seen: "2099-01-01T00:00:00Z".into(),
        last_seen: "2099-01-02T00:00:00Z".into(),
        occurrence_count: 1,
        reopened: false,
    }
}

#[cfg(all(test, feature = "native-e2e", debug_assertions))]
mod tests {
    use super::*;
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "edy-level5-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn fixture_flows_through_real_storage_lifecycle_graph_and_reports() {
        let temp = Temp::new();
        let backend = InvestigationBackend::open_fixture(
            &temp.0.join("level5.sqlite3"),
            NativeCorrelationScenario::Complete,
        )
        .unwrap();
        let summary = backend.run_correlation().unwrap();
        assert!(
            summary.replay_match
                && summary.nodes > 0
                && summary.relationships > 0
                && summary.cases > 0
        );
        let clusters = backend
            .list_clusters(InvestigationPageRequest {
                run_id: summary.run_id.clone(),
                offset: 0,
                limit: 100,
            })
            .unwrap()
            .items;
        let cases = backend
            .list_cases(InvestigationPageRequest {
                run_id: summary.run_id.clone(),
                offset: 0,
                limit: 100,
            })
            .unwrap()
            .items;
        let graph = backend.graph(&summary.run_id).unwrap();
        assert!(graph.edges.iter().all(|edge| {
            graph
                .nodes
                .iter()
                .any(|node| node.entity_id == edge.from_entity)
                && graph
                    .nodes
                    .iter()
                    .any(|node| node.entity_id == edge.to_entity)
        }));
        let opened = backend
            .create_case_from_cluster(InvestigationItemRequest {
                run_id: summary.run_id.clone(),
                item_id: clusters[0].cluster_id.clone(),
            })
            .unwrap();
        assert_eq!(opened.status, CaseStatus::Open);
        let investigating = backend
            .update_case_status(CaseTransitionRequest {
                run_id: summary.run_id.clone(),
                case_id: opened.case_id.clone(),
                status: CaseStatus::Investigating,
                reason_safe: "Analyst review".into(),
            })
            .unwrap();
        assert_eq!(investigating.timeline.len(), 3);
        assert!(
            backend
                .update_case_status(CaseTransitionRequest {
                    run_id: summary.run_id.clone(),
                    case_id: investigating.case_id.clone(),
                    status: CaseStatus::Remediating,
                    reason_safe: "EDY_FAKE_SECRET_LEVEL5".into()
                })
                .is_err()
        );
        for kind in [
            InvestigationReportKind::Executive,
            InvestigationReportKind::Technical,
            InvestigationReportKind::Analyst,
        ] {
            let report = backend
                .report(InvestigationReportRequest {
                    run_id: summary.run_id.clone(),
                    case_id: investigating.case_id.clone(),
                    kind,
                })
                .unwrap();
            assert!(report.json.contains("LEVEL5_INVESTIGATION_REPORT_V1"));
            assert!(!report.json.contains("EDY_FAKE_SECRET_LEVEL5"));
        }
        assert!(!cases.is_empty());
    }
}
