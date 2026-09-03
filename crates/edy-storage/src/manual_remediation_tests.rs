use super::*;
use crate::level0_snapshot::*;
use edy_remediation::*;
use std::{fs, path::PathBuf};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("edy-manual-storage-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
const RUN: &str = "018f4c2a-1d3b-7abc-8def-0123456789f6";
fn finding(id: &str, target: &str) -> CorrelationFinding {
    use edy_core::{IdentifierKind, StrongIdentity, TargetType};
    CorrelationFinding {
        finding_id: id.into(),
        target_id: target.into(),
        target_type: TargetType::Repository,
        target_identity: StrongIdentity::new(IdentifierKind::StableTarget, target).unwrap(),
        affected_identity: StrongIdentity::new(IdentifierKind::Purl, "pkg:npm/fixture@1.0.0")
            .unwrap(),
        vulnerability_id: None,
        artifact_sha256: None,
        purl: Some("pkg:npm/fixture@1.0.0".into()),
        cpe: None,
        web_origin: None,
        web_domain: None,
        evidence_ids: vec![format!("evidence-{id}")],
        source_scans: vec![RUN.into()],
        severity_points: 50,
        kev: false,
        epss_basis_points: None,
        provider_available: true,
        parser_certain: true,
        conflicting_evidence: false,
        first_seen: manual_now(),
        last_seen: manual_now(),
        occurrence_count: 1,
        reopened: false,
    }
}
fn seed(store: &mut ManualRemediationStore) -> String {
    let observations = vec![
        finding("finding-a", "target-a"),
        finding("finding-b", "target-b"),
    ];
    let result = edy_core::correlate_investigation(
        observations.clone(),
        edy_core::GraphLimits::default(),
        || false,
    )
    .unwrap();
    assert_eq!(result.suggested_cases.len(), 1);
    let id = result.suggested_cases[0].case_id.clone();
    store
        .investigation
        .promote(RUN, &observations, &result)
        .unwrap();
    id
}
fn plan(case: &str, finding: &str) -> ManualSnapshot {
    let z = "0".repeat(64);
    let action = RemediationAction {
        action_id: String::new(),
        finding_id: finding.into(),
        case_id: Some(case.into()),
        target_id: format!("target-{}", finding.chars().last().unwrap()),
        kind: RemediationActionKind::RepositoryInventoryReview,
        safety_class: RemediationSafetyClass::ManualChangeVerifiable,
        rule_id: "MANUAL_REPOSITORY_INVENTORY_V1".into(),
        rule_version: 1,
        explanation_safe: "Read-only original scanner verification".into(),
        precondition: RemediationPrecondition {
            canonical_path: "synthetic-authorized-repository".into(),
            stable_identity: "fixture-directory".into(),
            expected_sha256: z.clone(),
            expected_size: 0,
            expected_anchor_sha256: z.clone(),
        },
        edit: None,
        verification: VerificationPlan {
            scanner_id: "edy-inventory".into(),
            original_fingerprint: finding.into(),
            required_checks: vec!["original inventory".into()],
            expected_post_sha256: z.clone(),
            coverage_required: true,
            manual_scope: None,
        },
        rollback: RollbackPlan {
            eligible: false,
            required_post_sha256: z,
            explanation_safe: "POLICY_BLOCKED".into(),
        },
    };
    ManualSnapshot::create(
        RemediationPlan {
            plan_id: uuid::Uuid::now_v7().to_string(),
            plan_sha256: String::new(),
            finding_id: finding.into(),
            case_id: Some(case.into()),
            created_at_utc: manual_now(),
            actions: vec![action],
        },
        RUN.into(),
        vec!["Manual action required".into()],
        None,
    )
    .unwrap()
}
fn complete(s: &mut ManualSnapshot, store: &mut ManualRemediationStore, outcome: ManualState) {
    s.review().unwrap();
    store.save(s).unwrap();
    let raw = s.authorize_verification(100).unwrap();
    store.save(s).unwrap();
    s.begin_verification(&raw, 101).unwrap();
    store.save(s).unwrap();
    s.finish(FreshVerification {
        scanner_id: "edy-inventory".into(),
        original_present: outcome == ManualState::StillPresent,
        required_checks_executed: outcome != ManualState::Inconclusive,
        sufficient_coverage: true,
        stable_during_scan: true,
        target_valid: true,
        contradictory: false,
        regression_count: u32::from(outcome == ManualState::RegressionDetected),
        cancelled: outcome == ManualState::Cancelled,
    })
    .unwrap();
    store.save(s).unwrap();
}
#[test]
fn migrations_zero_through_seven_preserve_data_and_have_no_production_write_journal() {
    for version in 0..=7 {
        let temp = Temp::new();
        let path = temp.0.join("state.sqlite3");
        match version {
            0 => {}
            1 => {
                Level0SnapshotStore::open(&path).unwrap();
            }
            2 => {
                Level1SnapshotStore::open(&path).unwrap();
            }
            3 => {
                Level2SnapshotStore::open(&path).unwrap();
            }
            4 => {
                Level3SnapshotStore::open(&path).unwrap();
            }
            5 => {
                Level4SnapshotStore::open(&path).unwrap();
            }
            6 => {
                Level5SnapshotStore::open(&path).unwrap();
            }
            _ => {
                crate::level6_snapshot::Level6SnapshotStore::open(&path).unwrap();
            }
        }
        if version > 0 {
            Level0SnapshotStore::open(&path)
                .unwrap()
                .create(RUN, b"{\"safe\":true}")
                .unwrap();
        }
        let store = ManualRemediationStore::open(&path).unwrap();
        assert_eq!(
            store
                .investigation
                .connection
                .query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
                .unwrap(),
            8
        );
        assert_eq!(
            store
                .investigation
                .connection
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
                    .get::<_, u32>(
                    0
                ))
                .unwrap(),
            0
        );
        if version < 7 {
            assert_eq!(
                store
                    .investigation
                    .connection
                    .query_row(
                        "SELECT count(*) FROM sqlite_master WHERE name='level6_recovery_journal'",
                        [],
                        |r| r.get::<_, u32>(0)
                    )
                    .unwrap(),
                0
            );
        }
        drop(store);
        ManualRemediationStore::open_read_only(&path).unwrap();
        if version > 0 {
            assert_eq!(
                Level0SnapshotStore::open(&path)
                    .unwrap()
                    .load(RUN)
                    .unwrap()
                    .payload,
                b"{\"safe\":true}"
            );
        }
    }
}
#[test]
fn membership_revision_and_whole_case_resolution_are_transactional() {
    let temp = Temp::new();
    let path = temp.0.join("state.sqlite3");
    let mut store = ManualRemediationStore::open(&path).unwrap();
    let case = seed(&mut store);
    let mut a = plan(&case, "finding-a");
    let mut b = plan(&case, "finding-b");
    store.save(&mut a).unwrap();
    store.save(&mut b).unwrap();
    let mut stale = a.clone();
    complete(&mut a, &mut store, ManualState::Resolved);
    assert!(store.save(&mut stale).is_err());
    assert_ne!(
        store.investigation.get_case(RUN, &case).unwrap().status,
        CaseStatus::Resolved
    );
    complete(&mut b, &mut store, ManualState::Resolved);
    assert_eq!(
        store.investigation.get_case(RUN, &case).unwrap().status,
        CaseStatus::Resolved
    );
    complete(&mut a, &mut store, ManualState::RegressionDetected);
    assert_ne!(
        store.investigation.get_case(RUN, &case).unwrap().status,
        CaseStatus::Resolved
    );
    let mut orphan = plan(&case, "finding-not-in-case");
    assert!(store.save(&mut orphan).is_err());
    assert_eq!(store.list(None, 0, 100).unwrap().len(), 2);
    let c = store.investigation.get_case(RUN, &case).unwrap();
    for event in &a.timeline {
        assert!(c.timeline.iter().any(|e| e.event_type == event.event_type));
    }
    assert!(
        c.timeline
            .iter()
            .any(|e| e.event_type == "finding_reopened")
    );
    assert_eq!(
        store
            .investigation
            .connection
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, u32>(
                0
            ))
            .unwrap(),
        0
    );
}
#[test]
fn seven_restart_states_rehydrate_and_pending_authority_is_consumed_once() {
    for state in [
        ManualState::Planned,
        ManualState::AwaitingManualChange,
        ManualState::VerificationPending,
        ManualState::Cancelled,
        ManualState::Inconclusive,
        ManualState::Resolved,
        ManualState::RegressionDetected,
    ] {
        let temp = Temp::new();
        let path = temp.0.join("state.sqlite3");
        let mut store = ManualRemediationStore::open(&path).unwrap();
        let case = seed(&mut store);
        let mut s = plan(&case, "finding-a");
        store.save(&mut s).unwrap();
        match state {
            ManualState::Planned => {}
            ManualState::AwaitingManualChange => {
                s.review().unwrap();
                store.save(&mut s).unwrap();
            }
            ManualState::VerificationPending => {
                s.review().unwrap();
                s.authorize_verification(100).unwrap();
                store.save(&mut s).unwrap();
            }
            v => complete(&mut s, &mut store, v),
        }
        let id = s.plan.actions[0].action_id.clone();
        drop(store);
        let mut store = ManualRemediationStore::open(&path).unwrap();
        store.recover_verifications().unwrap();
        let after = store.get(&id).unwrap();
        let expected = if state == ManualState::VerificationPending {
            ManualState::Interrupted
        } else {
            state
        };
        assert_eq!(after.state, expected);
        let count = after.timeline.len();
        assert_eq!(store.recover_verifications().unwrap(), 0);
        assert_eq!(store.get(&id).unwrap().timeline.len(), count);
    }
}
#[test]
fn sentinel_redaction_covers_metadata_results_timeline_and_sqlite() {
    let temp = Temp::new();
    let path = temp.0.join("state.sqlite3");
    let mut store = ManualRemediationStore::open(&path).unwrap();
    let case = seed(&mut store);
    let mut s = plan(&case, "finding-a");
    for marker in [
        "EDY_FAKE_SECRET_LEVEL6",
        "EDY_FAKE_COOKIE_LEVEL6",
        "EDY_FAKE_QUERY_LEVEL6",
        "EDY_FAKE_AUTH_TOKEN_LEVEL6",
        "EDY_FAKE_PASSWORD_LEVEL6",
    ] {
        s.guidance.push(safe_manual_text(marker, 2048));
        s.suggested_diff = Some(safe_manual_text(marker, 4096));
        let mut poisoned = s.clone();
        poisoned.limitations.push(marker.into());
        assert!(store.save(&mut poisoned).is_err());
    }
    store.save(&mut s).unwrap();
    complete(&mut s, &mut store, ManualState::Resolved);
    let encoded = serde_json::to_string(&store.get(&s.plan.actions[0].action_id).unwrap()).unwrap();
    assert!(!encoded.contains("EDY_FAKE_"));
    drop(store);
    assert!(
        !fs::read(&path)
            .unwrap()
            .windows(9)
            .any(|s| s == b"EDY_FAKE_")
    );
}
