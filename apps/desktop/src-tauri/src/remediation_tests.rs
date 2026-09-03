use super::*;
use std::fs;
fn setup() -> (PathBuf, RemediationBackend, RemediationCandidate) {
    let root =
        std::env::temp_dir().join(format!("edy-manual-verification-{}", uuid::Uuid::now_v7()));
    fs::create_dir_all(root.join("repo")).unwrap();
    fs::create_dir_all(root.join("synthetic-associated-repo")).unwrap();
    fs::write(
        root.join("synthetic-associated-repo/package.json"),
        "{\"name\":\"controlled-fixture\",\"version\":\"1.0.0\"}\n",
    )
    .unwrap();
    fs::write(
        root.join("repo/package.json"),
        "{\"name\":\"controlled-fixture\",\"version\":\"1.0.0\"}\n",
    )
    .unwrap();
    let backend =
        RemediationBackend::open_fixture(&root.join("db.sqlite3"), &root.join("repo")).unwrap();
    let c = backend
        .candidates()
        .unwrap()
        .into_iter()
        .find(|c| backend.fixture_origin(&c.finding_id).unwrap().is_some())
        .expect("Actual inventory finding must belong to a persisted case");
    (root, backend, c)
}
fn create(backend: &RemediationBackend, c: &RemediationCandidate) -> ManualSnapshot {
    backend
        .create_plan(
            CreateRemediationPlanRequest {
                run_id: c.run_id.clone(),
                case_id: c.case_id.clone(),
                finding_id: c.finding_id.clone(),
            },
            None,
        )
        .unwrap()
}
fn verify(backend: &RemediationBackend, s: &ManualSnapshot) -> ManualSnapshot {
    let a = backend
        .authorize(AuthorizeRemediationRequest {
            action_id: s.plan.actions[0].action_id.clone(),
            plan_sha256: s.plan.plan_sha256.clone(),
            confirmed: true,
        })
        .unwrap();
    backend
        .verify(VerifyRemediationRequest {
            action_id: s.plan.actions[0].action_id.clone(),
            authorization_token: a.authorization_token,
        })
        .unwrap()
}
#[test]
fn production_policy_manual_rescan_uses_original_inventory_and_persists_case() {
    let (root, backend, c) = setup();
    let s = create(&backend, &c);
    let id = s.plan.actions[0].action_id.clone();
    const {
        assert!(!PRODUCTION_MUTATING_REMEDIATION);
    }
    let s = backend
        .preview(RemediationActionRequest {
            action_id: id.clone(),
        })
        .unwrap();
    assert_eq!(verify(&backend, &s).state, ManualState::StillPresent);
    // External harness, not IPC/executor: simulate a manual package-manager result.
    fs::write(
        root.join("repo/package-lock.json"),
        "{\"lockfileVersion\":3}\n",
    )
    .unwrap();
    let s = backend
        .get(RemediationActionRequest {
            action_id: id.clone(),
        })
        .unwrap();
    let resolved = verify(&backend, &s);
    assert_eq!(resolved.state, ManualState::Resolved);
    let case = backend
        .lock()
        .unwrap()
        .investigation
        .get_case(&c.run_id, &c.case_id)
        .unwrap();
    assert!(
        case.timeline
            .iter()
            .any(|e| e.event_type == "VERIFICATION_RESOLVED")
    );
    if case.finding_ids.len() > 1 {
        assert_ne!(case.status, edy_core::CaseStatus::Resolved);
    }
    drop(backend);
    let reopened = RemediationBackend::open(&root.join("db.sqlite3")).unwrap();
    assert_eq!(
        reopened
            .get(RemediationActionRequest { action_id: id })
            .unwrap(),
        resolved
    );
    assert_eq!(
        fs::read_to_string(root.join("repo/package-lock.json")).unwrap(),
        "{\"lockfileVersion\":3}\n"
    );
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn restart_consumes_pending_authority_and_cannot_false_resolve() {
    let (root, backend, c) = setup();
    let s = create(&backend, &c);
    let id = s.plan.actions[0].action_id.clone();
    backend
        .preview(RemediationActionRequest {
            action_id: id.clone(),
        })
        .unwrap();
    let grant = backend
        .authorize(AuthorizeRemediationRequest {
            action_id: id.clone(),
            plan_sha256: s.plan.plan_sha256,
            confirmed: true,
        })
        .unwrap();
    drop(backend);
    let reopened = RemediationBackend::open(&root.join("db.sqlite3")).unwrap();
    let s = reopened
        .get(RemediationActionRequest {
            action_id: id.clone(),
        })
        .unwrap();
    assert_eq!(s.state, ManualState::Interrupted);
    assert!(
        reopened
            .verify(VerifyRemediationRequest {
                action_id: id,
                authorization_token: grant.authorization_token
            })
            .is_err()
    );
    let count = s.timeline.len();
    drop(reopened);
    let reopened = RemediationBackend::open(&root.join("db.sqlite3")).unwrap();
    assert_eq!(
        reopened
            .get(RemediationActionRequest {
                action_id: s.plan.actions[0].action_id.clone()
            })
            .unwrap()
            .timeline
            .len(),
        count
    );
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn malformed_lockfile_after_manual_change_is_regression() {
    let (root, backend, c) = setup();
    let s = create(&backend, &c);
    let s = backend
        .preview(RemediationActionRequest {
            action_id: s.plan.actions[0].action_id.clone(),
        })
        .unwrap();
    fs::write(root.join("repo/package-lock.json"), "").unwrap();
    assert_eq!(verify(&backend, &s).state, ManualState::RegressionDetected);
    drop(backend);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn removal_of_manifest_never_counts_as_resolved() {
    let (root, backend, c) = setup();
    let s = create(&backend, &c);
    let s = backend
        .preview(RemediationActionRequest {
            action_id: s.plan.actions[0].action_id.clone(),
        })
        .unwrap();
    fs::rename(
        root.join("repo/package.json"),
        root.join("repo/package.manually-moved"),
    )
    .unwrap();
    assert_eq!(verify(&backend, &s).state, ManualState::Inconclusive);
    drop(backend);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_new_material_finding_in_another_ecosystem_is_regression() {
    let (root, backend, c) = setup();
    let s = create(&backend, &c);
    let s = backend
        .preview(RemediationActionRequest {
            action_id: s.plan.actions[0].action_id.clone(),
        })
        .unwrap();
    fs::write(
        root.join("repo/package-lock.json"),
        "{\"lockfileVersion\":3}",
    )
    .unwrap();
    fs::write(
        root.join("repo/Cargo.toml"),
        "[package]\nname=\"fixture\"\nversion=\"1.0.0\"\n",
    )
    .unwrap();
    assert_eq!(verify(&backend, &s).state, ManualState::RegressionDetected);
    drop(backend);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accepted_cancellation_persists_cancelled_and_can_resume() {
    let (root, backend, c) = setup();
    let backend = Arc::new(backend);
    let s = create(&backend, &c);
    let id = s.plan.actions[0].action_id.clone();
    backend
        .preview(RemediationActionRequest {
            action_id: id.clone(),
        })
        .unwrap();
    let grant = backend
        .authorize(AuthorizeRemediationRequest {
            action_id: id.clone(),
            plan_sha256: s.plan.plan_sha256.clone(),
            confirmed: true,
        })
        .unwrap();
    let worker_backend = backend.clone();
    let worker_id = id.clone();
    let worker = std::thread::spawn(move || {
        worker_backend.verify(VerifyRemediationRequest {
            action_id: worker_id,
            authorization_token: grant.authorization_token,
        })
    });
    let mut accepted = false;
    for _ in 0..100 {
        if backend
            .cancel(RemediationActionRequest {
                action_id: id.clone(),
            })
            .is_ok()
        {
            accepted = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(accepted);
    let cancelled = worker.join().unwrap().unwrap();
    assert_eq!(cancelled.state, ManualState::Cancelled);
    drop(backend);
    let reopened =
        RemediationBackend::open_fixture(&root.join("db.sqlite3"), &root.join("repo")).unwrap();
    assert_eq!(
        reopened
            .get(RemediationActionRequest { action_id: id })
            .unwrap()
            .state,
        ManualState::Cancelled
    );
    assert_eq!(
        verify(&reopened, &cancelled).state,
        ManualState::StillPresent
    );
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}
