//! Links the normal library (not cfg(test)). Run in the real release profile.
use edy_remediation::*;
use std::fs;

#[test]
fn l6_s01_production_regression_concurrent_user_changes_are_never_overwritten() {
    let root =
        std::env::temp_dir().join(format!("edy-l6-production-policy-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    let path = root.join("config.txt");
    fs::write(&path, "original").unwrap();
    for strategy in ["concurrent content update", "concurrent path replacement"] {
        // External test harness supplies the user change. The production library
        // can construct guidance, but cannot expose any apply/rollback executor.
        if strategy == "concurrent path replacement" {
            fs::rename(&path, root.join("user-original.txt")).unwrap();
        }
        fs::write(&path, strategy).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(!std::hint::black_box(PRODUCTION_MUTATING_REMEDIATION));
        let z = "0".repeat(64);
        let case = Some(format!("case-v1-{}", "a".repeat(64)));
        let action = RemediationAction {
            action_id: String::new(),
            finding_id: "synthetic-finding".into(),
            case_id: case.clone(),
            target_id: "synthetic-target".into(),
            kind: RemediationActionKind::RepositoryInventoryReview,
            safety_class: RemediationSafetyClass::ManualChangeVerifiable,
            rule_id: "MANUAL_REVIEW".into(),
            rule_version: 1,
            explanation_safe: "Manual change required".into(),
            precondition: RemediationPrecondition {
                canonical_path: path.to_string_lossy().into(),
                stable_identity: "fixture".into(),
                expected_sha256: z.clone(),
                expected_size: 0,
                expected_anchor_sha256: z.clone(),
            },
            edit: None,
            verification: VerificationPlan {
                scanner_id: "original-scanner".into(),
                original_fingerprint: "original-finding".into(),
                required_checks: vec!["original check".into()],
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
        let mut s = ManualSnapshot::create(
            RemediationPlan {
                plan_id: uuid::Uuid::now_v7().to_string(),
                plan_sha256: String::new(),
                finding_id: "synthetic-finding".into(),
                case_id: case,
                created_at_utc: manual_now(),
                actions: vec![action],
            },
            uuid::Uuid::now_v7().to_string(),
            vec!["Manual action required".into()],
            None,
        )
        .unwrap();
        s.review().unwrap();
        // No production apply method exists: the compile_fail doc tests enforce
        // absence of both exports; action/plan validation rejects mutating kinds.
        let mut attempted_apply = s.clone();
        attempted_apply.plan.actions[0].kind = RemediationActionKind::ExactTextConfigPatch;
        attempted_apply.plan.actions[0].safety_class = RemediationSafetyClass::TestOnlyReversible;
        assert!(attempted_apply.validate().is_err());
        let mut attempted_rollback = s.clone();
        attempted_rollback.plan.actions[0].rollback.eligible = true;
        assert!(attempted_rollback.validate().is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!root.join("backup").exists());
    }
    fs::remove_dir_all(root).unwrap();
}
