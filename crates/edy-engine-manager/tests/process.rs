#![cfg(windows)]
use edy_engine_manager::process::*;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::atomic::AtomicBool, time::Duration};
#[test]
fn working_directory_must_resolve_to_directory() {
    let mut request = request("success");
    request.working_directory = request.executable.clone();
    assert!(execute(&request, &AtomicBool::new(false)).is_err());
}
#[test]
fn pre_cancelled_request_never_opens_or_launches_image() {
    let mut request = request("success");
    request.executable = request.executable.with_file_name("does-not-exist.exe");
    let result = execute(&request, &AtomicBool::new(true)).unwrap();
    assert_eq!(result.outcome, Outcome::Cancelled);
    assert_eq!(result.process_id, 0);
    assert!(result.stdout.is_empty());
}
#[test]
fn expired_deadline_never_launches() {
    let mut request = request("success");
    request.timeout = Duration::from_nanos(1);
    let result = execute(&request, &AtomicBool::new(false)).unwrap();
    assert_eq!(result.outcome, Outcome::TimedOut);
    assert_eq!(result.process_id, 0);
}
fn request(mode: &str) -> ProcessRequest {
    let path = PathBuf::from(env!("CARGO_BIN_EXE_benign-fixture"));
    ProcessRequest {
        approved_root: path.parent().unwrap().to_path_buf(),
        sha256: format!("{:x}", Sha256::digest(std::fs::read(&path).unwrap())),
        executable: path,
        arguments: vec![mode.into()],
        environment: Vec::new(),
        working_directory: PathBuf::from(env!("CARGO_BIN_EXE_benign-fixture"))
            .parent()
            .unwrap()
            .to_path_buf(),
        timeout: Duration::from_secs(3),
        stdout_limit: 4096,
        stderr_limit: 4096,
    }
}
#[test]
fn success_stderr_nonzero() {
    for (mode, outcome) in [
        ("success", Outcome::Exited(0)),
        ("stderr", Outcome::Exited(0)),
        ("nonzero", Outcome::Exited(23)),
    ] {
        let result = execute(&request(mode), &AtomicBool::new(false)).unwrap();
        assert_eq!(result.outcome, outcome);
        assert!(result.job_empty);
        if mode == "success" {
            assert!(
                String::from_utf8(result.stdout)
                    .unwrap()
                    .contains("fixture-ok")
            );
        }
        if mode == "stderr" {
            assert!(!result.stderr.is_empty());
        }
    }
}
#[test]
fn timeout_and_tree_are_killed() {
    for mode in ["sleep", "tree"] {
        let mut request = request(mode);
        request.timeout = Duration::from_millis(300);
        let result = execute(&request, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.outcome, Outcome::TimedOut);
        assert!(result.job_empty);
        if mode == "tree" {
            assert!(String::from_utf8(result.stdout).unwrap().contains("child:"));
        }
    }
}
#[test]
fn excessive_output_is_bounded() {
    for mode in ["stdout", "stderr-overflow"] {
        let result = execute(&request(mode), &AtomicBool::new(false)).unwrap();
        assert_eq!(result.outcome, Outcome::OutputLimit);
        assert!(result.stdout.len() <= 4096);
        assert!(result.stderr.len() <= 4096);
        assert!(result.job_empty);
    }
}
#[test]
fn cancellation_reaps_job() {
    let cancel = AtomicBool::new(false);
    std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(Duration::from_millis(100));
            cancel.store(true, std::sync::atomic::Ordering::Release);
        });
        let result = execute(&request("tree"), &cancel).unwrap();
        assert_eq!(result.outcome, Outcome::Cancelled);
        assert!(result.job_empty);
    });
}
#[test]
fn bad_hash_is_not_executed() {
    let mut request = request("success");
    request.sha256 = "0".repeat(64);
    assert!(execute(&request, &AtomicBool::new(false)).is_err());
}
#[test]
fn arguments_are_not_shell_interpreted() {
    let mut request = request("echo");
    let values = vec![
        "with space".to_string(),
        "quotes\"and\\".into(),
        "& echo should-not-run".into(),
        "%PATH%".into(),
        "á漢字".into(),
        String::new(),
    ];
    request.arguments.extend(values.clone());
    let result = execute(&request, &AtomicBool::new(false)).unwrap();
    assert_eq!(result.outcome, Outcome::Exited(0));
    let actual: Vec<String> = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(actual, values);
}

#[test]
fn executable_and_working_directory_must_stay_in_approved_root() {
    let mut outside_root = request("success");
    outside_root.approved_root = std::env::temp_dir();
    assert!(execute(&outside_root, &AtomicBool::new(false)).is_err());

    let mut outside_cwd = request("success");
    outside_cwd.working_directory = std::env::temp_dir();
    assert!(execute(&outside_cwd, &AtomicBool::new(false)).is_err());
}

#[test]
fn environment_is_allowlisted_and_does_not_accept_secrets() {
    let mut secret_environment = request("success");
    secret_environment.environment =
        vec![("EDY_FAKE_TEST_TOKEN".into(), "impossible-fixture".into())];
    assert!(execute(&secret_environment, &AtomicBool::new(false)).is_err());

    let mut allowed_environment = request("success");
    allowed_environment.environment = vec![(
        "TEMP".into(),
        allowed_environment.approved_root.display().to_string(),
    )];
    assert_eq!(
        execute(&allowed_environment, &AtomicBool::new(false))
            .unwrap()
            .outcome,
        Outcome::Exited(0)
    );
}
