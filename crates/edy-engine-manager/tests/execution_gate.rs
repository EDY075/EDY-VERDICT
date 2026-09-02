#![cfg(windows)]

use edy_engine_manager::execution::*;
use edy_engine_manager::manifest::{
    AuxiliaryHash, EngineManifest, EngineTrustPolicy, ProvenanceType,
};
use edy_engine_manager::receipt::{EngineReceipt, NullableTimestamp, ReceiptState};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

static NEXT: AtomicU64 = AtomicU64::new(1);

fn ordinary_canonical(path: &Path) -> PathBuf {
    let canonical = path.canonicalize().unwrap();
    let text = canonical.to_string_lossy();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text))
}

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(label: &str) -> Self {
        let project = ordinary_canonical(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
        let root = project.join("_intake/execution-gate-tests").join(format!(
            "{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn policy() -> EngineTrustPolicy {
    EngineTrustPolicy::new(vec![ProvenanceType::PublishedChecksum], 1).unwrap()
}

struct Fixture {
    _sandbox: Sandbox,
    manifest: PathBuf,
    receipt: PathBuf,
    root: PathBuf,
    executable: PathBuf,
    auxiliary: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sandbox = Sandbox::new("engine");
        let root = sandbox.0.join("payload");
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("fixture.exe");
        fs::copy(env!("CARGO_BIN_EXE_benign-fixture"), &executable).unwrap();
        let bytes = fs::read(&executable).unwrap();
        let auxiliary = root.join("fixture-support.dll");
        let auxiliary_bytes = b"synthetic auxiliary payload";
        fs::write(&auxiliary, auxiliary_bytes).unwrap();

        let source_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/engines/yara-x/1.20.0/manifest.json");
        let mut manifest = EngineManifest::parse(&fs::read(source_manifest).unwrap()).unwrap();
        manifest.identity.id = "execution-fixture".into();
        manifest.identity.version = "1.0.0".into();
        manifest.artifact.entrypoint = "fixture.exe".into();
        manifest.artifact.entrypoint_size = bytes.len() as u64;
        manifest.artifact.executable_sha256 = sha(&bytes);
        manifest.artifact.auxiliary_hashes = vec![AuxiliaryHash {
            relative_path: "fixture-support.dll".into(),
            sha256: sha(auxiliary_bytes),
            size: auxiliary_bytes.len() as u64,
        }];
        let receipt = EngineReceipt {
            schema_version: 2,
            engine_id: manifest.identity.id.clone(),
            version: manifest.identity.version.clone(),
            manifest_sha256: manifest.canonical_sha256().unwrap(),
            entrypoint_sha256: manifest.artifact.executable_sha256.clone(),
            artifact_set_sha256: manifest.declared_artifact_set_sha256().unwrap(),
            promoted_at: NullableTimestamp(Some("2026-09-02T00:00:00Z".into())),
            state: ReceiptState::Ready,
        };
        let manifest_path = sandbox.0.join("manifest.json");
        let receipt_path = sandbox.0.join("receipt.json");
        fs::write(&manifest_path, manifest.canonical_bytes().unwrap()).unwrap();
        fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        Self {
            _sandbox: sandbox,
            manifest: manifest_path,
            receipt: receipt_path,
            root,
            executable,
            auxiliary,
        }
    }

    fn request<'a>(&'a self, trust_policy: &'a EngineTrustPolicy) -> ExecutionGateRequest<'a> {
        ExecutionGateRequest {
            manifest_path: &self.manifest,
            receipt_path: &self.receipt,
            engine_root: &self.root,
            trust_policy,
        }
    }
}

#[test]
fn valid_engine_binds_manifest_receipt_and_closed_artifact_set() {
    let fixture = Fixture::new();
    let policy = policy();
    let verified = verify_engine(&fixture.request(&policy)).unwrap();
    assert_eq!(verified.manifest.identity.id, "execution-fixture");
    assert_eq!(
        verified.executable,
        fixture.executable.canonicalize().unwrap()
    );
    assert_eq!(verified.root, fixture.root.canonicalize().unwrap());
    assert_eq!(verified.artifacts.len(), 2);
}

#[test]
fn auxiliary_tamper_after_gate_is_denied_immediately_before_spawn() {
    let fixture = Fixture::new();
    let verified = verify_engine(&fixture.request(&policy())).unwrap();
    let request = verified.process_request(vec!["success".into()], Vec::new());

    fs::write(&fixture.auxiliary, b"post-gate replacement attempt").unwrap();
    let result = edy_engine_manager::process::execute(&request, &AtomicBool::new(false));
    assert!(result.is_err());
}

#[test]
fn omitting_auxiliary_from_process_request_breaks_receipt_bound_artifact_set() {
    let fixture = Fixture::new();
    let verified = verify_engine(&fixture.request(&policy())).unwrap();
    let mut request = verified.process_request(vec!["success".into()], Vec::new());
    request.artifacts.retain(|artifact| {
        artifact.path.extension().and_then(|value| value.to_str()) == Some("exe")
    });
    let result = edy_engine_manager::process::execute(&request, &AtomicBool::new(false));
    assert!(result.is_err());
}

#[test]
fn artifact_handles_deny_replacement_until_process_tree_is_reaped() {
    let fixture = Fixture::new();
    let verified = verify_engine(&fixture.request(&policy())).unwrap();
    let mut request = verified.process_request(vec!["sleep".into()], Vec::new());
    request.timeout = Duration::from_millis(500);
    let cancel = AtomicBool::new(false);

    std::thread::scope(|scope| {
        let execution = scope.spawn(|| edy_engine_manager::process::execute(&request, &cancel));
        let locked = (0..40).any(|_| {
            let denied = fs::OpenOptions::new()
                .write(true)
                .open(&fixture.auxiliary)
                .is_err();
            if !denied {
                std::thread::sleep(Duration::from_millis(10));
            }
            denied
        });
        assert!(locked, "auxiliary was never protected by a held handle");
        assert!(fs::write(&fixture.auxiliary, b"replacement while running").is_err());
        let result = execution.join().unwrap().unwrap();
        assert_eq!(
            result.outcome,
            edy_engine_manager::process::Outcome::TimedOut
        );
    });

    fs::write(&fixture.auxiliary, b"handle released after cleanup").unwrap();
}

#[test]
fn approved_catalog_payloads_pass_full_filesystem_integrity_gate() {
    let project = ordinary_canonical(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let policy = policy();
    for (engine, version) in [
        ("yara-x", "1.20.0"),
        ("gitleaks", "8.30.0"),
        ("trivy", "0.74.0"),
        ("osv-scanner", "2.5.1"),
    ] {
        let base = project.join("tools/engines").join(engine).join(version);
        let receipt = project
            .join("tools/receipts/engines")
            .join(engine)
            .join(format!("{version}.json"));
        let verified = verify_engine(&ExecutionGateRequest {
            manifest_path: &base.join("manifest.json"),
            receipt_path: &receipt,
            engine_root: &base.join("payload"),
            trust_policy: &policy,
        })
        .unwrap_or_else(|error| panic!("{engine} {version}: {error}"));
        assert_eq!(verified.manifest.identity.id, engine);
        assert_eq!(verified.manifest.identity.version, version);
    }
}

#[test]
fn missing_wrong_type_hash_and_extra_closed_set_file_fail_closed() {
    let policy = policy();

    let fixture = Fixture::new();
    fs::remove_file(&fixture.executable).unwrap();
    assert_eq!(
        verify_engine(&fixture.request(&policy)),
        Err(ExecutionGateError::Missing)
    );

    let fixture = Fixture::new();
    fs::remove_file(&fixture.executable).unwrap();
    fs::create_dir(&fixture.executable).unwrap();
    assert_eq!(
        verify_engine(&fixture.request(&policy)),
        Err(ExecutionGateError::WrongType)
    );

    let fixture = Fixture::new();
    fs::write(&fixture.executable, b"tampered").unwrap();
    assert!(matches!(
        verify_engine(&fixture.request(&policy)),
        Err(ExecutionGateError::HashMismatch | ExecutionGateError::SizeMismatch)
    ));

    let fixture = Fixture::new();
    fs::write(fixture.root.join("extra.txt"), b"not declared").unwrap();
    assert_eq!(
        verify_engine(&fixture.request(&policy)),
        Err(ExecutionGateError::UnexpectedFile)
    );
}

#[test]
fn receipt_mismatch_is_tamper_denial() {
    let fixture = Fixture::new();
    let mut receipt: EngineReceipt =
        serde_json::from_slice(&fs::read(&fixture.receipt).unwrap()).unwrap();
    receipt.manifest_sha256 = "0".repeat(64);
    fs::write(&fixture.receipt, serde_json::to_vec(&receipt).unwrap()).unwrap();
    assert_eq!(
        verify_engine(&fixture.request(&policy())),
        Err(ExecutionGateError::ReceiptMismatch)
    );
}

#[test]
fn unc_ads_relative_and_traversal_paths_are_rejected_before_io() {
    let fixture = Fixture::new();
    let policy = policy();
    for unsafe_root in [
        Path::new(r"\\server\share\engine"),
        Path::new(r"D:\engine:stream"),
        Path::new(r"relative\engine"),
        Path::new(r"D:\engine\..\escape"),
    ] {
        let request = ExecutionGateRequest {
            engine_root: unsafe_root,
            ..fixture.request(&policy)
        };
        assert_eq!(
            verify_engine(&request),
            Err(ExecutionGateError::UnsafePath),
            "{}",
            unsafe_root.display()
        );
    }
}

#[test]
fn symlink_or_reparse_entrypoint_is_rejected() {
    let fixture = Fixture::new();
    let real_root = fixture.root.with_file_name("payload-real");
    fs::rename(&fixture.root, &real_root).unwrap();
    let command = format!(
        "mklink /J \"{}\" \"{}\"",
        fixture.root.display().to_string().replace('/', "\\"),
        real_root.display().to_string().replace('/', "\\")
    );
    let mut junction = std::process::Command::new("cmd.exe");
    junction.args(["/d", "/c"]);
    junction.raw_arg(command);
    let status = junction.status().unwrap();
    assert!(
        status.success(),
        "controlled junction fixture was not created"
    );
    assert_eq!(
        verify_engine(&fixture.request(&policy())),
        Err(ExecutionGateError::ReparsePoint)
    );
}

#[test]
fn immutable_rules_config_and_ignore_are_separate_hash_gates() {
    let sandbox = Sandbox::new("runtime-assets");
    let root = sandbox.0.join("approved-data");
    fs::create_dir_all(&root).unwrap();
    let rules = b"rule EDY_BENIGN_TEST_RULE { condition: true }";
    let config = b"title = 'EDY synthetic only'";
    let ignore = b"# intentionally empty\n";
    fs::write(root.join("rules.yar"), rules).unwrap();
    fs::write(root.join("config.toml"), config).unwrap();
    fs::write(root.join("empty.ignore"), ignore).unwrap();
    let declarations = [
        RuntimeAssetDeclaration {
            class: RuntimeAssetClass::Ruleset,
            root: &root,
            relative_path: "rules.yar",
            sha256: &sha(rules),
            size: rules.len() as u64,
        },
        RuntimeAssetDeclaration {
            class: RuntimeAssetClass::Config,
            root: &root,
            relative_path: "config.toml",
            sha256: &sha(config),
            size: config.len() as u64,
        },
        RuntimeAssetDeclaration {
            class: RuntimeAssetClass::IgnorePolicy,
            root: &root,
            relative_path: "empty.ignore",
            sha256: &sha(ignore),
            size: ignore.len() as u64,
        },
    ];
    assert_eq!(
        verify_runtime_assets(&sandbox.0, &declarations)
            .unwrap()
            .len(),
        3
    );
    fs::write(root.join("rules.yar"), b"modified rule").unwrap();
    assert!(matches!(
        verify_runtime_assets(&sandbox.0, &declarations),
        Err(ExecutionGateError::HashMismatch | ExecutionGateError::SizeMismatch)
    ));
    fs::write(root.join("rules.yar"), rules).unwrap();
    fs::write(root.join("config.toml"), b"modified config").unwrap();
    assert!(matches!(
        verify_runtime_assets(&sandbox.0, &declarations),
        Err(ExecutionGateError::HashMismatch | ExecutionGateError::SizeMismatch)
    ));
}

#[test]
fn committed_synthetic_rules_and_config_are_hash_pinned() {
    let project = ordinary_canonical(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let root = project.join("crates/edy-engine-manager/tests/fixtures/execution");
    let declarations = [
        RuntimeAssetDeclaration {
            class: RuntimeAssetClass::Ruleset,
            root: &root,
            relative_path: "yara/EDY_BENIGN_TEST_RULE.yar",
            sha256: "7bf9eba5960cb441e977630149dee5355ab31eb8b74546ef3f1e195095d996fc",
            size: 214,
        },
        RuntimeAssetDeclaration {
            class: RuntimeAssetClass::Config,
            root: &root,
            relative_path: "gitleaks/config.toml",
            sha256: "a88d4e348643f41925daa0dd11f870fcdaf7bec2f81241966935927568ef1e69",
            size: 296,
        },
        RuntimeAssetDeclaration {
            class: RuntimeAssetClass::IgnorePolicy,
            root: &root,
            relative_path: "gitleaks/empty.ignore",
            sha256: "c70487d750b7f249ae37edfdca0ae8c657cfe8d87dd40a0fb3e3eab54c86b4e6",
            size: 47,
        },
    ];
    assert_eq!(
        verify_runtime_assets(&project, &declarations)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn trivy_osv_data_contract_distinguishes_missing_stale_and_tampered() {
    let sandbox = Sandbox::new("offline-data");
    let data_root = sandbox.0.join("cache/trivy/db");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let bytes = b"synthetic offline database fixture";
    let declaration = [DataFileDeclaration {
        relative_path: "metadata.json",
        sha256: &sha(bytes),
        size: bytes.len() as u64,
    }];
    let contract = DataTrustContract {
        project_root: &sandbox.0,
        data_root: &data_root,
        expected_version: "fixture-v1",
        observed_version: "fixture-v1",
        provenance: "synthetic-test-provenance",
        provenance_verified: true,
        acquired_at: now - Duration::from_secs(60),
        maximum_age: Duration::from_secs(3600),
        files: &declaration,
    };
    assert_eq!(
        verify_data_trust(&contract, now),
        Err(DataUnavailableReason::Missing)
    );
    fs::create_dir_all(&data_root).unwrap();
    fs::write(data_root.join("metadata.json"), bytes).unwrap();
    assert_eq!(
        verify_data_trust(&contract, now).unwrap().freshness,
        DataFreshness::Fresh
    );

    let stale = DataTrustContract {
        acquired_at: now - Duration::from_secs(7200),
        ..contract
    };
    assert_eq!(
        verify_data_trust(&stale, now),
        Err(DataUnavailableReason::Stale)
    );
    fs::write(data_root.join("metadata.json"), b"tampered").unwrap();
    assert_eq!(
        verify_data_trust(&contract, now),
        Err(DataUnavailableReason::Tampered)
    );
}

#[test]
fn process_request_is_root_confined_and_environment_explicit() {
    let fixture = Fixture::new();
    let verified = verify_engine(&fixture.request(&policy())).unwrap();
    let request = verified.process_request(
        vec!["echo".into()],
        vec![("TEMP".into(), fixture.root.to_string_lossy().into_owned())],
    );
    assert_eq!(request.approved_root, verified.root);
    assert_eq!(request.working_directory, verified.root);
    assert_eq!(request.environment.len(), 1);
}
