use edy_core::{Target, TargetId, TargetKind, TargetLocator};
use edy_engine_manager::adapters::*;

fn output(exit_code: u32, stdout: &[u8]) -> CapturedOutput<'_> {
    CapturedOutput {
        outcome: CaptureOutcome::Exited(exit_code),
        stdout,
        stderr: &[],
    }
}

fn local_target(kind: TargetKind, path: &str) -> Target {
    Target::new(
        TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789ac").unwrap(),
        kind,
        TargetLocator::new_local_path(path).unwrap(),
    )
    .unwrap()
}

fn approved(path: &'static str) -> ApprovedLocalPath<'static> {
    ApprovedLocalPath::new(path).unwrap()
}

fn preparation(target: &Target) -> AdapterPreparation<'_> {
    AdapterPreparation {
        target,
        project_root: approved("D:/EDY-Projects/EDY-VERDICT"),
        yara_rules_path: None,
        gitleaks_config_path: None,
        gitleaks_ignore_path: None,
        trivy_cache_dir: None,
    }
}

const YARA: &[u8] = br#"{
  "version":"1.20.0",
  "matches":[
    {"rule":"Synthetic_Suspicious","file":"fixtures/benign.bin","strings":[{"match":"SANITIZED"}]},
    {"rule":"Synthetic_Suspicious","file":"fixtures/benign.bin"}
  ]
}"#;

const GITLEAKS: &[u8] = br#"[
  {"RuleID":"synthetic-token","Description":"Synthetic only","StartLine":7,"File":"src/config.txt","Fingerprint":"src/config.txt:synthetic-token:7","Secret":"FAKE_SECRET_DO_NOT_PERSIST","Match":"token=FAKE_SECRET_DO_NOT_PERSIST"},
  {"RuleID":"synthetic-token","Description":"Synthetic duplicate","StartLine":7,"File":"src/config.txt","Fingerprint":"src/config.txt:synthetic-token:7","Secret":"ANOTHER_FAKE"}
]"#;

const TRIVY: &[u8] = br#"{
  "SchemaVersion":2,
  "Results":[{"Target":"Cargo.lock","Vulnerabilities":[
    {"VulnerabilityID":"CVE-2099-0001","PkgName":"fixture-crate","InstalledVersion":"1.0.0","FixedVersion":"1.0.1","Severity":"HIGH"}
  ]}]
}"#;

const OSV: &[u8] = br#"{
  "results":[{"source":{"path":"fixtures/Cargo.lock","type":"lockfile"},"packages":[{
    "package":{"name":"fixture-crate","version":"1.0.0","ecosystem":"crates.io"},
    "vulnerabilities":[{"id":"RUSTSEC-2099-0001","database_specific":{"severity":"MODERATE"},"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]}]}]
  }]}]
}"#;

#[test]
fn pinned_fixture_parsers_normalize_and_classify() {
    let cases: [(&dyn EngineAdapter, u32, &[u8], &str); 4] = [
        (&YaraXAdapter, 0, YARA, "yara-x"),
        (&GitleaksAdapter, 1, GITLEAKS, "gitleaks"),
        (&TrivyAdapter, 0, TRIVY, "trivy"),
        (&OsvScannerAdapter, 1, OSV, "osv-scanner"),
    ];
    for (adapter, code, fixture, id) in cases {
        let report = adapter.parse(output(code, fixture)).unwrap();
        assert_eq!(report.engine_id, id);
        assert_eq!(report.exit, AdapterExit::Findings);
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.observations[0].fingerprint.len(), 64);
    }
}

#[test]
fn clean_outputs_are_not_findings() {
    let cases: [(&dyn EngineAdapter, &[u8]); 4] = [
        (&YaraXAdapter, br#"{"version":"1.20.0","matches":[]}"#),
        (&GitleaksAdapter, br#"[]"#),
        (&TrivyAdapter, br#"{"SchemaVersion":2,"Results":[]}"#),
        (&OsvScannerAdapter, br#"{"results":[]}"#),
    ];
    for (adapter, fixture) in cases {
        let report = adapter.parse(output(0, fixture)).unwrap();
        assert_eq!(report.exit, AdapterExit::Clean);
        assert!(report.observations.is_empty());
    }
}

#[test]
fn gitleaks_secret_material_is_always_redacted() {
    let report = GitleaksAdapter.parse(output(1, GITLEAKS)).unwrap();
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(report.observations[0].redacted);
    assert!(!serialized.contains("FAKE_SECRET"));
    assert!(!serialized.contains("ANOTHER_FAKE"));
    assert!(!serialized.contains("token="));
    assert!(!serialized.contains("src/config.txt:synthetic-token:7"));
}

#[test]
fn duplicate_observations_are_stably_collapsed() {
    let report = YaraXAdapter.parse(output(0, YARA)).unwrap();
    assert_eq!(report.observations.len(), 1);
    let report = GitleaksAdapter.parse(output(1, GITLEAKS)).unwrap();
    assert_eq!(report.observations.len(), 1);
}

#[test]
fn dependency_versions_are_part_of_the_stable_identity() {
    let fixture = br#"{
      "SchemaVersion":2,
      "Results":[{"Target":"Cargo.lock","Vulnerabilities":[
        {"VulnerabilityID":"CVE-2099-0001","PkgName":"fixture-crate","InstalledVersion":"1.0.0","Severity":"HIGH"},
        {"VulnerabilityID":"CVE-2099-0001","PkgName":"fixture-crate","InstalledVersion":"1.1.0","Severity":"HIGH"}
      ]}]
    }"#;
    let report = TrivyAdapter.parse(output(0, fixture)).unwrap();
    assert_eq!(report.observations.len(), 2);
    assert_ne!(
        report.observations[0].fingerprint,
        report.observations[1].fingerprint
    );
}

#[test]
fn empty_invalid_utf8_and_schema_drift_fail_closed() {
    assert_eq!(
        TrivyAdapter.parse(output(0, b"")),
        Err(AdapterError::EmptyOutput)
    );
    assert_eq!(
        YaraXAdapter.parse(output(0, &[0xff, 0xfe])),
        Err(AdapterError::InvalidOutput)
    );
    assert_eq!(
        TrivyAdapter.parse(output(0, br#"{"SchemaVersion":3,"Results":[]}"#)),
        Err(AdapterError::UnsupportedSchema)
    );
    assert_eq!(
        OsvScannerAdapter.parse(output(0, br#"{"results":{}}"#)),
        Err(AdapterError::InvalidOutput)
    );
    assert_eq!(
        YaraXAdapter.parse(output(
            0,
            b"{\"version\":\"1.20.0\",\"matches\":[{\"rule\":\"bad\\tfield\",\"file\":\"fixture.bin\"}]}"
        )),
        Err(AdapterError::InvalidOutput)
    );
}

#[test]
fn truncated_timeout_cancel_and_process_errors_fail_closed() {
    for outcome in [
        CaptureOutcome::OutputLimit,
        CaptureOutcome::TimedOut,
        CaptureOutcome::Cancelled,
    ] {
        assert!(
            TrivyAdapter
                .parse(CapturedOutput {
                    outcome,
                    stdout: TRIVY,
                    stderr: b"FAKE_SECRET_MUST_NOT_LEAK",
                })
                .is_err()
        );
    }
    let error = TrivyAdapter.parse(output(127, TRIVY)).unwrap_err();
    assert_eq!(error, AdapterError::ProcessFailed);
    assert!(!error.to_string().contains("FAKE_SECRET"));
}

#[test]
fn finding_exit_codes_must_agree_with_output() {
    assert_eq!(
        GitleaksAdapter.parse(output(0, GITLEAKS)),
        Err(AdapterError::ExitMismatch)
    );
    assert_eq!(
        OsvScannerAdapter.parse(output(1, br#"{"results":[]}"#)),
        Err(AdapterError::ExitMismatch)
    );
}

#[test]
fn absolute_locations_are_display_redacted() {
    let fixture = br#"[{"RuleID":"synthetic-token","StartLine":9,"File":"C:\\Users\\person\\secret.txt","Fingerprint":"secret.txt:synthetic-token:9","Secret":"FAKE"}]"#;
    let report = GitleaksAdapter.parse(output(1, fixture)).unwrap();
    assert_eq!(
        report.observations[0].location_reference,
        "<target>/secret.txt:9"
    );
    assert!(!serde_json::to_string(&report).unwrap().contains("person"));
}

#[test]
fn adapters_declare_their_supported_targets() {
    assert_eq!(
        YaraXAdapter.supported_targets(),
        &[TargetKind::Repository, TargetKind::File, TargetKind::Binary]
    );
    for adapter in [
        &GitleaksAdapter as &dyn EngineAdapter,
        &TrivyAdapter,
        &OsvScannerAdapter,
    ] {
        assert_eq!(
            adapter.supported_targets(),
            &[TargetKind::Repository, TargetKind::File]
        );
    }
}

#[test]
fn preparation_is_pure_offline_and_redacted_by_default() {
    let repository = local_target(TargetKind::Repository, "D:/fixture/repository");
    let mut yara_preparation = preparation(&repository);
    yara_preparation.yara_rules_path = Some(approved(
        "D:/EDY-Projects/EDY-VERDICT/.local/engine-config/yara/rules",
    ));
    let yara = YaraXAdapter.prepare_arguments(&yara_preparation).unwrap();
    assert_eq!(
        yara,
        [
            "scan",
            "--output-format=json",
            "--no-mmap",
            "--recursive",
            "D:/EDY-Projects/EDY-VERDICT/.local/engine-config/yara/rules",
            "D:/fixture/repository"
        ]
    );

    let mut gitleaks_preparation = preparation(&repository);
    gitleaks_preparation.gitleaks_config_path = Some(approved(
        "D:/EDY-Projects/EDY-VERDICT/.local/engine-config/gitleaks/config.toml",
    ));
    gitleaks_preparation.gitleaks_ignore_path = Some(approved(
        "D:/EDY-Projects/EDY-VERDICT/.local/engine-config/gitleaks/empty.ignore",
    ));
    assert_eq!(
        GitleaksAdapter
            .prepare_arguments(&gitleaks_preparation)
            .unwrap(),
        [
            "dir",
            "--no-banner",
            "--no-color",
            "--redact=100",
            "--config=D:/EDY-Projects/EDY-VERDICT/.local/engine-config/gitleaks/config.toml",
            "--gitleaks-ignore-path=D:/EDY-Projects/EDY-VERDICT/.local/engine-config/gitleaks/empty.ignore",
            "--ignore-gitleaks-allow",
            "--report-format=json",
            "--report-path=-",
            "--exit-code=1",
            "D:/fixture/repository",
        ]
    );

    let mut trivy_preparation = preparation(&repository);
    trivy_preparation.trivy_cache_dir = Some(approved(
        "D:/EDY-Projects/EDY-VERDICT/.local/engine-cache/trivy",
    ));
    assert_eq!(
        TrivyAdapter.prepare_arguments(&trivy_preparation).unwrap(),
        [
            "filesystem",
            "--format=json",
            "--offline-scan",
            "--skip-db-update",
            "--scanners=vuln",
            "--cache-dir=D:/EDY-Projects/EDY-VERDICT/.local/engine-cache/trivy",
            "D:/fixture/repository",
        ]
    );

    assert_eq!(
        OsvScannerAdapter
            .prepare_arguments(&preparation(&repository))
            .unwrap(),
        [
            "scan",
            "source",
            "--format=json",
            "--offline",
            "--offline-vulnerabilities",
            "--recursive",
            "D:/fixture/repository",
        ]
    );

    let lockfile = local_target(TargetKind::File, "D:/fixture/Cargo.lock");
    assert_eq!(
        OsvScannerAdapter
            .prepare_arguments(&preparation(&lockfile))
            .unwrap(),
        [
            "scan",
            "source",
            "--format=json",
            "--offline",
            "--offline-vulnerabilities",
            "--lockfile",
            "D:/fixture/Cargo.lock",
        ]
    );
}

#[test]
fn argument_preparation_fails_closed() {
    let application = Target::new(
        TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789ad").unwrap(),
        TargetKind::InstalledApplication,
        TargetLocator::new_application_id("fixture.app").unwrap(),
    )
    .unwrap();
    assert_eq!(
        GitleaksAdapter.prepare_arguments(&preparation(&application)),
        Err(AdapterError::UnsupportedTarget)
    );
    assert_eq!(
        YaraXAdapter.prepare_arguments(&preparation(&local_target(
            TargetKind::Binary,
            "D:/fixture/sample.bin",
        ))),
        Err(AdapterError::MissingRules)
    );
    let repository = local_target(TargetKind::Repository, "D:/fixture/repository");
    assert_eq!(
        GitleaksAdapter.prepare_arguments(&preparation(&repository)),
        Err(AdapterError::MissingGitleaksConfig)
    );
    let mut only_config = preparation(&repository);
    only_config.gitleaks_config_path = Some(approved(
        "D:/EDY-Projects/EDY-VERDICT/.local/engine-config/gitleaks/config.toml",
    ));
    assert_eq!(
        GitleaksAdapter.prepare_arguments(&only_config),
        Err(AdapterError::MissingGitleaksIgnorePolicy)
    );
    assert_eq!(
        TrivyAdapter.prepare_arguments(&preparation(&repository)),
        Err(AdapterError::MissingTrivyCache)
    );
    let mut unexpected = preparation(&repository);
    unexpected.yara_rules_path = Some(approved(
        "D:/EDY-Projects/EDY-VERDICT/.local/engine-config/yara/rules",
    ));
    assert_eq!(
        TrivyAdapter.prepare_arguments(&unexpected),
        Err(AdapterError::InvalidArgument)
    );
}

#[test]
fn engine_paths_are_absolute_local_and_project_confined() {
    for invalid in [
        "relative/path",
        "//server/share/file",
        r"\\server\share\file",
        r"\\?\D:\device\file",
        "D:drive-relative",
        "D:/path/../file",
        "D:/path/file:stream",
        "D:/path/NUL.txt",
        "D:/path/file*",
    ] {
        assert_eq!(
            ApprovedLocalPath::new(invalid),
            Err(AdapterError::InvalidArgument),
            "{invalid}"
        );
    }
    assert!(ApprovedLocalPath::new("D:/approved/path").is_ok());

    let repository = local_target(TargetKind::Repository, "D:/fixture/repository");
    let mut outside_project = preparation(&repository);
    outside_project.trivy_cache_dir = Some(approved("D:/EDY-Projects/other/cache"));
    assert_eq!(
        TrivyAdapter.prepare_arguments(&outside_project),
        Err(AdapterError::InvalidArgument)
    );

    let remote = local_target(TargetKind::File, "//server/share/Cargo.lock");
    assert_eq!(
        OsvScannerAdapter.prepare_arguments(&preparation(&remote)),
        Err(AdapterError::InvalidArgument)
    );
}
