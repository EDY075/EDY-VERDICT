#![forbid(unsafe_code)]
//! Safe, read-only Level 0 command surface.

use edy_core::{GraphLimits, correlate_investigation};
use edy_engine_manager::manifest::EngineManifest;
use edy_engine_manager::receipt::{EngineReceipt, IntegrityObservation, ObservedArtifact};
use edy_storage::level0_snapshot::Level5SnapshotStore;
use edy_storage::manual_remediation::ManualRemediationStore;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

const ENGINES: [(&str, &str); 4] = [
    ("yara-x", "1.20.0"),
    ("gitleaks", "8.30.0"),
    ("trivy", "0.74.0"),
    ("osv-scanner", "2.5.1"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    fn success(lines: impl IntoIterator<Item = String>) -> Self {
        Self {
            exit_code: 0,
            stdout: lines.into_iter().collect::<Vec<_>>().join("\n"),
            stderr: String::new(),
        }
    }

    fn error(exit_code: i32, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            stdout: String::new(),
            stderr: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntegrityStatus {
    Ready,
    Missing,
    Invalid,
}

impl IntegrityStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::Missing => "MISSING",
            Self::Invalid => "INVALID",
        }
    }
}

pub fn run(args: &[String], project_root: &Path) -> CommandResult {
    match args {
        [command] if command == "version" || command == "--version" || command == "-V" => {
            CommandResult::success([format!("edy-verdict {}", env!("CARGO_PKG_VERSION"))])
        }
        [command] if command == "help" || command == "--help" || command == "-h" => {
            CommandResult::success([usage(), exit_code_contract()])
        }
        [command] if command == "doctor" => doctor(project_root),
        [command] if command == "engines" => engine_list(project_root),
        [command, path] if command == "validate-manifest" => {
            validate_manifest(project_root, Path::new(path))
        }
        [command] if command == "correlate" => correlate(project_root, false),
        [command, json] if command == "correlate" && json == "--json" => {
            correlate(project_root, true)
        }
        [group, command, run_id] if group == "clusters" && command == "list" => {
            list_clusters(project_root, run_id, false)
        }
        [group, command, run_id, json]
            if group == "clusters" && command == "list" && json == "--json" =>
        {
            list_clusters(project_root, run_id, true)
        }
        [group, command, run_id, cluster_id] if group == "clusters" && command == "show" => {
            show_cluster(project_root, run_id, cluster_id, false)
        }
        [group, command, run_id, cluster_id, json]
            if group == "clusters" && command == "show" && json == "--json" =>
        {
            show_cluster(project_root, run_id, cluster_id, true)
        }
        [group, command, run_id] if group == "cases" && command == "list" => {
            list_cases(project_root, run_id, false)
        }
        [group, command, run_id, json]
            if group == "cases" && command == "list" && json == "--json" =>
        {
            list_cases(project_root, run_id, true)
        }
        [group, command, run_id, case_id] if group == "cases" && command == "show" => {
            show_case(project_root, run_id, case_id, false)
        }
        [group, command, run_id, case_id, json]
            if group == "cases" && command == "show" && json == "--json" =>
        {
            show_case(project_root, run_id, case_id, true)
        }
        [group, plans, command]
            if group == "remediation" && plans == "plans" && command == "list" =>
        {
            remediation_list(project_root, false)
        }
        [group, plans, command, json]
            if group == "remediation"
                && plans == "plans"
                && command == "list"
                && json == "--json" =>
        {
            remediation_list(project_root, true)
        }
        [group, plans, command, action_id]
            if group == "remediation" && plans == "plans" && command == "show" =>
        {
            remediation_show(project_root, action_id, false)
        }
        [group, plans, command, action_id, json]
            if group == "remediation"
                && plans == "plans"
                && command == "show"
                && json == "--json" =>
        {
            remediation_show(project_root, action_id, true)
        }
        [group, command, action_id] if group == "remediation" && command == "status" => {
            remediation_status(project_root, action_id, false)
        }
        [group, command, action_id, json]
            if group == "remediation" && command == "status" && json == "--json" =>
        {
            remediation_status(project_root, action_id, true)
        }
        [group, command, action_id] if group == "remediation" && command == "receipt" => {
            remediation_receipt(project_root, action_id, false)
        }
        [group, command, action_id, json]
            if group == "remediation" && command == "receipt" && json == "--json" =>
        {
            remediation_receipt(project_root, action_id, true)
        }
        [] => CommandResult::error(2, usage()),
        _ => CommandResult::error(2, format!("Unsupported or unsafe command.\n{}", usage())),
    }
}

fn usage() -> String {
    "Usage: edy-verdict <doctor|engines|validate-manifest|version|correlate|clusters list|clusters show|cases list|cases show|remediation plans list|remediation plans show|remediation status|remediation receipt> [--json]".into()
}

fn exit_code_contract() -> String {
    "Exit codes: 0=success; 1=validated operation unavailable or failed safely; 2=invalid or unsupported command".into()
}

fn remediation_store(root: &Path) -> Result<ManualRemediationStore, CommandResult> {
    if !root.is_absolute() {
        return Err(CommandResult::error(
            1,
            "Level 6 project-local database is unavailable",
        ));
    }
    let candidates = [
        root.join(".local/data/level0.sqlite3"),
        root.join(".local/data/edy-verdict.sqlite3"),
    ];
    let database = candidates
        .iter()
        .find(|path| path.is_file())
        .ok_or_else(|| CommandResult::error(1, "Level 6 project-local database is unavailable"))?;
    ManualRemediationStore::open_read_only(database)
        .map_err(|_| CommandResult::error(1, "Level 6 database failed integrity validation"))
}

fn remediation_list(root: &Path, json: bool) -> CommandResult {
    let store = match remediation_store(root) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match store.list(None, 0, 100) {
        Ok(items) if json => json_result(&items),
        Ok(items) => CommandResult::success(items.into_iter().map(|item| {
            format!(
                "{} state={:?} finding={}",
                item.plan.actions[0].action_id, item.state, item.plan.finding_id
            )
        })),
        Err(_) => CommandResult::error(1, "Remediation plans could not be read"),
    }
}
fn remediation_show(root: &Path, action_id: &str, json: bool) -> CommandResult {
    let store = match remediation_store(root) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match store.get(action_id) {
        Ok(item) if json => json_result(&item.plan),
        Ok(item) => CommandResult::success([
            format!("action_id={action_id}"),
            format!("plan_id={}", item.plan.plan_id),
            format!("plan_sha256={}", item.plan.plan_sha256),
            format!("safety_class={:?}", item.plan.actions[0].safety_class),
        ]),
        Err(_) => CommandResult::error(1, "Remediation plan was not found"),
    }
}
fn remediation_status(root: &Path, action_id: &str, json: bool) -> CommandResult {
    let store = match remediation_store(root) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match store.get(action_id) {
        Ok(item) if json => json_result(&item),
        Ok(item) => CommandResult::success([
            format!("action_id={action_id}"),
            format!("state={:?}", item.state),
            format!(
                "verification={:?}",
                item.verification.as_ref().map(|value| value.outcome)
            ),
            "automatic_mutation=POLICY_BLOCKED".into(),
        ]),
        Err(_) => CommandResult::error(1, "Remediation status was not found"),
    }
}
fn remediation_receipt(root: &Path, action_id: &str, json: bool) -> CommandResult {
    // Compatibility read route: reports verification, never an automatic-change receipt.
    let store = match remediation_store(root) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match store.get(action_id) {
        Ok(item) => {
            let report = edy_reporting::remediation::ManualRemediationReport::from_snapshot(&item);
            if json {
                json_result(&report)
            } else {
                CommandResult::success([
                    format!("action_id={action_id}"),
                    report.status.clone(),
                    "automatic_mutation=POLICY_BLOCKED".into(),
                ])
            }
        }
        Err(_) => CommandResult::error(1, "Verification report is not available"),
    }
}

fn investigation_store(root: &Path) -> Result<Level5SnapshotStore, CommandResult> {
    let database = root.join(".local/data/edy-verdict.sqlite3");
    if !root.is_absolute() || !database.is_file() {
        return Err(CommandResult::error(
            1,
            "Level 5 project-local database is unavailable",
        ));
    }
    Level5SnapshotStore::open_read_only(&database)
        .map_err(|_| CommandResult::error(1, "Level 5 database failed integrity validation"))
}

fn correlate(root: &Path, json: bool) -> CommandResult {
    let store = match investigation_store(root) {
        Ok(store) => store,
        Err(error) => return error,
    };
    let run_id = match store.list_run_ids(0, 1) {
        Ok(ids) if !ids.is_empty() => ids[0].clone(),
        _ => return CommandResult::error(1, "No approved Level 5 observations are persisted"),
    };
    let observations = match store.load_observations(&run_id) {
        Ok(value) => value,
        Err(_) => {
            return CommandResult::error(1, "Persisted observations failed integrity validation");
        }
    };
    let expected = match store.load_result(&run_id) {
        Ok(value) => value,
        Err(_) => {
            return CommandResult::error(1, "Persisted correlation failed integrity validation");
        }
    };
    let replay = match correlate_investigation(observations, GraphLimits::default(), || false) {
        Ok(value) => value,
        Err(_) => return CommandResult::error(1, "Correlation replay was refused"),
    };
    if replay != expected {
        return CommandResult::error(1, "Correlation replay does not match the persisted result");
    }
    if json {
        json_result(&replay)
    } else {
        CommandResult::success([
            format!("run_id={run_id}"),
            "replay=MATCH".into(),
            format!("nodes={}", replay.nodes.len()),
            format!("relationships={}", replay.edges.len()),
            format!("clusters={}", replay.clusters.len()),
            format!("cases={}", replay.suggested_cases.len()),
        ])
    }
}

fn list_clusters(root: &Path, run_id: &str, json: bool) -> CommandResult {
    let store = match investigation_store(root) {
        Ok(store) => store,
        Err(error) => return error,
    };
    match store.list_clusters(run_id, 0, 100) {
        Ok(items) if json => json_result(&items),
        Ok(items) => CommandResult::success(items.into_iter().map(|item| {
            format!(
                "{} {:?} findings={} targets={}",
                item.cluster_id,
                item.cluster_type,
                item.member_findings.len(),
                item.target_count
            )
        })),
        Err(_) => CommandResult::error(1, "Clusters could not be read"),
    }
}

fn show_cluster(root: &Path, run_id: &str, cluster_id: &str, json: bool) -> CommandResult {
    if !valid_level5_id(cluster_id, "cluster-v1-") {
        return CommandResult::error(2, "Cluster identifier was refused");
    }
    let store = match investigation_store(root) {
        Ok(store) => store,
        Err(error) => return error,
    };
    match store.get_cluster(run_id, cluster_id) {
        Ok(item) if json => json_result(&item),
        Ok(item) => CommandResult::success([
            format!("cluster_id={}", item.cluster_id),
            format!("type={:?}", item.cluster_type),
            format!("findings={}", item.member_findings.len()),
            format!("evidence={}", item.evidence_count),
            format!("explanation={}", item.explanation_safe),
        ]),
        Err(_) => CommandResult::error(1, "Cluster was not found"),
    }
}

fn list_cases(root: &Path, run_id: &str, json: bool) -> CommandResult {
    let store = match investigation_store(root) {
        Ok(store) => store,
        Err(error) => return error,
    };
    match store.list_cases(run_id, 0, 100) {
        Ok(items) if json => json_result(&items),
        Ok(items) => CommandResult::success(items.into_iter().map(|item| {
            format!(
                "{} {:?} risk={} confidence={} coverage={}",
                item.case_id,
                item.status,
                item.assessment.risk,
                item.assessment.confidence,
                item.assessment.coverage
            )
        })),
        Err(_) => CommandResult::error(1, "Cases could not be read"),
    }
}

fn show_case(root: &Path, run_id: &str, case_id: &str, json: bool) -> CommandResult {
    if !valid_level5_id(case_id, "case-v1-") {
        return CommandResult::error(2, "Case identifier was refused");
    }
    let store = match investigation_store(root) {
        Ok(store) => store,
        Err(error) => return error,
    };
    match store.get_case(run_id, case_id) {
        Ok(item) if json => json_result(&item),
        Ok(item) => CommandResult::success([
            format!("case_id={}", item.case_id),
            format!("status={:?}", item.status),
            format!("risk={}", item.assessment.risk),
            format!("confidence={}", item.assessment.confidence),
            format!("coverage={}", item.assessment.coverage),
            format!("findings={}", item.finding_ids.len()),
        ]),
        Err(_) => CommandResult::error(1, "Case was not found"),
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

fn json_result<T: serde::Serialize>(value: &T) -> CommandResult {
    match serde_json::to_string_pretty(value) {
        Ok(output) => CommandResult::success([output]),
        Err(_) => CommandResult::error(1, "JSON output failed"),
    }
}

fn doctor(root: &Path) -> CommandResult {
    let mut lines = vec![
        format!("version={}", env!("CARGO_PKG_VERSION")),
        format!(
            "platform={}",
            if cfg!(windows) {
                "windows"
            } else {
                "unsupported"
            }
        ),
        format!("workspace={}", present(root.join("Cargo.toml"))),
        format!(
            "storage={}",
            present(root.join(".local/data/edy-verdict.sqlite3"))
        ),
        "storage_action=READ_ONLY_NO_REPAIR".into(),
    ];
    let statuses = inspect_engines(root);
    let ready = statuses
        .iter()
        .filter(|(_, status)| *status == IntegrityStatus::Ready)
        .count();
    lines.push(format!("engine_integrity={ready}/{}", statuses.len()));
    lines.push("network_requests=0".into());
    lines.push("repairs_performed=0".into());
    let failed = !cfg!(windows)
        || !root.join("Cargo.toml").is_file()
        || statuses
            .iter()
            .any(|(_, status)| *status != IntegrityStatus::Ready);
    let mut result = CommandResult::success(lines);
    if failed {
        result.exit_code = 1;
    }
    result
}

fn engine_list(root: &Path) -> CommandResult {
    let statuses = inspect_engines(root);
    let failed = statuses
        .iter()
        .any(|(_, status)| *status != IntegrityStatus::Ready);
    let mut result = CommandResult::success(
        statuses
            .into_iter()
            .map(|(engine, status)| format!("{engine}={}", status.label())),
    );
    if failed {
        result.exit_code = 1;
    }
    result
}

fn inspect_engines(root: &Path) -> Vec<(String, IntegrityStatus)> {
    ENGINES
        .iter()
        .map(|(id, version)| {
            let status = inspect_engine(root, id, version);
            (format!("{id}@{version}"), status)
        })
        .collect()
}

fn inspect_engine(root: &Path, id: &str, version: &str) -> IntegrityStatus {
    let base = root.join("tools/engines").join(id).join(version);
    let manifest_bytes = match read_bounded(&base.join("manifest.json"), MAX_MANIFEST_BYTES) {
        Ok(bytes) => bytes,
        Err(_) => return IntegrityStatus::Missing,
    };
    let receipt_bytes = match read_bounded(
        &root
            .join("tools/receipts/engines")
            .join(id)
            .join(format!("{version}.json")),
        MAX_RECEIPT_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(_) => return IntegrityStatus::Missing,
    };
    let manifest = match EngineManifest::parse(&manifest_bytes) {
        Ok(value) => value,
        Err(_) => return IntegrityStatus::Invalid,
    };
    let receipt = match EngineReceipt::parse(&receipt_bytes) {
        Ok(value) => value,
        Err(_) => return IntegrityStatus::Invalid,
    };
    if manifest.identity.id != id || manifest.identity.version != version {
        return IntegrityStatus::Invalid;
    }
    let manifest_hash = match manifest.canonical_sha256() {
        Ok(hash) => hash,
        Err(_) => return IntegrityStatus::Invalid,
    };
    if receipt.manifest_sha256 != manifest_hash {
        return IntegrityStatus::Invalid;
    }
    let payload = base.join("payload");
    let entrypoint = match read_exact_size(
        &payload.join(&manifest.artifact.entrypoint),
        manifest.artifact.entrypoint_size,
    ) {
        Ok(bytes) => bytes,
        Err(_) => return IntegrityStatus::Missing,
    };
    let auxiliaries: Vec<_> = match manifest
        .artifact
        .auxiliary_hashes
        .iter()
        .map(|item| {
            read_exact_size(&payload.join(&item.relative_path), item.size)
                .map(|bytes| (item.relative_path.clone(), bytes))
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(files) => files,
        Err(_) => return IntegrityStatus::Missing,
    };
    let observed: Vec<_> = auxiliaries
        .iter()
        .map(|(path, bytes)| ObservedArtifact {
            relative_path: path,
            bytes,
        })
        .collect();
    let observation = match IntegrityObservation::from_bytes(&manifest, &entrypoint, &observed) {
        Ok(value) => value,
        Err(_) => return IntegrityStatus::Invalid,
    };
    if receipt.verify_against(&manifest, &observation).is_ok() {
        IntegrityStatus::Ready
    } else {
        IntegrityStatus::Invalid
    }
}

fn validate_manifest(root: &Path, requested: &Path) -> CommandResult {
    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        root.join(requested)
    };
    let allowed = root.join("tools/engines");
    let (path, allowed) = match (joined.canonicalize(), allowed.canonicalize()) {
        (Ok(path), Ok(allowed)) if path.starts_with(&allowed) => (path, allowed),
        _ => return CommandResult::error(2, "Manifest path must resolve inside tools/engines"),
    };
    let _ = allowed;
    let bytes = match read_bounded(&path, MAX_MANIFEST_BYTES) {
        Ok(bytes) => bytes,
        Err(_) => return CommandResult::error(1, "Manifest could not be read"),
    };
    match EngineManifest::parse(&bytes).and_then(|manifest| manifest.canonical_sha256()) {
        Ok(hash) => CommandResult::success([
            "manifest=VALID_V2".into(),
            format!("canonical_sha256={hash}"),
        ]),
        Err(_) => CommandResult::error(1, "manifest=INVALID"),
    }
}

fn read_bounded(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds the permitted size",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file changed while being read",
        ));
    }
    Ok(bytes)
}

fn read_exact_size(path: &Path, expected: u64) -> io::Result<Vec<u8>> {
    let bytes = read_bounded(path, expected)?;
    if bytes.len() as u64 != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file size disagrees with trusted manifest",
        ));
    }
    Ok(bytes)
}

fn present(path: PathBuf) -> &'static str {
    if path.exists() { "PRESENT" } else { "ABSENT" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_only_the_four_safe_commands() {
        let root = Path::new(".");
        assert_eq!(run(&["version".into()], root).exit_code, 0);
        for command in ["help", "--help", "-h"] {
            let result = run(&[command.into()], root);
            assert_eq!(result.exit_code, 0);
            assert!(result.stdout.contains("Exit codes:"));
        }
        assert_eq!(
            run(&["--version".into()], root).stdout,
            "edy-verdict 1.0.0-rc.1"
        );
        for command in ["scan", "fix", "remediate", "url-test", "shell"] {
            let result = run(&[command.into()], root);
            assert_eq!(result.exit_code, 2);
            assert!(result.stderr.contains("unsafe"));
        }
    }

    #[test]
    fn level6_cli_exposes_reads_but_no_apply_or_rollback() {
        let root = Path::new(".");
        for args in [
            vec!["remediation", "apply", "rma-v1-dead"],
            vec!["remediation", "rollback", "rma-v1-dead"],
            vec!["remediation", "patch", "rma-v1-dead"],
        ] {
            let result = run(
                &args.into_iter().map(str::to_owned).collect::<Vec<_>>(),
                root,
            );
            assert_eq!(result.exit_code, 2);
            assert!(result.stderr.contains("unsafe"));
        }
        assert_eq!(
            run(&["remediation".into(), "plans".into(), "list".into()], root).exit_code,
            1
        );
    }

    #[test]
    fn level6_cli_reads_schema_eight_without_modifying_the_database() {
        let root = std::env::temp_dir().join(format!(
            "edy-cli-manual-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let data = root.join(".local/data");
        fs::create_dir_all(&data).unwrap();
        let path = data.join("level0.sqlite3");
        drop(ManualRemediationStore::open(&path).unwrap());
        let before = fs::read(&path).unwrap();
        let list = run(
            &[
                "remediation".into(),
                "plans".into(),
                "list".into(),
                "--json".into(),
            ],
            &root,
        );
        assert_eq!(list.exit_code, 0);
        assert_eq!(list.stdout, "[]");
        for verb in ["status", "receipt"] {
            assert_eq!(
                run(
                    &[
                        "remediation".into(),
                        verb.into(),
                        format!("rma-v1-{}", "a".repeat(64))
                    ],
                    &root
                )
                .exit_code,
                1
            );
        }
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validate_manifest_rejects_paths_outside_engine_root() {
        let result = run(
            &["validate-manifest".into(), "Cargo.toml".into()],
            Path::new("."),
        );
        assert_eq!(result.exit_code, 2);
        assert!(!result.stdout.contains("Cargo.toml"));
    }

    #[test]
    fn engine_contract_is_fixed_and_deterministic() {
        assert_eq!(
            ENGINES,
            [
                ("yara-x", "1.20.0"),
                ("gitleaks", "8.30.0"),
                ("trivy", "0.74.0"),
                ("osv-scanner", "2.5.1")
            ]
        );
    }

    #[test]
    fn bounded_reader_rejects_oversized_files_before_consuming_them() {
        let path = std::env::temp_dir().join(format!(
            "edy-cli-bounded-{}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, [0_u8; 8]).unwrap();
        let error = read_bounded(&path, 4).unwrap_err();
        fs::remove_file(path).unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn level5_commands_replay_and_read_persisted_cases_without_host_actions() {
        use edy_core::{
            CorrelationFinding, GraphLimits, IdentifierKind, StrongIdentity, TargetType,
            correlate_investigation,
        };
        let root = std::env::temp_dir().join(format!(
            "edy-cli-level5-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let data = root.join(".local/data");
        fs::create_dir_all(&data).unwrap();
        let run_id = "018f4c2a-1d3b-7abc-8def-0123456789f1";
        let finding = |id: &str, target: &str| CorrelationFinding {
            finding_id: id.into(),
            target_id: target.into(),
            target_type: TargetType::Repository,
            target_identity: StrongIdentity::new(IdentifierKind::StableTarget, target).unwrap(),
            affected_identity: StrongIdentity::new(
                IdentifierKind::Purl,
                format!("pkg:npm/{target}@1.0.0"),
            )
            .unwrap(),
            vulnerability_id: Some("CVE-2099-1001".into()),
            artifact_sha256: None,
            purl: Some(format!("pkg:npm/{target}@1.0.0")),
            cpe: None,
            web_origin: None,
            web_domain: None,
            evidence_ids: vec![format!("evidence-{id}")],
            source_scans: vec![format!("scan-{id}")],
            severity_points: 70,
            kev: false,
            epss_basis_points: None,
            provider_available: true,
            parser_certain: true,
            conflicting_evidence: false,
            first_seen: "2099-01-01T00:00:00Z".into(),
            last_seen: "2099-01-02T00:00:00Z".into(),
            occurrence_count: 1,
            reopened: false,
        };
        let observations = vec![
            finding("finding-a", "package-a"),
            finding("finding-b", "package-b"),
        ];
        let result =
            correlate_investigation(observations.clone(), GraphLimits::default(), || false)
                .unwrap();
        let mut store = Level5SnapshotStore::open(&data.join("edy-verdict.sqlite3")).unwrap();
        store.promote(run_id, &observations, &result).unwrap();
        drop(store);
        let database_before = fs::read(data.join("edy-verdict.sqlite3")).unwrap();
        let replay = run(&["correlate".into(), "--json".into()], &root);
        assert_eq!(replay.exit_code, 0);
        assert!(replay.stdout.contains("LEVEL5_INVESTIGATION_V1"));
        let cases = run(
            &[
                "cases".into(),
                "list".into(),
                run_id.into(),
                "--json".into(),
            ],
            &root,
        );
        assert_eq!(cases.exit_code, 0);
        assert!(cases.stdout.contains("case-v1-"));
        let show = run(
            &[
                "clusters".into(),
                "show".into(),
                run_id.into(),
                result.clusters[0].cluster_id.clone(),
            ],
            &root,
        );
        assert_eq!(show.exit_code, 0);
        assert!(show.stdout.contains("findings=2"));
        let invalid = run(
            &[
                "cases".into(),
                "show".into(),
                run_id.into(),
                "case-v1-not-hex".into(),
            ],
            &root,
        );
        assert_eq!(invalid.exit_code, 2);
        assert_eq!(
            fs::read(data.join("edy-verdict.sqlite3")).unwrap(),
            database_before
        );
        fs::remove_dir_all(root).unwrap();
    }
}
