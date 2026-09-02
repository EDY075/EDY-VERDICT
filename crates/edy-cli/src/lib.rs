#![forbid(unsafe_code)]
//! Safe, read-only Level 0 command surface.

use edy_engine_manager::manifest::EngineManifest;
use edy_engine_manager::receipt::{EngineReceipt, IntegrityObservation, ObservedArtifact};
use std::fs;
use std::path::{Path, PathBuf};

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
        [command] if command == "version" => {
            CommandResult::success([format!("edy-verdict {}", env!("CARGO_PKG_VERSION"))])
        }
        [command] if command == "doctor" => doctor(project_root),
        [command] if command == "engines" => engine_list(project_root),
        [command, path] if command == "validate-manifest" => {
            validate_manifest(project_root, Path::new(path))
        }
        [] => CommandResult::error(2, usage()),
        _ => CommandResult::error(2, format!("Unsupported or unsafe command.\n{}", usage())),
    }
}

fn usage() -> String {
    "Usage: edy-verdict <doctor|engines|validate-manifest|version>".into()
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
    let manifest_bytes = match fs::read(base.join("manifest.json")) {
        Ok(bytes) => bytes,
        Err(_) => return IntegrityStatus::Missing,
    };
    let receipt_bytes = match fs::read(
        root.join("tools/receipts/engines")
            .join(id)
            .join(format!("{version}.json")),
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
    let payload = base.join("payload");
    let entrypoint = match fs::read(payload.join(&manifest.artifact.entrypoint)) {
        Ok(bytes) => bytes,
        Err(_) => return IntegrityStatus::Missing,
    };
    let auxiliaries: Vec<_> = match manifest
        .artifact
        .auxiliary_hashes
        .iter()
        .map(|item| {
            fs::read(payload.join(&item.relative_path))
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
    let bytes = match fs::read(path) {
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
        for command in ["scan", "fix", "remediation", "url-test", "shell"] {
            let result = run(&[command.into()], root);
            assert_eq!(result.exit_code, 2);
            assert!(result.stderr.contains("unsafe"));
        }
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
}
