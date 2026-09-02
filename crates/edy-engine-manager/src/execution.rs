//! Windows execution-integrity gate layered above the frozen Manifest/Receipt V2 contract.
//!
//! This module never acquires engines or data. It binds an already-approved manifest and
//! receipt to the exact local payload, rejects redirecting filesystem objects, and keeps
//! mutable scanner data (rules/config/databases) in a separate trust domain.

use crate::manifest::{
    ArtifactSetRecord, ContractError, EngineManifest, EngineTrustPolicy, artifact_set_sha256,
    safe_relative,
};
use crate::receipt::{EngineReceipt, ReceiptState};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::time::{Duration, SystemTime};
use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, GetDriveTypeW};

const MAX_CONTROL_BYTES: u64 = 256 * 1024;
const MAX_ENGINE_FILE_BYTES: u64 = 512 * 1024 * 1024;
const DRIVE_FIXED: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionGateError {
    UnsafePath,
    Missing,
    WrongType,
    ReparsePoint,
    OutsideApprovedRoot,
    InvalidManifest,
    InvalidReceipt,
    ReceiptMismatch,
    PolicyBlocked,
    HashMismatch,
    SizeMismatch,
    MissingDeclaredFile,
    UnexpectedFile,
    DuplicateDeclaration,
    Io,
}

impl fmt::Display for ExecutionGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath => "unsafe or non-local path",
            Self::Missing => "required path is missing",
            Self::WrongType => "path has an unexpected file type",
            Self::ReparsePoint => "reparse point, symlink, or junction rejected",
            Self::OutsideApprovedRoot => "path escapes its approved root",
            Self::InvalidManifest => "manifest is invalid",
            Self::InvalidReceipt => "receipt is invalid",
            Self::ReceiptMismatch => "receipt does not match the manifest or payload",
            Self::PolicyBlocked => "engine trust policy blocked execution",
            Self::HashMismatch => "content hash mismatch",
            Self::SizeMismatch => "content size mismatch",
            Self::MissingDeclaredFile => "declared file is missing",
            Self::UnexpectedFile => "closed artifact set contains an unexpected file",
            Self::DuplicateDeclaration => "duplicate runtime asset declaration",
            Self::Io => "filesystem validation failed",
        })
    }
}

impl std::error::Error for ExecutionGateError {}

impl From<io::Error> for ExecutionGateError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::NotFound {
            Self::Missing
        } else {
            Self::Io
        }
    }
}

pub struct ExecutionGateRequest<'a> {
    pub manifest_path: &'a Path,
    pub receipt_path: &'a Path,
    pub engine_root: &'a Path,
    pub trust_policy: &'a EngineTrustPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEngine {
    pub manifest: EngineManifest,
    pub receipt: EngineReceipt,
    pub root: PathBuf,
    pub executable: PathBuf,
    pub artifacts: Vec<VerifiedArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifact {
    pub relative_path: String,
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
}

impl VerifiedEngine {
    #[cfg(windows)]
    pub fn process_request(
        &self,
        arguments: Vec<String>,
        environment: Vec<(String, String)>,
    ) -> crate::process::ProcessRequest {
        crate::process::ProcessRequest {
            approved_root: self.root.clone(),
            executable: self.executable.clone(),
            sha256: self.manifest.artifact.executable_sha256.clone(),
            artifact_set_sha256: self.receipt.artifact_set_sha256.clone(),
            artifacts: self
                .artifacts
                .iter()
                .map(|artifact| crate::process::ProcessArtifact {
                    relative_path: artifact.relative_path.clone(),
                    path: artifact.path.clone(),
                    sha256: artifact.sha256.clone(),
                    size: artifact.size,
                })
                .collect(),
            arguments,
            environment,
            working_directory: self.root.clone(),
            timeout: Duration::from_millis(self.manifest.process.timeout_ms),
            stdout_limit: self.manifest.process.stdout_limit_bytes as usize,
            stderr_limit: self.manifest.process.stderr_limit_bytes as usize,
        }
    }
}

pub fn verify_engine(
    request: &ExecutionGateRequest<'_>,
) -> Result<VerifiedEngine, ExecutionGateError> {
    let manifest_path = canonical_regular_file(request.manifest_path)?;
    let receipt_path = canonical_regular_file(request.receipt_path)?;
    require_extension(&manifest_path, "json")?;
    require_extension(&receipt_path, "json")?;
    let manifest_bytes = read_bounded(&manifest_path, MAX_CONTROL_BYTES)?;
    let receipt_bytes = read_bounded(&receipt_path, MAX_CONTROL_BYTES)?;
    let manifest = EngineManifest::parse(&manifest_bytes).map_err(map_manifest_error)?;
    let receipt =
        EngineReceipt::parse(&receipt_bytes).map_err(|_| ExecutionGateError::InvalidReceipt)?;
    request
        .trust_policy
        .evaluate(&manifest)
        .map_err(|_| ExecutionGateError::PolicyBlocked)?;

    let root = canonical_local_directory(request.engine_root)?;
    let executable_path = root.join(&manifest.artifact.entrypoint);
    let executable = revalidate_canonical_regular_file(&executable_path)?;
    ensure_contained(&root, &executable)?;
    require_extension(&executable, "exe")?;

    let mut expected = BTreeMap::new();
    insert_expected(
        &mut expected,
        &manifest.artifact.entrypoint,
        &manifest.artifact.executable_sha256,
        manifest.artifact.entrypoint_size,
    )?;
    for auxiliary in &manifest.artifact.auxiliary_hashes {
        insert_expected(
            &mut expected,
            &auxiliary.relative_path,
            &auxiliary.sha256,
            auxiliary.size,
        )?;
    }

    let observed = observe_tree(&root)?;
    if manifest.artifact.closed_set {
        for path in observed.keys() {
            if !expected.contains_key(path) {
                return Err(ExecutionGateError::UnexpectedFile);
            }
        }
    }
    if observed.len() < expected.len() {
        return Err(ExecutionGateError::MissingDeclaredFile);
    }

    let mut records = Vec::with_capacity(expected.len());
    let mut verified_artifacts = Vec::with_capacity(expected.len());
    for (relative, (expected_hash, expected_size)) in &expected {
        let observed_file = observed
            .get(relative)
            .ok_or(ExecutionGateError::MissingDeclaredFile)?;
        if observed_file.size != *expected_size {
            return Err(ExecutionGateError::SizeMismatch);
        }
        if observed_file.sha256 != *expected_hash {
            return Err(ExecutionGateError::HashMismatch);
        }
        records.push(ArtifactSetRecord {
            relative_path: observed_file.relative_path.clone(),
            sha256: observed_file.sha256.clone(),
            size: observed_file.size,
        });
        verified_artifacts.push(VerifiedArtifact {
            relative_path: observed_file.relative_path.clone(),
            path: observed_file.path.clone(),
            sha256: observed_file.sha256.clone(),
            size: observed_file.size,
        });
    }
    let artifact_set = artifact_set_sha256(records).map_err(map_manifest_error)?;
    let manifest_sha = manifest.canonical_sha256().map_err(map_manifest_error)?;
    if receipt.state != ReceiptState::Ready
        || receipt.engine_id != manifest.identity.id
        || receipt.version != manifest.identity.version
        || receipt.manifest_sha256 != manifest_sha
        || receipt.entrypoint_sha256 != manifest.artifact.executable_sha256
        || receipt.artifact_set_sha256 != artifact_set
        || receipt.artifact_set_sha256
            != manifest
                .declared_artifact_set_sha256()
                .map_err(map_manifest_error)?
    {
        return Err(ExecutionGateError::ReceiptMismatch);
    }
    Ok(VerifiedEngine {
        manifest,
        receipt,
        root,
        executable,
        artifacts: verified_artifacts,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuntimeAssetClass {
    Ruleset,
    Config,
    IgnorePolicy,
    Template,
}

pub struct RuntimeAssetDeclaration<'a> {
    pub class: RuntimeAssetClass,
    pub root: &'a Path,
    pub relative_path: &'a str,
    pub sha256: &'a str,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRuntimeAsset {
    pub class: RuntimeAssetClass,
    pub path: PathBuf,
}

/// Verifies immutable scanner data without conflating it with engine binary trust.
pub fn verify_runtime_assets(
    project_root: &Path,
    declarations: &[RuntimeAssetDeclaration<'_>],
) -> Result<Vec<VerifiedRuntimeAsset>, ExecutionGateError> {
    let project_root = canonical_local_directory(project_root)?;
    let mut seen = BTreeSet::new();
    let mut verified = Vec::with_capacity(declarations.len());
    for declaration in declarations {
        if !safe_relative(declaration.relative_path)
            || !seen.insert((
                declaration.class,
                declaration
                    .root
                    .join(declaration.relative_path)
                    .to_string_lossy()
                    .to_ascii_lowercase(),
            ))
        {
            return Err(ExecutionGateError::DuplicateDeclaration);
        }
        let root = canonical_local_directory(declaration.root)?;
        ensure_contained(&project_root, &root)?;
        let path = revalidate_canonical_regular_file(&root.join(declaration.relative_path))?;
        ensure_contained(&root, &path)?;
        let observed = hash_file(&path)?;
        if observed.size != declaration.size {
            return Err(ExecutionGateError::SizeMismatch);
        }
        if observed.sha256 != declaration.sha256 {
            return Err(ExecutionGateError::HashMismatch);
        }
        verified.push(VerifiedRuntimeAsset {
            class: declaration.class,
            path,
        });
    }
    Ok(verified)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataUnavailableReason {
    Missing,
    VersionMismatch,
    ProvenanceUnverified,
    Stale,
    FutureTimestamp,
    Tampered,
    UnsafeLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFreshness {
    Fresh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataReadiness {
    pub present: bool,
    pub version: String,
    pub age: Duration,
    pub provenance: String,
    pub freshness: DataFreshness,
}

pub struct DataFileDeclaration<'a> {
    pub relative_path: &'a str,
    pub sha256: &'a str,
    pub size: u64,
}

/// Explicit offline-data contract for Trivy/OSV. Absence is unavailable, never clean.
#[derive(Clone, Copy)]
pub struct DataTrustContract<'a> {
    pub project_root: &'a Path,
    pub data_root: &'a Path,
    pub expected_version: &'a str,
    pub observed_version: &'a str,
    pub provenance: &'a str,
    pub provenance_verified: bool,
    pub acquired_at: SystemTime,
    pub maximum_age: Duration,
    pub files: &'a [DataFileDeclaration<'a>],
}

pub fn verify_data_trust(
    contract: &DataTrustContract<'_>,
    now: SystemTime,
) -> Result<DataReadiness, DataUnavailableReason> {
    if !contract.data_root.exists() {
        return Err(DataUnavailableReason::Missing);
    }
    if contract.expected_version.is_empty()
        || contract.observed_version != contract.expected_version
    {
        return Err(DataUnavailableReason::VersionMismatch);
    }
    if !contract.provenance_verified || contract.provenance.trim().is_empty() {
        return Err(DataUnavailableReason::ProvenanceUnverified);
    }
    let age = now
        .duration_since(contract.acquired_at)
        .map_err(|_| DataUnavailableReason::FutureTimestamp)?;
    if age > contract.maximum_age {
        return Err(DataUnavailableReason::Stale);
    }
    let project_root = canonical_local_directory(contract.project_root)
        .map_err(|_| DataUnavailableReason::UnsafeLocation)?;
    let data_root = canonical_local_directory(contract.data_root)
        .map_err(|_| DataUnavailableReason::UnsafeLocation)?;
    ensure_contained(&project_root, &data_root)
        .map_err(|_| DataUnavailableReason::UnsafeLocation)?;
    if contract.files.is_empty() {
        return Err(DataUnavailableReason::Missing);
    }
    let mut seen = BTreeSet::new();
    for file in contract.files {
        if !safe_relative(file.relative_path)
            || !seen.insert(file.relative_path.to_ascii_lowercase())
        {
            return Err(DataUnavailableReason::Tampered);
        }
        let path = revalidate_canonical_regular_file(&data_root.join(file.relative_path))
            .map_err(|_| DataUnavailableReason::Tampered)?;
        ensure_contained(&data_root, &path).map_err(|_| DataUnavailableReason::Tampered)?;
        let observed = hash_file(&path).map_err(|_| DataUnavailableReason::Tampered)?;
        if observed.size != file.size || observed.sha256 != file.sha256 {
            return Err(DataUnavailableReason::Tampered);
        }
    }
    Ok(DataReadiness {
        present: true,
        version: contract.observed_version.to_owned(),
        age,
        provenance: contract.provenance.to_owned(),
        freshness: DataFreshness::Fresh,
    })
}

#[derive(Debug)]
struct ObservedFile {
    relative_path: String,
    path: PathBuf,
    sha256: String,
    size: u64,
}

fn observe_tree(root: &Path) -> Result<BTreeMap<String, ObservedFile>, ExecutionGateError> {
    let mut files = BTreeMap::new();
    observe_directory(root, root, &mut files)?;
    Ok(files)
}

fn observe_directory(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, ObservedFile>,
) -> Result<(), ExecutionGateError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if is_reparse(&metadata) || metadata.file_type().is_symlink() {
            return Err(ExecutionGateError::ReparsePoint);
        }
        if metadata.is_dir() {
            observe_directory(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| ExecutionGateError::OutsideApprovedRoot)?
                .to_str()
                .ok_or(ExecutionGateError::UnsafePath)?
                .replace('\\', "/");
            if !safe_relative(&relative) {
                return Err(ExecutionGateError::UnsafePath);
            }
            let observed = hash_file(&path)?;
            let key = relative.to_ascii_lowercase();
            if files
                .insert(
                    key,
                    ObservedFile {
                        relative_path: relative,
                        path,
                        sha256: observed.sha256,
                        size: observed.size,
                    },
                )
                .is_some()
            {
                return Err(ExecutionGateError::DuplicateDeclaration);
            }
        } else {
            return Err(ExecutionGateError::WrongType);
        }
    }
    Ok(())
}

fn insert_expected(
    expected: &mut BTreeMap<String, (String, u64)>,
    relative: &str,
    hash: &str,
    size: u64,
) -> Result<(), ExecutionGateError> {
    if !safe_relative(relative)
        || expected
            .insert(relative.to_ascii_lowercase(), (hash.to_owned(), size))
            .is_some()
    {
        return Err(ExecutionGateError::DuplicateDeclaration);
    }
    Ok(())
}

struct HashObservation {
    sha256: String,
    size: u64,
}

fn hash_file(path: &Path) -> Result<HashObservation, ExecutionGateError> {
    let metadata = fs::symlink_metadata(path)?;
    if is_reparse(&metadata) || metadata.file_type().is_symlink() {
        return Err(ExecutionGateError::ReparsePoint);
    }
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_ENGINE_FILE_BYTES {
        return Err(ExecutionGateError::WrongType);
    }
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(HashObservation {
        sha256: format!("{:x}", digest.finalize()),
        size: metadata.len(),
    })
}

pub(crate) fn canonical_regular_file(path: &Path) -> Result<PathBuf, ExecutionGateError> {
    validate_local_lexical(path, false)?;
    reject_reparse_chain(path)?;
    let canonical = path.canonicalize()?;
    revalidate_canonical_regular_file(&canonical)
}

pub(crate) fn revalidate_canonical_regular_file(
    canonical: &Path,
) -> Result<PathBuf, ExecutionGateError> {
    validate_local_lexical(canonical, true)?;
    reject_reparse_chain(canonical)?;
    let metadata = fs::symlink_metadata(canonical)?;
    if is_reparse(&metadata) || metadata.file_type().is_symlink() {
        return Err(ExecutionGateError::ReparsePoint);
    }
    if !metadata.is_file() {
        return Err(ExecutionGateError::WrongType);
    }
    Ok(canonical.to_path_buf())
}

pub(crate) fn canonical_local_directory(path: &Path) -> Result<PathBuf, ExecutionGateError> {
    validate_local_lexical(path, false)?;
    reject_reparse_chain(path)?;
    let canonical = path.canonicalize()?;
    revalidate_canonical_directory(&canonical)
}

pub(crate) fn revalidate_canonical_directory(
    canonical: &Path,
) -> Result<PathBuf, ExecutionGateError> {
    validate_local_lexical(canonical, true)?;
    reject_reparse_chain(canonical)?;
    let metadata = fs::symlink_metadata(canonical)?;
    if is_reparse(&metadata) || metadata.file_type().is_symlink() {
        return Err(ExecutionGateError::ReparsePoint);
    }
    if !metadata.is_dir() {
        return Err(ExecutionGateError::WrongType);
    }
    Ok(canonical.to_path_buf())
}

pub(crate) fn ensure_contained(root: &Path, candidate: &Path) -> Result<(), ExecutionGateError> {
    let normalize = |path: &Path| -> Result<String, ExecutionGateError> {
        let value = path
            .to_str()
            .ok_or(ExecutionGateError::UnsafePath)?
            .replace('/', "\\");
        let value = value.strip_prefix(r"\\?\").unwrap_or(&value);
        Ok(value.trim_end_matches('\\').to_ascii_lowercase())
    };
    let root = normalize(root)?;
    let candidate = normalize(candidate)?;
    if candidate == root || candidate.starts_with(&format!("{root}\\")) {
        Ok(())
    } else {
        Err(ExecutionGateError::OutsideApprovedRoot)
    }
}

fn validate_local_lexical(path: &Path, allow_verbatim: bool) -> Result<(), ExecutionGateError> {
    if !path.is_absolute() {
        return Err(ExecutionGateError::UnsafePath);
    }
    let text = path.to_str().ok_or(ExecutionGateError::UnsafePath)?;
    if text.contains('\0')
        || (!allow_verbatim && (text.starts_with("\\\\") || text.starts_with("//")))
    {
        return Err(ExecutionGateError::UnsafePath);
    }
    if !allow_verbatim
        && text
            .char_indices()
            .any(|(index, character)| character == ':' && index != 1)
    {
        return Err(ExecutionGateError::UnsafePath);
    }
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) => drive,
            Prefix::VerbatimDisk(drive) if allow_verbatim => drive,
            _ => return Err(ExecutionGateError::UnsafePath),
        },
        _ => return Err(ExecutionGateError::UnsafePath),
    };
    if !matches!(components.next(), Some(Component::RootDir))
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ExecutionGateError::UnsafePath);
    }
    let drive_root = [drive as u16, b':' as u16, b'\\' as u16, 0];
    if unsafe { GetDriveTypeW(drive_root.as_ptr()) } != DRIVE_FIXED {
        return Err(ExecutionGateError::UnsafePath);
    }
    Ok(())
}

fn reject_reparse_chain(path: &Path) -> Result<(), ExecutionGateError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current)?;
        if is_reparse(&metadata) || metadata.file_type().is_symlink() {
            return Err(ExecutionGateError::ReparsePoint);
        }
    }
    Ok(())
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn require_extension(path: &Path, extension: &str) -> Result<(), ExecutionGateError> {
    if path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
    {
        Ok(())
    } else {
        Err(ExecutionGateError::WrongType)
    }
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, ExecutionGateError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 || metadata.len() > limit {
        return Err(ExecutionGateError::WrongType);
    }
    fs::read(path).map_err(Into::into)
}

fn map_manifest_error(_: ContractError) -> ExecutionGateError {
    ExecutionGateError::InvalidManifest
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn ordinary_local_paths_canonicalize_without_losing_drive_identity() {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let canonical_directory = canonical_local_directory(&directory)
            .unwrap_or_else(|error| panic!("directory {}: {error}", directory.display()));
        let file = directory.join("Cargo.toml");
        let canonical_file = canonical_regular_file(&file)
            .unwrap_or_else(|error| panic!("file {}: {error}", file.display()));
        ensure_contained(&canonical_directory, &canonical_file).unwrap();
    }
}
