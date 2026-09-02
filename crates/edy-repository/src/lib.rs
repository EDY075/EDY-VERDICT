//! Level 1 repository boundary: explicit authorization and bounded, first-party inventory.
//!
//! This crate never invokes an external engine and never follows a link or reparse point.

use edy_core::{Target, TargetId, TargetKind, TargetLocator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

mod correlation;
pub use correlation::*;
mod aggregation;
pub use aggregation::*;
mod pipeline;
pub use pipeline::*;

pub const REPOSITORY_SNAPSHOT_VERSION: &str = "REPOSITORY_SNAPSHOT_V1";
pub const BUILT_IN_EXCLUSIONS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".local",
    "dist",
    "build",
    "coverage",
    ".engine-payloads",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryFindingCategory {
    Secret,
    VulnerableDependency,
    Misconfiguration,
    SupplyChain,
    License,
    SuspiciousRepositoryArtifact,
}

impl RepositoryFindingCategory {
    pub const fn token(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::VulnerableDependency => "vulnerable_dependency",
            Self::Misconfiguration => "misconfiguration",
            Self::SupplyChain => "supply_chain",
            Self::License => "license",
            Self::SuspiciousRepositoryArtifact => "suspicious_repository_artifact",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryObservation {
    pub engine_id: String,
    pub engine_version: String,
    pub category: RepositoryFindingCategory,
    pub rule_id: String,
    pub description: String,
    pub location: String,
    pub line: Option<u64>,
    pub severity: String,
    pub confidence: String,
    pub fingerprint_version: String,
    pub fingerprint: String,
    pub package: Option<String>,
    pub installed_version: Option<String>,
    pub vulnerability_id: Option<String>,
    pub aliases: Vec<String>,
    pub affected_range: Option<String>,
    pub fixed_version: Option<String>,
    pub source: Option<String>,
    pub secret_class: Option<String>,
    pub secret_preview: Option<String>,
    pub secret_digest: Option<String>,
    pub license: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

pub fn finding_fingerprint(
    version: &str,
    target: &AuthorizedRepositoryTarget,
    fields: &[&str],
) -> String {
    let mut hash = Sha256::new();
    hash.update(version.as_bytes());
    hash.update([0]);
    hash.update(target.canonical_root().to_ascii_lowercase().as_bytes());
    for field in fields {
        let normalized = field.trim().replace('\\', "/").to_ascii_lowercase();
        hash.update((normalized.len() as u32).to_be_bytes());
        hash.update(normalized.as_bytes());
    }
    format!("{}-{:x}", version.to_ascii_lowercase(), hash.finalize())
}

/// Normalizes an engine-reported file location and proves it remains under the
/// immutable authorized repository root. It does not touch the filesystem.
pub fn normalize_reported_path(
    target: &AuthorizedRepositoryTarget,
    value: &str,
) -> Result<String, RepositoryError> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(RepositoryError::new("reported_path_invalid"));
    }
    reject_raw_path(value)?;
    let normalized = value.replace('\\', "/");
    let root = target.canonical_root().trim_end_matches('/');
    let relative = if Path::new(value).is_absolute() {
        let lower = normalized.to_ascii_lowercase();
        let root_lower = root.to_ascii_lowercase();
        let prefix = format!("{root_lower}/");
        if !lower.starts_with(&prefix) {
            return Err(RepositoryError::new("reported_path_escape"));
        }
        &normalized[root.len() + 1..]
    } else {
        normalized.as_str()
    };
    if relative.is_empty()
        || relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(RepositoryError::new("reported_path_escape"));
    }
    Ok(relative.into())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryLimits {
    pub max_files: u64,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_depth: u32,
}

impl Default for RepositoryLimits {
    fn default() -> Self {
        Self {
            max_files: 100_000,
            max_total_bytes: 5 * 1024 * 1024 * 1024,
            max_file_bytes: 64 * 1024 * 1024,
            max_depth: 48,
        }
    }
}

impl RepositoryLimits {
    pub fn validate(self) -> Result<Self, RepositoryError> {
        if self.max_files == 0
            || self.max_files > 1_000_000
            || self.max_total_bytes == 0
            || self.max_total_bytes > 100 * 1024 * 1024 * 1024
            || self.max_file_bytes == 0
            || self.max_file_bytes > 2 * 1024 * 1024 * 1024
            || self.max_depth == 0
            || self.max_depth > 128
        {
            return Err(RepositoryError::new("limits_invalid"));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedRepositoryTarget {
    authorization_id: String,
    authorized_at: String,
    target: Target,
    canonical_root: String,
    limits: RepositoryLimits,
    exclusions: Vec<String>,
}

impl AuthorizedRepositoryTarget {
    pub fn authorize(
        input: &str,
        target_id: TargetId,
        authorization_id: impl Into<String>,
        authorized_at: impl Into<String>,
        limits: RepositoryLimits,
    ) -> Result<Self, RepositoryError> {
        if input.is_empty() || input.len() > 4096 || input.contains('\0') {
            return Err(RepositoryError::new("path_invalid"));
        }
        reject_raw_path(input)?;
        let raw = Path::new(input);
        if !raw.is_absolute() || raw.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(RepositoryError::new("path_not_absolute"));
        }
        let metadata =
            fs::symlink_metadata(raw).map_err(|_| RepositoryError::new("path_missing"))?;
        if is_link_or_reparse(&metadata) {
            return Err(RepositoryError::new("path_reparse_denied"));
        }
        if !metadata.is_dir() {
            return Err(RepositoryError::new("path_not_directory"));
        }
        reject_reparse_ancestors(raw)?;
        let canonical = fs::canonicalize(raw).map_err(|_| RepositoryError::new("path_invalid"))?;
        if !canonical.is_dir() || !is_local_fixed_path(&canonical) {
            return Err(RepositoryError::new("path_not_local_fixed"));
        }
        reject_forbidden_root(&canonical)?;
        let canonical_root = portable_path(&canonical);
        let locator = TargetLocator::new_local_path(canonical_root.clone())
            .map_err(|_| RepositoryError::new("path_invalid"))?;
        let target = Target::new(target_id, TargetKind::Repository, locator)
            .map_err(|_| RepositoryError::new("target_invalid"))?;
        let authorization_id = authorization_id.into();
        let authorized_at = authorized_at.into();
        if authorization_id.len() != 36 || authorized_at.len() > 64 || authorized_at.is_empty() {
            return Err(RepositoryError::new("authorization_invalid"));
        }
        Ok(Self {
            authorization_id,
            authorized_at,
            target,
            canonical_root,
            limits: limits.validate()?,
            exclusions: BUILT_IN_EXCLUSIONS.iter().map(|s| (*s).into()).collect(),
        })
    }

    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }
    pub fn authorized_at(&self) -> &str {
        &self.authorized_at
    }
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn canonical_root(&self) -> &str {
        &self.canonical_root
    }
    pub fn root_path(&self) -> PathBuf {
        PathBuf::from(&self.canonical_root)
    }
    pub const fn limits(&self) -> RepositoryLimits {
        self.limits
    }
    pub fn exclusions(&self) -> &[String] {
        &self.exclusions
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryDocumentKind {
    Manifest,
    Lockfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecognizedDocument {
    pub relative_path: String,
    pub name: String,
    pub ecosystem: String,
    pub kind: RepositoryDocumentKind,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStatus {
    Complete,
    PartialLimitReached,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositorySecurityEvent {
    pub code: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryInventory {
    pub snapshot_version: String,
    pub structural_fingerprint: String,
    pub canonical_root: String,
    pub file_count: u64,
    pub directory_count: u64,
    pub total_bytes: u64,
    pub oversized_files: u64,
    pub extensions: BTreeMap<String, u64>,
    pub documents: Vec<RecognizedDocument>,
    pub ecosystems: Vec<String>,
    pub exclusions: Vec<String>,
    pub limits: RepositoryLimits,
    pub status: InventoryStatus,
    pub security_events: Vec<RepositorySecurityEvent>,
    pub gitignore_support: String,
}

pub fn inspect(
    target: &AuthorizedRepositoryTarget,
) -> Result<RepositoryInventory, RepositoryError> {
    let root = target.root_path();
    let root = fs::canonicalize(&root).map_err(|_| RepositoryError::new("target_unavailable"))?;
    if portable_path(&root) != target.canonical_root || is_reparse_path(&root)? {
        return Err(RepositoryError::new("target_changed"));
    }
    let mut state = InventoryState::default();
    let mut pending = vec![(root.clone(), 0_u32)];
    while let Some((directory, depth)) = pending.pop() {
        if depth > target.limits.max_depth {
            state.limit_reached = true;
            continue;
        }
        let mut entries = fs::read_dir(&directory)
            .map_err(|_| RepositoryError::new("inventory_read_failed"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RepositoryError::new("inventory_read_failed"))?;
        entries.sort_by_key(|entry| entry.file_name().to_string_lossy().to_ascii_lowercase());
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let relative = path
                .strip_prefix(&root)
                .map_err(|_| RepositoryError::new("path_escape"))?;
            let rel = portable_relative(relative)?;
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| RepositoryError::new("inventory_metadata_failed"))?;
            if is_link_or_reparse(&metadata) {
                state.security_events.push(RepositorySecurityEvent {
                    code: "reparse_point_skipped".into(),
                    relative_path: rel,
                });
                continue;
            }
            if metadata.is_dir() {
                if excluded(relative) {
                    continue;
                }
                state.directories += 1;
                pending.push((path, depth + 1));
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            if state.files >= target.limits.max_files
                || state.total_bytes.saturating_add(metadata.len()) > target.limits.max_total_bytes
            {
                state.limit_reached = true;
                continue;
            }
            state.files += 1;
            state.total_bytes += metadata.len();
            if metadata.len() > target.limits.max_file_bytes {
                state.oversized += 1;
            }
            if let Some(ext) = path
                .extension()
                .and_then(|x| x.to_str())
                .filter(|x| !x.is_empty())
            {
                *state
                    .extensions
                    .entry(ext.to_ascii_lowercase())
                    .or_default() += 1;
            }
            let mut content_hash = None;
            if let Some((ecosystem, kind)) = classify_document(&path) {
                let hash = if metadata.len() <= target.limits.max_file_bytes {
                    hash_file(&path)?
                } else {
                    hash_metadata(&rel, metadata.len())
                };
                content_hash = Some(hash.clone());
                state.ecosystems.insert(ecosystem.into());
                state.documents.push(RecognizedDocument {
                    relative_path: rel.clone(),
                    name: path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    ecosystem: ecosystem.into(),
                    kind,
                    size: metadata.len(),
                    sha256: hash,
                });
            }
            state.structural.push((rel, metadata.len(), content_hash));
        }
    }
    state.structural.sort();
    state
        .documents
        .sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    state
        .security_events
        .sort_by(|a, b| (&a.relative_path, &a.code).cmp(&(&b.relative_path, &b.code)));
    let fingerprint = snapshot_fingerprint(&state.structural);
    Ok(RepositoryInventory {
        snapshot_version: REPOSITORY_SNAPSHOT_VERSION.into(),
        structural_fingerprint: fingerprint,
        canonical_root: target.canonical_root.clone(),
        file_count: state.files,
        directory_count: state.directories,
        total_bytes: state.total_bytes,
        oversized_files: state.oversized,
        extensions: state.extensions,
        documents: state.documents,
        ecosystems: state.ecosystems.into_iter().collect(),
        exclusions: target.exclusions.clone(),
        limits: target.limits,
        status: if state.limit_reached {
            InventoryStatus::PartialLimitReached
        } else {
            InventoryStatus::Complete
        },
        security_events: state.security_events,
        gitignore_support: "deferred_builtin_exclusions_only".into(),
    })
}

pub fn inspect_revalidated(
    target: &AuthorizedRepositoryTarget,
    expected_fingerprint: &str,
) -> Result<RepositoryInventory, RepositoryError> {
    if !expected_fingerprint.starts_with("rsv1-") || expected_fingerprint.len() != 69 {
        return Err(RepositoryError::new("snapshot_invalid"));
    }
    let inventory = inspect(target)?;
    if inventory.structural_fingerprint != expected_fingerprint {
        return Err(RepositoryError::new("revalidation_required"));
    }
    Ok(inventory)
}

#[derive(Default)]
struct InventoryState {
    files: u64,
    directories: u64,
    total_bytes: u64,
    oversized: u64,
    extensions: BTreeMap<String, u64>,
    documents: Vec<RecognizedDocument>,
    ecosystems: BTreeSet<String>,
    structural: Vec<(String, u64, Option<String>)>,
    security_events: Vec<RepositorySecurityEvent>,
    limit_reached: bool,
}

fn reject_raw_path(input: &str) -> Result<(), RepositoryError> {
    let normalized = input.replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();
    if lower.starts_with("\\\\")
        || lower.starts_with(r"\\?\")
        || lower.starts_with(r"\\.\")
        || lower.starts_with(r"\device\")
        || lower.starts_with(r"\??\")
        || lower.contains(r"\pipe\")
    {
        return Err(RepositoryError::new("path_prefix_denied"));
    }
    if normalized.char_indices().any(|(i, c)| c == ':' && i != 1) {
        return Err(RepositoryError::new("alternate_data_stream_denied"));
    }
    Ok(())
}

fn reject_reparse_ancestors(path: &Path) -> Result<(), RepositoryError> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if is_link_or_reparse(&metadata) => {
                return Err(RepositoryError::new("path_reparse_denied"));
            }
            Ok(_) => {}
            Err(_) => return Err(RepositoryError::new("path_invalid")),
        }
    }
    Ok(())
}

fn is_reparse_path(path: &Path) -> Result<bool, RepositoryError> {
    fs::symlink_metadata(path)
        .map(|m| is_link_or_reparse(&m))
        .map_err(|_| RepositoryError::new("path_invalid"))
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
fn is_local_fixed_path(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    let portable = portable_path(path);
    if portable.len() < 3 || portable.as_bytes()[1] != b':' || portable.as_bytes()[2] != b'/' {
        return false;
    }
    let root = format!("{}\\", &portable[..2]);
    let wide: Vec<u16> = std::ffi::OsStr::new(&root)
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: `wide` is a valid, NUL-terminated immutable UTF-16 drive-root buffer.
    unsafe { GetDriveTypeW(wide.as_ptr()) == 3 }
}

#[cfg(not(windows))]
fn is_local_fixed_path(path: &Path) -> bool {
    path.is_absolute()
}

fn reject_forbidden_root(path: &Path) -> Result<(), RepositoryError> {
    let portable = portable_path(path);
    if path.parent().is_none()
        || (cfg!(windows)
            && portable.len() == 3
            && portable.as_bytes()[1] == b':'
            && portable.ends_with('/'))
    {
        return Err(RepositoryError::new("broad_root_denied"));
    }
    let mut forbidden = Vec::new();
    for variable in [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "USERPROFILE",
    ] {
        if let Some(value) = std::env::var_os(variable) {
            forbidden.push(PathBuf::from(value));
        }
    }
    if let Some(profile) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        forbidden.extend([
            profile.join("Desktop"),
            profile.join("Downloads"),
            profile.join("Documents"),
        ]);
    }
    let normalized = portable_path(path).to_ascii_lowercase();
    if forbidden
        .into_iter()
        .filter_map(|p| fs::canonicalize(p).ok())
        .any(|p| portable_path(&p).to_ascii_lowercase() == normalized)
    {
        return Err(RepositoryError::new("broad_root_denied"));
    }
    Ok(())
}

fn excluded(relative: &Path) -> bool {
    let parts = relative.components().filter_map(|part| match part {
        Component::Normal(v) => Some(v.to_string_lossy()),
        _ => None,
    });
    for part in parts {
        if BUILT_IN_EXCLUSIONS
            .iter()
            .any(|x| part.eq_ignore_ascii_case(x))
        {
            return true;
        }
    }
    relative
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
        .contains("tools/.staging")
}

fn classify_document(path: &Path) -> Option<(&'static str, RepositoryDocumentKind)> {
    let name = path.file_name()?.to_str()?;
    match name {
        "Cargo.toml" => Some(("rust", RepositoryDocumentKind::Manifest)),
        "Cargo.lock" => Some(("rust", RepositoryDocumentKind::Lockfile)),
        "package.json" => Some(("node", RepositoryDocumentKind::Manifest)),
        "pnpm-lock.yaml" | "package-lock.json" | "yarn.lock" => {
            Some(("node", RepositoryDocumentKind::Lockfile))
        }
        "requirements.txt" | "pyproject.toml" => Some(("python", RepositoryDocumentKind::Manifest)),
        "poetry.lock" => Some(("python", RepositoryDocumentKind::Lockfile)),
        "go.mod" => Some(("go", RepositoryDocumentKind::Manifest)),
        "go.sum" => Some(("go", RepositoryDocumentKind::Lockfile)),
        _ => None,
    }
}

fn portable_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    text.strip_prefix(r"\\?\")
        .unwrap_or(&text)
        .replace('\\', "/")
}

fn portable_relative(path: &Path) -> Result<String, RepositoryError> {
    if path
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(RepositoryError::new("path_escape"));
    }
    let value = path.to_string_lossy().replace('\\', "/");
    if value.is_empty() || value.len() > 4096 {
        return Err(RepositoryError::new("path_invalid"));
    }
    Ok(value)
}

fn hash_file(path: &Path) -> Result<String, RepositoryError> {
    let bytes = fs::read(path).map_err(|_| RepositoryError::new("inventory_read_failed"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn hash_metadata(relative: &str, size: u64) -> String {
    let mut hash = Sha256::new();
    hash.update(b"REPOSITORY_OVERSIZED_DOCUMENT_V1\0");
    hash.update(relative.as_bytes());
    hash.update(size.to_be_bytes());
    format!("{:x}", hash.finalize())
}

fn snapshot_fingerprint(files: &[(String, u64, Option<String>)]) -> String {
    let mut hash = Sha256::new();
    hash.update(REPOSITORY_SNAPSHOT_VERSION.as_bytes());
    hash.update([0]);
    for (path, size, content) in files {
        hash.update((path.len() as u32).to_be_bytes());
        hash.update(path.as_bytes());
        hash.update(size.to_be_bytes());
        if let Some(content) = content {
            hash.update(content.as_bytes());
        }
    }
    format!("rsv1-{:x}", hash.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryError {
    code: &'static str,
}

impl RepositoryError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }
    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}
impl std::error::Error for RepositoryError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary(name: &str) -> PathBuf {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let manifest = if manifest.is_absolute() {
            manifest
        } else {
            std::env::current_dir().unwrap().join(manifest)
        };
        let path = manifest
            .join("../../target/edy-repository-tests")
            .join(format!("{name}-{id}"));
        fs::create_dir_all(&path).unwrap();
        let canonical = fs::canonicalize(path).unwrap();
        let text = canonical.to_string_lossy();
        PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text))
    }

    fn authorized(path: &Path, limits: RepositoryLimits) -> AuthorizedRepositoryTarget {
        AuthorizedRepositoryTarget::authorize(
            path.to_str().unwrap(),
            TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789b1").unwrap(),
            "018f4c2a-1d3b-7abc-8def-0123456789b2",
            "2026-09-02T13:00:00Z",
            limits,
        )
        .unwrap()
    }

    #[test]
    fn inventory_is_deterministic_and_routes_manifests() {
        let root = temporary("mixed");
        fs::write(root.join("Cargo.toml"), b"[package]\nname='fixture'\n").unwrap();
        fs::write(root.join("Cargo.lock"), b"version = 4\n").unwrap();
        fs::write(root.join("package.json"), b"{}\n").unwrap();
        fs::create_dir_all(root.join("node_modules/ignored")).unwrap();
        fs::write(root.join("node_modules/ignored/token.txt"), b"ignore").unwrap();
        let target = authorized(&root, RepositoryLimits::default());
        let first = inspect(&target).unwrap();
        let second = inspect(&target).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.file_count, 3);
        assert_eq!(first.ecosystems, ["node", "rust"]);
        assert_eq!(first.documents.len(), 3);
        assert!(first.structural_fingerprint.starts_with("rsv1-"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inventory_stops_at_limits_without_reading_large_file() {
        let root = temporary("limits");
        fs::write(root.join("a.bin"), vec![0_u8; 32]).unwrap();
        fs::write(root.join("b.bin"), vec![0_u8; 32]).unwrap();
        let limits = RepositoryLimits {
            max_files: 1,
            max_total_bytes: 64,
            max_file_bytes: 8,
            ..RepositoryLimits::default()
        };
        let inventory = inspect(&authorized(&root, limits)).unwrap();
        assert_eq!(inventory.status, InventoryStatus::PartialLimitReached);
        assert_eq!(inventory.file_count, 1);
        assert_eq!(inventory.oversized_files, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authorization_rejects_missing_files_and_broad_roots() {
        let id = TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789b1").unwrap();
        let call = |path: &str| {
            AuthorizedRepositoryTarget::authorize(
                path,
                id.clone(),
                "018f4c2a-1d3b-7abc-8def-0123456789b2",
                "2026-09-02T13:00:00Z",
                RepositoryLimits::default(),
            )
        };
        assert_eq!(
            call("relative/../repo").unwrap_err().code(),
            "path_not_absolute"
        );
        assert!(call("Z:/definitely/missing/edy").is_err());
        #[cfg(windows)]
        assert_eq!(call(r"C:\").unwrap_err().code(), "broad_root_denied");
    }

    #[test]
    fn changed_repository_requires_revalidation_before_scan() {
        let root = temporary("toctou");
        fs::write(root.join("safe.txt"), "before").unwrap();
        let target = authorized(&root, RepositoryLimits::default());
        let preview = inspect(&target).unwrap();
        fs::write(root.join("safe.txt"), "after-and-different-size").unwrap();
        assert_eq!(
            inspect_revalidated(&target, &preview.structural_fingerprint)
                .unwrap_err()
                .code(),
            "revalidation_required"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn nested_reparse_is_skipped_with_security_event() {
        let root = temporary("nested-reparse");
        let outside = temporary("outside");
        fs::write(outside.join("escape.txt"), "must-not-be-read").unwrap();
        let link = root.join("nested-link");
        if std::os::windows::fs::symlink_dir(&outside, &link).is_err() {
            eprintln!(
                "SKIP_PLATFORM_REASON=Windows symlink privilege unavailable; junction and mount-point safety remains enforced by the reparse attribute policy"
            );
            fs::remove_dir_all(root).unwrap();
            fs::remove_dir_all(outside).unwrap();
            return;
        }
        let inventory = inspect(&authorized(&root, RepositoryLimits::default())).unwrap();
        assert_eq!(inventory.file_count, 0);
        assert!(
            inventory
                .security_events
                .iter()
                .any(|event| event.code == "reparse_point_skipped")
        );
        fs::remove_dir(&link).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn junction_root_is_denied_and_nested_junction_is_never_traversed() {
        use std::process::Command;

        let root = temporary("junction-root");
        let outside = temporary("junction-outside");
        fs::write(outside.join("escape.txt"), "must-not-be-read").unwrap();
        let junction = root.join("nested-junction");
        let status = Command::new("cmd.exe")
            .args([
                "/d",
                "/c",
                "mklink",
                "/J",
                junction.to_str().unwrap(),
                outside.to_str().unwrap(),
            ])
            .status();
        if !status.is_ok_and(|status| status.success()) {
            eprintln!(
                "SKIP_PLATFORM_REASON=Windows junction creation unavailable; no host setting was changed"
            );
            fs::remove_dir_all(root).unwrap();
            fs::remove_dir_all(outside).unwrap();
            return;
        }
        let id = TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789b1").unwrap();
        let root_error = AuthorizedRepositoryTarget::authorize(
            junction.to_str().unwrap(),
            id,
            "018f4c2a-1d3b-7abc-8def-0123456789b2",
            "2026-09-02T13:00:00Z",
            RepositoryLimits::default(),
        )
        .unwrap_err();
        assert_eq!(root_error.code(), "path_reparse_denied");
        let inventory = inspect(&authorized(&root, RepositoryLimits::default())).unwrap();
        assert_eq!(inventory.file_count, 0);
        assert!(
            inventory
                .security_events
                .iter()
                .any(|event| event.code == "reparse_point_skipped")
        );
        fs::remove_dir(&junction).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn authorization_rejects_unc_ads_and_symlink_root() {
        let id = TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789b1").unwrap();
        let call = |path: &str| {
            AuthorizedRepositoryTarget::authorize(
                path,
                id.clone(),
                "018f4c2a-1d3b-7abc-8def-0123456789b2",
                "2026-09-02T13:00:00Z",
                RepositoryLimits::default(),
            )
        };
        assert_eq!(
            call(r"\\server\share").unwrap_err().code(),
            "path_prefix_denied"
        );
        assert_eq!(
            call(r"C:\repo:stream").unwrap_err().code(),
            "alternate_data_stream_denied"
        );
        let root = temporary("link");
        let link = root.with_extension("link");
        if std::os::windows::fs::symlink_dir(&root, &link).is_ok() {
            assert_eq!(
                call(link.to_str().unwrap()).unwrap_err().code(),
                "path_reparse_denied"
            );
            fs::remove_dir(&link).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
}
