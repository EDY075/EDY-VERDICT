use crate::{
    RecoveryClassification, RecoveryInspection, RecoveryJournal, RemediationPrecondition,
    sha256_hex, valid_sha256,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const MAX_REMEDIATION_FILE_BYTES: u64 = 1024 * 1024;
const ALLOWED_EXTENSIONS: &[&str] = &["toml", "json", "yaml", "yml", "ini", "conf", "txt"];
const BACKUP_MAGIC: &[u8] = b"EDYVERDICT-REMEDIATION-BACKUP-V1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedTextTarget {
    pub repository_root: PathBuf,
    pub canonical_path: PathBuf,
    pub canonical_path_safe: String,
    pub stable_identity: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedExactEdit {
    pub expected_text: String,
    pub replacement_text: String,
    pub expected_occurrences: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyRequest<'a> {
    pub action_id: &'a str,
    pub plan_sha256: &'a str,
    pub target: &'a AuthorizedTextTarget,
    pub precondition: &'a RemediationPrecondition,
    pub edit: &'a ApprovedExactEdit,
    pub backup_root: &'a Path,
    pub backup_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackRequest<'a> {
    pub action_id: &'a str,
    pub expected_action_id: &'a str,
    pub expected_plan_sha256: &'a str,
    pub target: &'a Path,
    pub expected_original_stable_identity: &'a str,
    pub expected_original_sha256: &'a str,
    pub expected_patched_stable_identity: &'a str,
    pub expected_patched_sha256: &'a str,
    pub backup_root: &'a Path,
    pub backup_id: &'a str,
    pub expected_backup_sha256: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppliedFile {
    pub original_sha256: String,
    pub resulting_sha256: String,
    pub backup_id: String,
    pub backup_sha256: String,
    pub resulting_stable_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutorError {
    PathRefused,
    TargetChanged,
    SensitiveContent,
    InvalidEncoding,
    InvalidRule,
    PermissionBlocked,
    BackupUnsafe,
    BackupIntegrity,
    AtomicReplaceFailed,
    RollbackConflict,
    Io,
}

impl ExecutorError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PathRefused => "remediation_path_refused",
            Self::TargetChanged => "target_changed",
            Self::SensitiveContent => "sensitive_content_guidance_only",
            Self::InvalidEncoding => "unsupported_text_encoding",
            Self::InvalidRule => "approved_rule_precondition_failed",
            Self::PermissionBlocked => "remediation_blocked_by_permission",
            Self::BackupUnsafe => "backup_path_refused",
            Self::BackupIntegrity => "backup_integrity_failed",
            Self::AtomicReplaceFailed => "atomic_replace_failed",
            Self::RollbackConflict => "rollback_conflict",
            Self::Io => "remediation_io_failed",
        }
    }
}

impl std::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ExecutorError {}

pub fn authorize_text_target(
    repository_root: &Path,
    requested_target: &Path,
) -> Result<AuthorizedTextTarget, ExecutorError> {
    reject_lexical(repository_root)?;
    reject_lexical(requested_target)?;
    reject_reparse_chain(repository_root)?;
    reject_reparse_chain(requested_target)?;
    let root = normalized_canonical(repository_root)?;
    let target = normalized_canonical(requested_target)?;
    if !target.starts_with(&root) || target == root || !local_fixed_path(&target) {
        return Err(ExecutorError::PathRefused);
    }
    reject_reparse_chain(&target)?;
    let metadata = fs::symlink_metadata(&target).map_err(|_| ExecutorError::PathRefused)?;
    if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_REMEDIATION_FILE_BYTES {
        return Err(ExecutorError::PathRefused);
    }
    let extension = target
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if !ALLOWED_EXTENSIONS
        .iter()
        .any(|allowed| extension.eq_ignore_ascii_case(allowed))
    {
        return Err(ExecutorError::PathRefused);
    }
    let bytes = read_bounded(&target)?;
    std::str::from_utf8(&bytes).map_err(|_| ExecutorError::InvalidEncoding)?;
    if contains_sensitive_plaintext(&bytes) {
        return Err(ExecutorError::SensitiveContent);
    }
    Ok(AuthorizedTextTarget {
        repository_root: root,
        canonical_path_safe: portable_path(&target),
        stable_identity: stable_identity(&target)?,
        sha256: sha256_hex(&bytes),
        size: metadata.len(),
        canonical_path: target,
    })
}

pub fn revalidate(target: &AuthorizedTextTarget) -> Result<Vec<u8>, ExecutorError> {
    reject_reparse_chain(&target.canonical_path)?;
    let canonical =
        normalized_canonical(&target.canonical_path).map_err(|_| ExecutorError::TargetChanged)?;
    if canonical != target.canonical_path || !canonical.starts_with(&target.repository_root) {
        return Err(ExecutorError::TargetChanged);
    }
    let metadata = fs::symlink_metadata(&canonical).map_err(|_| ExecutorError::TargetChanged)?;
    if !metadata.is_file()
        || is_reparse(&metadata)
        || metadata.len() != target.size
        || stable_identity(&canonical)? != target.stable_identity
    {
        return Err(ExecutorError::TargetChanged);
    }
    let bytes = read_bounded(&canonical).map_err(|_| ExecutorError::TargetChanged)?;
    if sha256_hex(&bytes) != target.sha256 {
        return Err(ExecutorError::TargetChanged);
    }
    Ok(bytes)
}

pub fn preview_exact_edit(
    target: &AuthorizedTextTarget,
    edit: &ApprovedExactEdit,
) -> Result<(String, Vec<u8>, u32), ExecutorError> {
    let bytes = revalidate(target)?;
    let current = std::str::from_utf8(&bytes).map_err(|_| ExecutorError::InvalidEncoding)?;
    if contains_sensitive_plaintext(&bytes) {
        return Err(ExecutorError::SensitiveContent);
    }
    validate_edit(edit)?;
    let count = current.matches(&edit.expected_text).count();
    if count != usize::from(edit.expected_occurrences) || count != 1 {
        return Err(ExecutorError::InvalidRule);
    }
    let index = current
        .find(&edit.expected_text)
        .ok_or(ExecutorError::InvalidRule)?;
    let line = current[..index]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count() as u32
        + 1;
    let patched = current
        .replacen(&edit.expected_text, &edit.replacement_text, 1)
        .into_bytes();
    if patched.len() as u64 > MAX_REMEDIATION_FILE_BYTES || patched == bytes {
        return Err(ExecutorError::InvalidRule);
    }
    let old = sanitize_diff_line(&edit.expected_text);
    let new = sanitize_diff_line(&edit.replacement_text);
    let diff = format!(
        "--- a/{name}\n+++ b/{name}\n@@ -{line},1 +{line},1 @@\n-{old}\n+{new}\n",
        name = target
            .canonical_path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("authorized-config")
    );
    if diff.len() > 4096 {
        return Err(ExecutorError::InvalidRule);
    }
    Ok((diff, patched, line))
}

pub fn apply_exact_edit(request: &ApplyRequest<'_>) -> Result<AppliedFile, ExecutorError> {
    if request.precondition.canonical_path != request.target.canonical_path_safe
        || request.precondition.stable_identity != request.target.stable_identity
        || request.precondition.expected_sha256 != request.target.sha256
        || request.precondition.expected_size != request.target.size
        || request.precondition.expected_anchor_sha256
            != sha256_hex(request.edit.expected_text.as_bytes())
    {
        return Err(ExecutorError::TargetChanged);
    }
    let original = revalidate(request.target)?;
    let (_, patched, _) = preview_exact_edit(request.target, request.edit)?;
    prepare_backup_root(request.backup_root, &request.target.repository_root)?;
    if !valid_backup_id(request.backup_id) {
        return Err(ExecutorError::BackupUnsafe);
    }
    let backup_path = request
        .backup_root
        .join(format!("{}.bin", request.backup_id));
    let backup_bytes = encode_backup(
        request.action_id,
        request.plan_sha256,
        &request.target.stable_identity,
        &original,
    )?;
    write_new_synced(&backup_path, &backup_bytes, None).map_err(map_backup_error)?;
    let backup_sha256 = sha256_hex(&backup_bytes);
    if sha256_hex(&read_bounded_backup(&backup_path)?) != backup_sha256 {
        return Err(ExecutorError::BackupIntegrity);
    }
    let temp = request
        .target
        .canonical_path
        .with_file_name(format!(".edy-remediation-{}.tmp", uuid::Uuid::now_v7()));
    let permissions = fs::metadata(&request.target.canonical_path)
        .map_err(|_| ExecutorError::TargetChanged)?
        .permissions();
    write_new_synced(&temp, &patched, Some(permissions)).map_err(map_target_write_error)?;
    if sha256_hex(&read_bounded(&temp).map_err(|_| ExecutorError::Io)?) != sha256_hex(&patched) {
        return Err(ExecutorError::Io);
    }
    // Final TOCTOU barrier immediately before the atomic replacement.
    revalidate(request.target)?;
    atomic_replace(&temp, &request.target.canonical_path)?;
    let result = read_bounded(&request.target.canonical_path).map_err(|_| ExecutorError::Io)?;
    if result != patched {
        return Err(ExecutorError::AtomicReplaceFailed);
    }
    Ok(AppliedFile {
        original_sha256: sha256_hex(&original),
        resulting_sha256: sha256_hex(&result),
        backup_id: request.backup_id.to_owned(),
        backup_sha256,
        resulting_stable_identity: stable_identity(&request.target.canonical_path)?,
    })
}

pub fn rollback_exact_edit(request: &RollbackRequest<'_>) -> Result<String, ExecutorError> {
    if request.action_id != request.expected_action_id || !valid_backup_id(request.backup_id) {
        return Err(ExecutorError::BackupUnsafe);
    }
    reject_reparse_chain(request.target)?;
    prepare_existing_backup_root(request.backup_root)?;
    let backup = request
        .backup_root
        .join(format!("{}.bin", request.backup_id));
    if backup.parent() != Some(request.backup_root) {
        return Err(ExecutorError::BackupUnsafe);
    }
    reject_reparse_chain(&backup)?;
    let current = read_bounded(request.target).map_err(|_| ExecutorError::RollbackConflict)?;
    if stable_identity(request.target).map_err(|_| ExecutorError::RollbackConflict)?
        != request.expected_patched_stable_identity
        || sha256_hex(&current) != request.expected_patched_sha256
    {
        return Err(ExecutorError::RollbackConflict);
    }
    let envelope = read_bounded_backup(&backup)?;
    if sha256_hex(&envelope) != request.expected_backup_sha256 {
        return Err(ExecutorError::BackupIntegrity);
    }
    let original = decode_backup(
        &envelope,
        request.action_id,
        request.expected_plan_sha256,
        request.expected_original_stable_identity,
        request.expected_original_sha256,
    )?;
    let temp = request
        .target
        .with_file_name(format!(".edy-rollback-{}.tmp", uuid::Uuid::now_v7()));
    let permissions = fs::metadata(request.target)
        .map_err(|_| ExecutorError::RollbackConflict)?
        .permissions();
    write_new_synced(&temp, &original, Some(permissions)).map_err(map_target_write_error)?;
    // Revalidate again after backup/temp preparation, just as apply does.
    // This is not an atomic compare-and-swap against a concurrent hostile writer.
    reject_reparse_chain(request.target)?;
    if stable_identity(request.target).map_err(|_| ExecutorError::RollbackConflict)?
        != request.expected_patched_stable_identity
        || sha256_hex(&read_bounded(request.target).map_err(|_| ExecutorError::RollbackConflict)?)
            != request.expected_patched_sha256
    {
        return Err(ExecutorError::RollbackConflict);
    }
    atomic_replace(&temp, request.target)?;
    let restored = read_bounded(request.target).map_err(|_| ExecutorError::Io)?;
    if restored != original {
        return Err(ExecutorError::AtomicReplaceFailed);
    }
    Ok(sha256_hex(&restored))
}

fn valid_backup_id(value: &str) -> bool {
    value.strip_prefix("backup-").is_some_and(|suffix| {
        suffix.len() == 36
            && suffix.bytes().all(|byte| {
                (byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) || byte == b'-'
            })
            && uuid::Uuid::parse_str(suffix).is_ok()
    })
}

fn encode_backup(
    action_id: &str,
    plan_sha256: &str,
    stable_identity: &str,
    original: &[u8],
) -> Result<Vec<u8>, ExecutorError> {
    if action_id.is_empty()
        || action_id.len() > 128
        || !valid_sha256(plan_sha256)
        || stable_identity.is_empty()
        || stable_identity.len() > 256
        || original.len() as u64 > MAX_REMEDIATION_FILE_BYTES
        || action_id
            .chars()
            .chain(stable_identity.chars())
            .any(char::is_control)
    {
        return Err(ExecutorError::BackupUnsafe);
    }
    let original_sha256 = sha256_hex(original);
    let mut output = Vec::with_capacity(BACKUP_MAGIC.len() + 512 + original.len());
    output.extend_from_slice(BACKUP_MAGIC);
    for value in [action_id, plan_sha256, stable_identity, &original_sha256] {
        let bytes = value.as_bytes();
        let length = u16::try_from(bytes.len()).map_err(|_| ExecutorError::BackupUnsafe)?;
        output.extend_from_slice(&length.to_le_bytes());
        output.extend_from_slice(bytes);
    }
    output.extend_from_slice(&(original.len() as u64).to_le_bytes());
    output.extend_from_slice(original);
    Ok(output)
}

fn decode_backup(
    bytes: &[u8],
    expected_action_id: &str,
    expected_plan_sha256: &str,
    expected_stable_identity: &str,
    expected_original_sha256: &str,
) -> Result<Vec<u8>, ExecutorError> {
    if !bytes.starts_with(BACKUP_MAGIC) {
        return Err(ExecutorError::BackupIntegrity);
    }
    let mut offset = BACKUP_MAGIC.len();
    let mut fields = Vec::with_capacity(4);
    for _ in 0..4 {
        if offset + 2 > bytes.len() {
            return Err(ExecutorError::BackupIntegrity);
        }
        let length = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        if offset + length > bytes.len() {
            return Err(ExecutorError::BackupIntegrity);
        }
        fields.push(
            std::str::from_utf8(&bytes[offset..offset + length])
                .map_err(|_| ExecutorError::BackupIntegrity)?,
        );
        offset += length;
    }
    if offset + 8 > bytes.len() {
        return Err(ExecutorError::BackupIntegrity);
    }
    let length = u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .map_err(|_| ExecutorError::BackupIntegrity)?,
    ) as usize;
    offset += 8;
    if length > MAX_REMEDIATION_FILE_BYTES as usize || offset + length != bytes.len() {
        return Err(ExecutorError::BackupIntegrity);
    }
    let original = &bytes[offset..];
    if fields
        != [
            expected_action_id,
            expected_plan_sha256,
            expected_stable_identity,
            expected_original_sha256,
        ]
        || sha256_hex(original) != expected_original_sha256
    {
        return Err(ExecutorError::BackupIntegrity);
    }
    Ok(original.to_vec())
}

fn read_bounded_backup(path: &Path) -> Result<Vec<u8>, ExecutorError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ExecutorError::BackupIntegrity)?;
    if !metadata.is_file()
        || is_reparse(&metadata)
        || metadata.len() > MAX_REMEDIATION_FILE_BYTES + 1024
    {
        return Err(ExecutorError::BackupIntegrity);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|_| ExecutorError::BackupIntegrity)?
        .take(MAX_REMEDIATION_FILE_BYTES + 1025)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutorError::BackupIntegrity)?;
    if bytes.len() as u64 > MAX_REMEDIATION_FILE_BYTES + 1024 {
        return Err(ExecutorError::BackupIntegrity);
    }
    Ok(bytes)
}

pub fn current_sha256(path: &Path) -> Result<String, ExecutorError> {
    Ok(sha256_hex(&read_bounded(path)?))
}

/// Inspects an interrupted action without modifying the target or backup.
pub fn inspect_recovery_journal(
    journal: &RecoveryJournal,
) -> Result<RecoveryInspection, ExecutorError> {
    if !valid_sha256(&journal.original_sha256)
        || !valid_sha256(&journal.patched_sha256)
        || journal.repository_root_safe.is_empty()
    {
        return Err(ExecutorError::BackupUnsafe);
    }
    let requested_root = PathBuf::from(&journal.repository_root_safe);
    let requested_target = PathBuf::from(&journal.target_safe);
    reject_lexical(&requested_root)?;
    reject_lexical(&requested_target)?;
    reject_reparse_chain(&requested_root)?;
    reject_reparse_chain(&requested_target)?;
    let root = normalized_canonical(&requested_root)?;
    let target = normalized_canonical(&requested_target)?;
    if target == root || !target.starts_with(&root) || !local_fixed_path(&target) {
        return Err(ExecutorError::PathRefused);
    }
    let current = sha256_hex(&read_bounded(&target)?);
    let classification = if current == journal.original_sha256 {
        RecoveryClassification::OriginalPresent
    } else if current == journal.patched_sha256 {
        RecoveryClassification::PatchedPresent
    } else {
        RecoveryClassification::UnknownState
    };
    let backup_integrity = match (&journal.backup_id, &journal.backup_sha256) {
        (Some(id), Some(expected)) if valid_backup_id(id) && valid_sha256(expected) => {
            let backup_root = root.join(".local").join("remediation-backups");
            let backup = backup_root.join(format!("{id}.bin"));
            let valid = prepare_existing_backup_root(&backup_root).is_ok()
                && reject_reparse_chain(&backup).is_ok()
                && read_bounded_backup(&backup).is_ok_and(|bytes| {
                    sha256_hex(&bytes) == *expected
                        && decode_backup(
                            &bytes,
                            &journal.action_id,
                            &journal.plan_sha256,
                            &journal.original_stable_identity,
                            &journal.original_sha256,
                        )
                        .is_ok()
                });
            Some(valid)
        }
        (None, None) => None,
        _ => Some(false),
    };
    let manual_review_required = classification == RecoveryClassification::UnknownState
        || (classification == RecoveryClassification::PatchedPresent
            && backup_integrity != Some(true));
    Ok(RecoveryInspection {
        classification,
        backup_integrity,
        manual_review_required,
    })
}

pub fn contains_sensitive_plaintext(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return true;
    };
    let lower = text.to_ascii_lowercase();
    if [
        "-----begin ",
        "bearer ",
        "edy_fake_secret_level6",
        "edy_fake_cookie_level6",
        "edy_fake_query_level6",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return true;
    }
    text.lines().any(|line| {
        let value = line.to_ascii_lowercase();
        let assignment = value.contains('=') || value.contains(':');
        assignment
            && [
                "api_key",
                "apikey",
                "password",
                "passwd",
                "secret",
                "bearer ",
                "private_key",
                "cookie",
                "token",
                "credential",
                "access_key",
                "authorization",
            ]
            .iter()
            .any(|marker| value.contains(marker))
    })
}

fn validate_edit(edit: &ApprovedExactEdit) -> Result<(), ExecutorError> {
    if edit.expected_text.is_empty()
        || edit.replacement_text.is_empty()
        || edit.expected_text.len() > 512
        || edit.replacement_text.len() > 512
        || edit.expected_occurrences != 1
        || edit.expected_text.contains(['\r', '\n'])
        || edit.replacement_text.contains(['\r', '\n'])
    {
        return Err(ExecutorError::InvalidRule);
    }
    Ok(())
}

fn sanitize_diff_line(value: &str) -> String {
    value
        .chars()
        .take(512)
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, ExecutorError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ExecutorError::Io)?;
    if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_REMEDIATION_FILE_BYTES {
        return Err(ExecutorError::PathRefused);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|_| ExecutorError::Io)?
        .take(MAX_REMEDIATION_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutorError::Io)?;
    if bytes.len() as u64 > MAX_REMEDIATION_FILE_BYTES {
        return Err(ExecutorError::PathRefused);
    }
    Ok(bytes)
}

fn write_new_synced(
    path: &Path,
    bytes: &[u8],
    permissions: Option<fs::Permissions>,
) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    if let Some(permissions) = permissions {
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn prepare_backup_root(backup_root: &Path, repository_root: &Path) -> Result<(), ExecutorError> {
    reject_lexical(backup_root)?;
    let expected = repository_root.join(".local").join("remediation-backups");
    if backup_root != expected {
        return Err(ExecutorError::BackupUnsafe);
    }
    if let Some(parent) = backup_root.parent()
        && parent.exists()
    {
        reject_reparse_chain(parent)?;
    }
    fs::create_dir_all(backup_root).map_err(|_| ExecutorError::BackupUnsafe)?;
    prepare_existing_backup_root(backup_root)
}

fn prepare_existing_backup_root(backup_root: &Path) -> Result<(), ExecutorError> {
    reject_reparse_chain(backup_root)?;
    let metadata = fs::symlink_metadata(backup_root).map_err(|_| ExecutorError::BackupUnsafe)?;
    if !metadata.is_dir() || is_reparse(&metadata) {
        return Err(ExecutorError::BackupUnsafe);
    }
    Ok(())
}

fn reject_lexical(path: &Path) -> Result<(), ExecutorError> {
    let value = path.to_string_lossy();
    let lower = value.to_ascii_lowercase();
    if value.contains('\0')
        || lower.starts_with("\\\\")
        || lower.starts_with("//")
        || lower.starts_with("\\\\?\\")
        || lower.starts_with("\\\\.\\")
    {
        return Err(ExecutorError::PathRefused);
    }
    #[cfg(windows)]
    {
        let without_drive = value.get(2..).unwrap_or(&value);
        if without_drive.contains(':') {
            return Err(ExecutorError::PathRefused);
        }
    }
    Ok(())
}

fn reject_reparse_chain(path: &Path) -> Result<(), ExecutorError> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() || is_reparse(&metadata) => {
                return Err(ExecutorError::PathRefused);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ExecutorError::PathRefused),
        }
        current = candidate.parent();
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}
#[cfg(not(windows))]
fn is_reparse(_: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn stable_identity(path: &Path) -> Result<String, ExecutorError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let file = File::open(path).map_err(|_| ExecutorError::Io)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the owned File provides a live handle and the initialized output lives through
    // the call. No handle ownership is transferred and a zero result is rejected.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) };
    if ok == 0 {
        return Err(ExecutorError::Io);
    }
    let file_id =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok(format!(
        "winfile-v1-{:08x}-{file_id:016x}",
        information.dwVolumeSerialNumber
    ))
}
#[cfg(not(windows))]
fn stable_identity(path: &Path) -> Result<String, ExecutorError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(path).map_err(|_| ExecutorError::Io)?;
    Ok(format!(
        "unixfile-v1-{:016x}-{:016x}",
        metadata.dev(),
        metadata.ino()
    ))
}

#[cfg(windows)]
fn local_fixed_path(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumePathNameW};
    const DRIVE_FIXED: u32 = 3;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut root = vec![0_u16; 1024];
    // SAFETY: input is NUL-terminated and the writable root buffer lives through the call.
    let ok = unsafe { GetVolumePathNameW(wide.as_ptr(), root.as_mut_ptr(), root.len() as u32) };
    // SAFETY: on success Windows initialized a NUL-terminated volume path in `root`.
    ok != 0 && unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_FIXED
}
#[cfg(not(windows))]
fn local_fixed_path(_: &Path) -> bool {
    true
}

fn portable_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn normalized_canonical(path: &Path) -> Result<PathBuf, ExecutorError> {
    let canonical = fs::canonicalize(path).map_err(|_| ExecutorError::PathRefused)?;
    #[cfg(windows)]
    {
        let value = canonical.to_string_lossy();
        if let Some(stripped) = value.strip_prefix(r"\\?\UNC\") {
            return Ok(PathBuf::from(format!(r"\\{stripped}")));
        }
        if let Some(stripped) = value.strip_prefix(r"\\?\") {
            return Ok(PathBuf::from(stripped));
        }
    }
    Ok(canonical)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, target: &Path) -> Result<(), ExecutorError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both buffers are valid NUL-terminated UTF-16 paths. Backup and reserved pointers
    // are null, and this wrapper exposes only the already-authorized source/target pair.
    let result = unsafe {
        ReplaceFileW(
            target.as_ptr(),
            source.as_ptr(),
            std::ptr::null(),
            // REPLACEFILE_WRITE_THROUGH is explicitly unsupported by Windows.
            // Temp contents were synced; crash durability is a separate gate.
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        Err(ExecutorError::AtomicReplaceFailed)
    } else {
        Ok(())
    }
}
#[cfg(not(windows))]
fn atomic_replace(source: &Path, target: &Path) -> Result<(), ExecutorError> {
    fs::rename(source, target).map_err(|_| ExecutorError::AtomicReplaceFailed)
}

fn map_backup_error(error: std::io::Error) -> ExecutorError {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        ExecutorError::PermissionBlocked
    } else {
        ExecutorError::BackupUnsafe
    }
}
fn map_target_write_error(error: std::io::Error) -> ExecutorError {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        ExecutorError::PermissionBlocked
    } else {
        ExecutorError::Io
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "edy-level6-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn exact_patch_preview_is_bounded_and_target_change_fails_closed() {
        let root = root("preview");
        let target = root.join("security-config.toml");
        fs::write(&target, "insecure_test_mode = true\n").unwrap();
        let authorized = authorize_text_target(&root, &target).unwrap();
        let edit = ApprovedExactEdit {
            expected_text: "insecure_test_mode = true".into(),
            replacement_text: "insecure_test_mode = false".into(),
            expected_occurrences: 1,
        };
        let (diff, _, line) = preview_exact_edit(&authorized, &edit).unwrap();
        assert_eq!(line, 1);
        assert!(diff.contains("+insecure_test_mode = false"));
        fs::write(&target, "insecure_test_mode = changed\n").unwrap();
        assert_eq!(revalidate(&authorized), Err(ExecutorError::TargetChanged));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sensitive_and_non_config_targets_are_guidance_only() {
        for text in [
            concat!("-----BEGIN ", "PRIVATE KEY-----\nsynthetic-material"),
            "Authorization Bearer synthetic-material",
            "access_token = synthetic-material",
            "EDY_FAKE_COOKIE_LEVEL6",
            "EDY_FAKE_QUERY_LEVEL6",
        ] {
            assert!(contains_sensitive_plaintext(text.as_bytes()));
        }
        let root = root("sensitive");
        let sensitive = root.join("security-config.toml");
        fs::write(&sensitive, "api_key = \"EDY_FAKE_SECRET_LEVEL6\"\n").unwrap();
        assert_eq!(
            authorize_text_target(&root, &sensitive),
            Err(ExecutorError::SensitiveContent)
        );
        let binary = root.join("program.exe");
        fs::write(&binary, b"MZ").unwrap();
        assert_eq!(
            authorize_text_target(&root, &binary),
            Err(ExecutorError::PathRefused)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn path_and_content_attack_matrix_is_refused() {
        let root = root("path-attacks");
        let target = root.join("security-config.toml");
        fs::write(&target, "flag = true\n").unwrap();
        let outside = root
            .parent()
            .unwrap()
            .join(format!("outside-{}.toml", uuid::Uuid::now_v7()));
        fs::write(&outside, "flag = true\n").unwrap();
        assert_eq!(
            authorize_text_target(&root, &outside),
            Err(ExecutorError::PathRefused)
        );
        assert_eq!(
            authorize_text_target(&root, Path::new(r"\\server\share\config.toml")),
            Err(ExecutorError::PathRefused)
        );
        assert_eq!(
            authorize_text_target(&root, Path::new(r"\\?\C:\config.toml")),
            Err(ExecutorError::PathRefused)
        );
        assert_eq!(
            authorize_text_target(
                &root,
                &PathBuf::from(format!("{}:stream", target.display()))
            ),
            Err(ExecutorError::PathRefused)
        );
        let invalid = root.join("invalid.toml");
        fs::write(&invalid, [0xff, 0xfe]).unwrap();
        assert_eq!(
            authorize_text_target(&root, &invalid),
            Err(ExecutorError::InvalidEncoding)
        );
        let oversized = root.join("oversized.toml");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_REMEDIATION_FILE_BYTES + 1)
            .unwrap();
        assert_eq!(
            authorize_text_target(&root, &oversized),
            Err(ExecutorError::PathRefused)
        );
        let authorized = authorize_text_target(&root, &target).unwrap();
        let ambiguous = ApprovedExactEdit {
            expected_text: "flag".into(),
            replacement_text: "mode".into(),
            expected_occurrences: 1,
        };
        fs::write(&target, "flag = true\nflag = false\n").unwrap();
        assert_eq!(
            preview_exact_edit(&authorized, &ambiguous),
            Err(ExecutorError::TargetChanged)
        );
        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rollback_backup_attack_matrix_fails_closed() {
        let root = root("backup-attacks");
        let target = root.join("security-config.toml");
        fs::write(&target, "insecure_test_mode = true\n").unwrap();
        let original = fs::read(&target).unwrap();
        let authorized = authorize_text_target(&root, &target).unwrap();
        let edit = ApprovedExactEdit {
            expected_text: "insecure_test_mode = true".into(),
            replacement_text: "insecure_test_mode = false".into(),
            expected_occurrences: 1,
        };
        let precondition = RemediationPrecondition {
            canonical_path: authorized.canonical_path_safe.clone(),
            stable_identity: authorized.stable_identity.clone(),
            expected_sha256: authorized.sha256.clone(),
            expected_size: authorized.size,
            expected_anchor_sha256: sha256_hex(edit.expected_text.as_bytes()),
        };
        let backup = root.join(".local/remediation-backups");
        let backup_id = format!("backup-{}", uuid::Uuid::now_v7());
        let applied = apply_exact_edit(&ApplyRequest {
            action_id: "action",
            plan_sha256: &"a".repeat(64),
            target: &authorized,
            precondition: &precondition,
            edit: &edit,
            backup_root: &backup,
            backup_id: &backup_id,
        })
        .unwrap();
        let patched = fs::read(&target).unwrap();
        let rollback =
            |action_id: &str, expected_action_id: &str, backup_id: &str, digest: &str| {
                rollback_exact_edit(&RollbackRequest {
                    action_id,
                    expected_action_id,
                    expected_plan_sha256: &"a".repeat(64),
                    target: &target,
                    expected_original_stable_identity: &authorized.stable_identity,
                    expected_original_sha256: &authorized.sha256,
                    expected_patched_stable_identity: &applied.resulting_stable_identity,
                    expected_patched_sha256: &applied.resulting_sha256,
                    backup_root: &backup,
                    backup_id,
                    expected_backup_sha256: digest,
                })
            };
        for result in [
            rollback(
                "wrong",
                "action",
                &applied.backup_id,
                &applied.backup_sha256,
            ),
            rollback(
                "action",
                "action",
                "backup-../escape",
                &applied.backup_sha256,
            ),
            rollback("action", "action", &applied.backup_id, &"0".repeat(64)),
        ] {
            assert!(result.is_err());
            assert_eq!(fs::read(&target).unwrap(), patched);
        }
        let swapped = encode_backup(
            "other-action",
            &"a".repeat(64),
            &authorized.stable_identity,
            &original,
        )
        .unwrap();
        fs::write(backup.join(format!("{}.bin", applied.backup_id)), &swapped).unwrap();
        assert_eq!(
            rollback(
                "action",
                "action",
                &applied.backup_id,
                &sha256_hex(&swapped)
            ),
            Err(ExecutorError::BackupIntegrity)
        );
        assert_eq!(fs::read(&target).unwrap(), patched);
        fs::write(backup.join(format!("{}.bin", applied.backup_id)), "corrupt").unwrap();
        assert_eq!(
            rollback(
                "action",
                "action",
                &applied.backup_id,
                &applied.backup_sha256
            ),
            Err(ExecutorError::BackupIntegrity)
        );
        assert_eq!(fs::read(&target).unwrap(), patched);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_inspection_is_read_only_and_checks_backup_integrity() {
        let root = root("recovery-inspection");
        let target = root.join("security-config.toml");
        fs::write(&target, "insecure_test_mode = true\n").unwrap();
        let authorized = authorize_text_target(&root, &target).unwrap();
        let edit = ApprovedExactEdit {
            expected_text: "insecure_test_mode = true".into(),
            replacement_text: "insecure_test_mode = false".into(),
            expected_occurrences: 1,
        };
        let precondition = RemediationPrecondition {
            canonical_path: authorized.canonical_path_safe.clone(),
            stable_identity: authorized.stable_identity.clone(),
            expected_sha256: authorized.sha256.clone(),
            expected_size: authorized.size,
            expected_anchor_sha256: sha256_hex(edit.expected_text.as_bytes()),
        };
        let backup = root.join(".local/remediation-backups");
        let backup_id = format!("backup-{}", uuid::Uuid::now_v7());
        let applied = apply_exact_edit(&ApplyRequest {
            action_id: "action",
            plan_sha256: &"a".repeat(64),
            target: &authorized,
            precondition: &precondition,
            edit: &edit,
            backup_root: &backup,
            backup_id: &backup_id,
        })
        .unwrap();
        let journal = RecoveryJournal {
            action_id: "action".into(),
            plan_sha256: "a".repeat(64),
            target_safe: authorized.canonical_path_safe.clone(),
            repository_root_safe: authorized
                .repository_root
                .to_string_lossy()
                .replace('\\', "/"),
            original_sha256: applied.original_sha256.clone(),
            original_stable_identity: authorized.stable_identity.clone(),
            patched_sha256: applied.resulting_sha256.clone(),
            backup_id: Some(applied.backup_id.clone()),
            backup_sha256: Some(applied.backup_sha256.clone()),
            state: crate::RemediationActionState::Applying,
            manual_review_required: false,
        };
        let before = fs::read(&target).unwrap();
        let inspected = inspect_recovery_journal(&journal).unwrap();
        assert_eq!(
            inspected.classification,
            RecoveryClassification::PatchedPresent
        );
        assert_eq!(inspected.backup_integrity, Some(true));
        assert!(!inspected.manual_review_required);
        assert_eq!(fs::read(&target).unwrap(), before);
        fs::write(backup.join(format!("{}.bin", applied.backup_id)), "corrupt").unwrap();
        let inspected = inspect_recovery_journal(&journal).unwrap();
        assert_eq!(inspected.backup_integrity, Some(false));
        assert!(inspected.manual_review_required);
        assert_eq!(fs::read(&target).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }
}
