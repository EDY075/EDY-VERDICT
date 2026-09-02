//! Level 2 file and binary security boundary.
//!
//! A caller must preview and explicitly authorize one regular local file. Analysis reopens that
//! exact identity once, streams hashes from the same handle, performs bounded parsing, and checks
//! identity/state again before producing a verdict. No external engine or network provider runs.

use edy_core::{Availability, Confidence, FilePrivacyMode, Severity, Sha256Digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

pub const FILE_SNAPSHOT_VERSION: &str = "FILE_SNAPSHOT_V1";
pub const DEFAULT_MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;
pub const HASH_CHUNK_BYTES: usize = 64 * 1024;
pub const YARA_FINDING_V1: &str = "YARA_FINDING_V1";
pub const SIGNATURE_FINDING_V1: &str = "SIGNATURE_FINDING_V1";
pub const PE_INDICATOR_V1: &str = "PE_INDICATOR_V1";
pub const REPUTATION_FINDING_V1: &str = "REPUTATION_FINDING_V1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileSecurityErrorKind {
    InvalidPath,
    Missing,
    NotRegularFile,
    NotLocalFixedFilesystem,
    LimitExceeded,
    NotReadable,
    ReparsePoint,
    TargetChanged,
    Cancelled,
    Io,
}

#[derive(Debug)]
pub struct FileSecurityError {
    kind: FileSecurityErrorKind,
}

impl FileSecurityError {
    const fn new(kind: FileSecurityErrorKind) -> Self {
        Self { kind }
    }

    pub const fn kind(&self) -> FileSecurityErrorKind {
        self.kind
    }

    pub const fn code(&self) -> &'static str {
        match self.kind {
            FileSecurityErrorKind::InvalidPath => "FILE_PATH_INVALID",
            FileSecurityErrorKind::Missing => "FILE_NOT_FOUND",
            FileSecurityErrorKind::NotRegularFile => "NOT_REGULAR_FILE",
            FileSecurityErrorKind::NotLocalFixedFilesystem => "NOT_LOCAL_FIXED_FILESYSTEM",
            FileSecurityErrorKind::LimitExceeded => "LIMIT_EXCEEDED",
            FileSecurityErrorKind::NotReadable => "FILE_NOT_READABLE",
            FileSecurityErrorKind::ReparsePoint => "REPARSE_POINT_REFUSED",
            FileSecurityErrorKind::TargetChanged => "TARGET_CHANGED",
            FileSecurityErrorKind::Cancelled => "CANCELLED",
            FileSecurityErrorKind::Io => "FILE_IO_FAILED",
        }
    }
}

impl std::fmt::Display for FileSecurityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for FileSecurityError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub volume_id: String,
    pub file_id: String,
    pub size: u64,
    pub last_write_time: String,
    pub attributes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileTargetPreview {
    pub requested_path: String,
    pub canonical_path: String,
    pub file_name: String,
    pub identity: FileIdentity,
    pub detected_type: FileClassification,
    pub proposed_checks: Vec<String>,
    pub policy_limitations: Vec<String>,
    pub max_file_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedFileTarget {
    pub authorization_id: String,
    pub requested_path: String,
    pub canonical_path: String,
    pub identity: FileIdentity,
    pub authorized_at_utc: String,
    pub snapshot_version: String,
    pub max_file_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileHashes {
    pub sha256: String,
    pub sha512: String,
    pub bytes_hashed: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileClassification {
    GenericFile,
    PeExecutable,
    PeDll,
    UnknownBinary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeMetadata {
    pub machine: u16,
    pub architecture: String,
    pub characteristics: u16,
    pub subsystem: u16,
    pub timestamp: u32,
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub sections: Vec<PeSection>,
    pub is_dll: bool,
    pub signature_present: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeError {
    TooShort,
    BadMz,
    PeOffsetOutsideFile,
    BadPeSignature,
    TruncatedCoff,
    TruncatedOptionalHeader,
    UnsupportedOptionalHeader,
    AbsurdSectionCount,
    SectionTableOverflow,
    InvalidSecurityDirectory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticodeStatus {
    Unsigned,
    SignedValidOffline,
    SignedInvalid,
    TrustChainValidOffline,
    TrustChainUnavailableOffline,
    Indeterminate,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PublisherMetadata {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub certificate_fingerprint: Option<String>,
    pub signing_time: Option<String>,
    pub timestamp_present: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticodeInspection {
    pub signature_present: bool,
    pub cryptographic_status: AuthenticodeStatus,
    pub trust_chain_status: AuthenticodeStatus,
    pub publisher: PublisherMetadata,
    pub offline_cache_only: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Completed,
    NotApplicable,
    PolicyBlocked,
    NotChecked,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileScanCoverage {
    pub hashing: CheckState,
    pub classification: CheckState,
    pub pe_inspection: CheckState,
    pub authenticode: CheckState,
    pub yara: CheckState,
    pub reputation: CheckState,
    pub target_stable: bool,
    pub unavailable_checks: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileFindingCategory {
    FileMetadata,
    FileIntegrity,
    ExecutableMetadata,
    DigitalSignature,
    YaraMatch,
    FileReputation,
    SuspiciousBinaryIndicator,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileSecurityFinding {
    pub fingerprint_version: String,
    pub fingerprint: String,
    pub category: FileFindingCategory,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub source: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct YaraRulesetTrust {
    pub source: String,
    pub version: String,
    pub digest_sha256: String,
    pub policy_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct YaraFileObservation {
    pub rule_id: String,
    pub severity: Severity,
    pub synthetic_benign_marker: bool,
    pub ruleset: YaraRulesetTrust,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileReputationSummary {
    pub privacy_mode: FilePrivacyMode,
    pub availability: Availability,
    pub provider: Option<String>,
    pub known: Option<bool>,
    pub malicious_count: Option<u32>,
    pub suspicious_count: Option<u32>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileVerdict {
    pub disposition: String,
    pub risk_score: u8,
    pub risk: Severity,
    pub confidence_score: u8,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileAnalysis {
    pub target: AuthorizedFileTarget,
    pub hashes: FileHashes,
    pub classification: FileClassification,
    pub pe: Option<PeMetadata>,
    pub pe_error: Option<PeError>,
    pub authenticode: AuthenticodeInspection,
    pub yara_observations: Vec<YaraFileObservation>,
    pub reputation: FileReputationSummary,
    pub findings: Vec<FileSecurityFinding>,
    pub coverage: FileScanCoverage,
    pub verdict: FileVerdict,
}

pub fn inspect_file_target(
    requested_path: &str,
    max_file_size: u64,
) -> Result<FileTargetPreview, FileSecurityError> {
    let opened = SecureOpenedFile::open(requested_path, max_file_size)?;
    let mut header = vec![0_u8; usize::try_from(opened.identity.size.min(4096)).unwrap_or(4096)];
    let mut file = opened.file;
    file.read_exact(&mut header)
        .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::NotReadable))?;
    let (detected_type, _, _) = classify(&header, opened.identity.size);
    Ok(FileTargetPreview {
        requested_path: requested_path.to_owned(),
        canonical_path: opened.canonical_path.clone(),
        file_name: Path::new(&opened.canonical_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
            .to_owned(),
        identity: opened.identity,
        detected_type,
        proposed_checks: vec![
            "streaming_sha256".into(),
            "streaming_sha512".into(),
            "file_classification".into(),
            "bounded_pe_inspection_when_applicable".into(),
            "offline_authenticode_when_applicable".into(),
            "yara_x_when_execution_policy_allows".into(),
            "optional_hash_reputation".into(),
        ],
        policy_limitations: vec![
            "YARA-X real execution is unavailable by execution policy".into(),
            "Reputation was not checked; no network request or upload is permitted".into(),
            "A signature is evidence and never a safety guarantee".into(),
        ],
        max_file_size,
    })
}

pub fn authorize_file_target(
    authorization_id: String,
    requested_path: &str,
    authorized_at_utc: String,
    max_file_size: u64,
) -> Result<AuthorizedFileTarget, FileSecurityError> {
    if authorization_id.len() != 36
        || authorized_at_utc.is_empty()
        || authorized_at_utc.len() > 64
        || max_file_size == 0
        || max_file_size > DEFAULT_MAX_FILE_SIZE
    {
        return Err(FileSecurityError::new(FileSecurityErrorKind::InvalidPath));
    }
    let opened = SecureOpenedFile::open(requested_path, max_file_size)?;
    Ok(AuthorizedFileTarget {
        authorization_id,
        requested_path: requested_path.to_owned(),
        canonical_path: opened.canonical_path,
        identity: opened.identity,
        authorized_at_utc,
        snapshot_version: FILE_SNAPSHOT_VERSION.into(),
        max_file_size,
    })
}

pub fn analyze_authorized_file<F>(
    target: &AuthorizedFileTarget,
    cancelled: F,
) -> Result<FileAnalysis, FileSecurityError>
where
    F: Fn() -> bool,
{
    let mut opened = SecureOpenedFile::open(&target.canonical_path, target.max_file_size)?;
    if opened.identity != target.identity
        || !eq_path(&opened.canonical_path, &target.canonical_path)
        || target.snapshot_version != FILE_SNAPSHOT_VERSION
    {
        return Err(FileSecurityError::new(FileSecurityErrorKind::TargetChanged));
    }

    let hashes = stream_hashes(&mut opened.file, &cancelled)?;
    let after_hash = file_identity(&opened.file)?;
    if after_hash != opened.identity || hashes.bytes_hashed != opened.identity.size {
        return Err(FileSecurityError::new(FileSecurityErrorKind::TargetChanged));
    }

    opened
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::Io))?;
    let header_size = usize::try_from(opened.identity.size.min(1024 * 1024))
        .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::LimitExceeded))?;
    let mut header = vec![0_u8; header_size];
    opened
        .file
        .read_exact(&mut header)
        .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::Io))?;
    if cancelled() {
        return Err(FileSecurityError::new(FileSecurityErrorKind::Cancelled));
    }
    let (classification, pe, pe_error) = classify(&header, opened.identity.size);
    let authenticode = inspect_authenticode(
        &opened.file,
        &opened.canonical_path,
        pe.as_ref().is_some_and(|value| value.signature_present),
        matches!(
            classification,
            FileClassification::PeExecutable | FileClassification::PeDll
        ),
    );
    let final_identity = file_identity(&opened.file)?;
    if cancelled() {
        return Err(FileSecurityError::new(FileSecurityErrorKind::Cancelled));
    }
    if final_identity != opened.identity {
        return Err(FileSecurityError::new(FileSecurityErrorKind::TargetChanged));
    }

    let reputation = FileReputationSummary {
        privacy_mode: FilePrivacyMode::LocalOnly,
        availability: Availability::NotConfigured,
        provider: None,
        known: None,
        malicious_count: None,
        suspicious_count: None,
        status: "not_checked".into(),
    };
    let mut coverage = FileScanCoverage {
        hashing: CheckState::Completed,
        classification: CheckState::Completed,
        pe_inspection: if matches!(classification, FileClassification::GenericFile) {
            CheckState::NotApplicable
        } else if pe.is_some() {
            CheckState::Completed
        } else {
            CheckState::Failed
        },
        authenticode: if matches!(
            classification,
            FileClassification::PeExecutable | FileClassification::PeDll
        ) {
            if matches!(
                authenticode.cryptographic_status,
                AuthenticodeStatus::Error | AuthenticodeStatus::Indeterminate
            ) || authenticode.trust_chain_status
                == AuthenticodeStatus::TrustChainUnavailableOffline
            {
                CheckState::Failed
            } else {
                CheckState::Completed
            }
        } else {
            CheckState::NotApplicable
        },
        yara: CheckState::PolicyBlocked,
        reputation: CheckState::NotChecked,
        target_stable: true,
        unavailable_checks: vec![
            "yara_x_real_execution_policy_blocked".into(),
            "file_reputation_not_checked".into(),
        ],
    };
    if coverage.authenticode == CheckState::Failed {
        coverage
            .unavailable_checks
            .push("authenticode_incomplete_offline".into());
    }
    if coverage.pe_inspection == CheckState::Failed {
        coverage
            .unavailable_checks
            .push("pe_inspection_incomplete".into());
    }
    let findings = correlate_file_evidence(target, pe_error, &authenticode, &[], &reputation);
    let verdict = assess_file_verdict(&findings, &coverage);
    Ok(FileAnalysis {
        target: target.clone(),
        hashes,
        classification,
        pe,
        pe_error,
        authenticode,
        yara_observations: Vec::new(),
        reputation,
        findings,
        coverage,
        verdict,
    })
}

pub fn stream_hashes<F>(file: &mut File, cancelled: &F) -> Result<FileHashes, FileSecurityError>
where
    F: Fn() -> bool,
{
    file.seek(SeekFrom::Start(0))
        .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::Io))?;
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut bytes_hashed = 0_u64;
    let mut chunk = vec![0_u8; HASH_CHUNK_BYTES];
    loop {
        if cancelled() {
            return Err(FileSecurityError::new(FileSecurityErrorKind::Cancelled));
        }
        let read = file
            .read(&mut chunk)
            .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::Io))?;
        if read == 0 {
            break;
        }
        sha256.update(&chunk[..read]);
        sha512.update(&chunk[..read]);
        bytes_hashed = bytes_hashed
            .checked_add(read as u64)
            .ok_or_else(|| FileSecurityError::new(FileSecurityErrorKind::LimitExceeded))?;
    }
    Ok(FileHashes {
        sha256: format!("{:x}", sha256.finalize()),
        sha512: format!("{:x}", sha512.finalize()),
        bytes_hashed,
    })
}

pub fn parse_pe(bytes: &[u8]) -> Result<PeMetadata, PeError> {
    parse_pe_with_size(bytes, bytes.len() as u64)
}

fn classify(
    bytes: &[u8],
    total_file_size: u64,
) -> (FileClassification, Option<PeMetadata>, Option<PeError>) {
    if bytes.starts_with(b"MZ") {
        match parse_pe_with_size(bytes, total_file_size) {
            Ok(pe) => {
                let class = if pe.is_dll {
                    FileClassification::PeDll
                } else {
                    FileClassification::PeExecutable
                };
                (class, Some(pe), None)
            }
            Err(error) => (FileClassification::UnknownBinary, None, Some(error)),
        }
    } else if probably_text(bytes) {
        (FileClassification::GenericFile, None, None)
    } else {
        (FileClassification::UnknownBinary, None, None)
    }
}

fn parse_pe_with_size(bytes: &[u8], total_file_size: u64) -> Result<PeMetadata, PeError> {
    if bytes.len() < 64 {
        return Err(PeError::TooShort);
    }
    if &bytes[..2] != b"MZ" {
        return Err(PeError::BadMz);
    }
    let pe_offset = read_u32(bytes, 0x3c).ok_or(PeError::PeOffsetOutsideFile)? as usize;
    if pe_offset > 1024 * 1024 || pe_offset.checked_add(4).is_none_or(|end| end > bytes.len()) {
        return Err(PeError::PeOffsetOutsideFile);
    }
    if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(PeError::BadPeSignature);
    }
    let coff = pe_offset.checked_add(4).ok_or(PeError::TruncatedCoff)?;
    if coff.checked_add(20).is_none_or(|end| end > bytes.len()) {
        return Err(PeError::TruncatedCoff);
    }
    let machine = read_u16(bytes, coff).ok_or(PeError::TruncatedCoff)?;
    let section_count = read_u16(bytes, coff + 2).ok_or(PeError::TruncatedCoff)? as usize;
    if section_count > 96 {
        return Err(PeError::AbsurdSectionCount);
    }
    let timestamp = read_u32(bytes, coff + 4).ok_or(PeError::TruncatedCoff)?;
    let optional_size = read_u16(bytes, coff + 16).ok_or(PeError::TruncatedCoff)? as usize;
    let characteristics = read_u16(bytes, coff + 18).ok_or(PeError::TruncatedCoff)?;
    let optional = coff + 20;
    let optional_end = optional
        .checked_add(optional_size)
        .ok_or(PeError::TruncatedOptionalHeader)?;
    if optional_size > 4096 || optional_end > bytes.len() {
        return Err(PeError::TruncatedOptionalHeader);
    }
    let magic = read_u16(bytes, optional).ok_or(PeError::TruncatedOptionalHeader)?;
    let (minimum, image_base, number_of_rva_offset, directory_offset) = match magic {
        0x10b => (
            96,
            read_u32(bytes, optional + 28)
                .map(u64::from)
                .ok_or(PeError::TruncatedOptionalHeader)?,
            92,
            96,
        ),
        0x20b => (
            112,
            read_u64(bytes, optional + 24).ok_or(PeError::TruncatedOptionalHeader)?,
            108,
            112,
        ),
        _ => return Err(PeError::UnsupportedOptionalHeader),
    };
    if optional_size < minimum {
        return Err(PeError::TruncatedOptionalHeader);
    }
    let entry_point_rva = read_u32(bytes, optional + 16).ok_or(PeError::TruncatedOptionalHeader)?;
    let subsystem = read_u16(bytes, optional + 68).ok_or(PeError::TruncatedOptionalHeader)?;
    let directory_count =
        read_u32(bytes, optional + number_of_rva_offset).ok_or(PeError::TruncatedOptionalHeader)?;
    if directory_count > 16 || optional_size < directory_offset + (directory_count as usize) * 8 {
        return Err(PeError::TruncatedOptionalHeader);
    }
    let signature_present = if directory_count > 4 {
        let security = optional + directory_offset + 32;
        let offset = read_u32(bytes, security).unwrap_or(0) as u64;
        let size = read_u32(bytes, security + 4).unwrap_or(0) as u64;
        if offset == 0 && size == 0 {
            false
        } else if offset == 0
            || size < 8
            || !offset.is_multiple_of(8)
            || offset < optional_end as u64
            || offset
                .checked_add(size)
                .is_none_or(|end| end > total_file_size)
        {
            return Err(PeError::InvalidSecurityDirectory);
        } else {
            true
        }
    } else {
        false
    };
    let section_table = optional_end;
    let section_bytes = section_count
        .checked_mul(40)
        .ok_or(PeError::SectionTableOverflow)?;
    let section_end = section_table
        .checked_add(section_bytes)
        .ok_or(PeError::SectionTableOverflow)?;
    if section_end > bytes.len() {
        return Err(PeError::SectionTableOverflow);
    }
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = section_table + index * 40;
        let name_bytes = &bytes[offset..offset + 8];
        let name_end = name_bytes.iter().position(|byte| *byte == 0).unwrap_or(8);
        let name = if name_bytes[..name_end]
            .iter()
            .all(|byte| byte.is_ascii_graphic())
        {
            String::from_utf8_lossy(&name_bytes[..name_end]).into_owned()
        } else {
            "<non-ascii>".into()
        };
        sections.push(PeSection {
            name,
            virtual_size: read_u32(bytes, offset + 8).ok_or(PeError::SectionTableOverflow)?,
            raw_size: read_u32(bytes, offset + 16).ok_or(PeError::SectionTableOverflow)?,
            characteristics: read_u32(bytes, offset + 36).ok_or(PeError::SectionTableOverflow)?,
        });
    }
    Ok(PeMetadata {
        machine,
        architecture: match machine {
            0x014c => "x86",
            0x8664 => "x86_64",
            0xaa64 => "arm64",
            _ => "unknown",
        }
        .into(),
        characteristics,
        subsystem,
        timestamp,
        image_base,
        entry_point_rva,
        sections,
        is_dll: characteristics & 0x2000 != 0,
        signature_present,
    })
}

pub fn correlate_file_evidence(
    target: &AuthorizedFileTarget,
    pe_error: Option<PeError>,
    signature: &AuthenticodeInspection,
    yara: &[YaraFileObservation],
    reputation: &FileReputationSummary,
) -> Vec<FileSecurityFinding> {
    let mut findings = Vec::new();
    if let Some(error) = pe_error {
        findings.push(file_finding(
            target,
            FileFindingDraft {
                version: PE_INDICATOR_V1,
                category: FileFindingCategory::ExecutableMetadata,
                rule_id: "pe_parser_rejected",
                title: "Malformed or unsupported PE structure requires review",
                severity: Severity::Medium,
                confidence: Confidence::High,
                source: "first-party-pe-parser",
                evidence: vec![format!("pe_error={error:?}")],
            },
        ));
    }
    if signature.signature_present
        && matches!(
            signature.cryptographic_status,
            AuthenticodeStatus::SignedInvalid
        )
    {
        findings.push(file_finding(
            target,
            FileFindingDraft {
                version: SIGNATURE_FINDING_V1,
                category: FileFindingCategory::DigitalSignature,
                rule_id: "authenticode_invalid",
                title: "Digital signature validation failed",
                severity: Severity::High,
                confidence: Confidence::High,
                source: "windows-authenticode-offline",
                evidence: vec![format!("status={:?}", signature.cryptographic_status)],
            },
        ));
    }
    for observation in yara {
        if observation.synthetic_benign_marker {
            continue;
        }
        findings.push(file_finding(
            target,
            FileFindingDraft {
                version: YARA_FINDING_V1,
                category: FileFindingCategory::YaraMatch,
                rule_id: &observation.rule_id,
                title: "YARA-X rule matched; analyst review is required",
                severity: observation.severity,
                confidence: Confidence::High,
                source: "yara-x",
                evidence: vec![
                    format!("ruleset_digest={}", observation.ruleset.digest_sha256),
                    format!("ruleset_policy={}", observation.ruleset.policy_state),
                ],
            },
        ));
    }
    if reputation.malicious_count.unwrap_or(0) > 0 || reputation.suspicious_count.unwrap_or(0) > 0 {
        findings.push(file_finding(
            target,
            FileFindingDraft {
                version: REPUTATION_FINDING_V1,
                category: FileFindingCategory::FileReputation,
                rule_id: "hash_reputation_indicator",
                title: "Hash reputation provider returned risk indicators",
                severity: if reputation.malicious_count.unwrap_or(0) > 0 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                confidence: Confidence::Medium,
                source: reputation.provider.as_deref().unwrap_or("hash-reputation"),
                evidence: vec![
                    format!(
                        "malicious_count={}",
                        reputation.malicious_count.unwrap_or(0)
                    ),
                    format!(
                        "suspicious_count={}",
                        reputation.suspicious_count.unwrap_or(0)
                    ),
                ],
            },
        ));
    }
    findings.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    findings
}

pub fn assess_file_verdict(
    findings: &[FileSecurityFinding],
    coverage: &FileScanCoverage,
) -> FileVerdict {
    let max_severity = findings
        .iter()
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(Severity::Info);
    let mut risk_score = max_severity.base_risk_score();
    let independent_sources = findings
        .iter()
        .map(|finding| finding.source.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if independent_sources > 1 {
        risk_score = risk_score.saturating_add(10).min(100);
    }
    let completed = [
        coverage.hashing,
        coverage.classification,
        coverage.pe_inspection,
        coverage.authenticode,
        coverage.yara,
        coverage.reputation,
    ]
    .into_iter()
    .filter(|state| matches!(state, CheckState::Completed | CheckState::NotApplicable))
    .count() as u8;
    let mut confidence_score = (u16::from(completed) * 100 / 6) as u8;
    if !coverage.target_stable {
        confidence_score = 0;
    }
    let confidence = match confidence_score {
        0..=39 => Confidence::Low,
        40..=74 => Confidence::Medium,
        _ => Confidence::High,
    };
    let risk = match risk_score {
        0..=9 => Severity::Info,
        10..=29 => Severity::Low,
        30..=59 => Severity::Medium,
        60..=84 => Severity::High,
        _ => Severity::Critical,
    };
    let disposition = if findings
        .iter()
        .any(|finding| finding.severity >= Severity::High)
    {
        "suspicious"
    } else if !findings.is_empty() {
        "needs_review"
    } else if coverage.unavailable_checks.is_empty() {
        "no_known_indicators"
    } else {
        "insufficient_coverage"
    };
    FileVerdict {
        disposition: disposition.into(),
        risk_score,
        risk,
        confidence_score,
        confidence,
        reasons: if coverage.unavailable_checks.is_empty() {
            vec!["Verdict is based only on observed evidence".into()]
        } else {
            vec![
                "Some planned checks were unavailable; absence of findings is not a clean guarantee"
                    .into(),
            ]
        },
    }
}

/// Normalize Level 2 evidence with the shared domain correlator before persistence.
/// File-specific fingerprint versions remain the public evidence keys; they do not replace
/// the Core Target/Observation/Finding model. IDs are supplied by the application boundary.
pub fn normalize_file_analysis<I: edy_core::FindingIdSource>(
    analysis: &mut FileAnalysis,
    scan_id: &edy_core::ScanId,
    observed_at: &edy_core::Timestamp,
    ids: &mut I,
) -> Result<(), edy_core::DomainError> {
    use edy_core::{
        CorrelationEngine, EngineId, EngineObservation, EvidenceId, EvidenceStrength,
        ObservationSignal, Target, TargetId, TargetKind, TargetLocator,
    };
    let kind = match analysis.classification {
        FileClassification::GenericFile => TargetKind::File,
        _ => TargetKind::Binary,
    };
    let target = Target::new(
        TargetId::new(&analysis.target.authorization_id)?,
        kind,
        TargetLocator::new_local_path(&analysis.target.canonical_path)?,
    )?;
    let observations = analysis
        .findings
        .iter()
        .map(|finding| {
            let category = match finding.category {
                FileFindingCategory::FileMetadata => "file_metadata",
                FileFindingCategory::FileIntegrity => "file_integrity",
                FileFindingCategory::ExecutableMetadata => "executable_metadata",
                FileFindingCategory::DigitalSignature => "digital_signature",
                FileFindingCategory::YaraMatch => "yara_match",
                FileFindingCategory::FileReputation => "file_reputation",
                FileFindingCategory::SuspiciousBinaryIndicator => "suspicious_binary_indicator",
            };
            Ok(EngineObservation {
                engine: EngineId::new(&finding.source)?,
                engine_version: "level2-v1".into(),
                target_id: target.id().clone(),
                rule_id: finding.rule_id.clone(),
                semantic_key: finding.fingerprint.clone(),
                category: category.into(),
                severity: finding.severity,
                location: target.locator().canonical(),
                message: finding.title.clone(),
                evidence_id: EvidenceId::new(ids.next_id().as_str())?,
                signal: if finding.severity >= Severity::High {
                    ObservationSignal::Suspicious
                } else {
                    ObservationSignal::Informational
                },
                evidence_strength: EvidenceStrength::Moderate,
                parser_confidence: finding.confidence,
            })
        })
        .collect::<Result<Vec<_>, edy_core::DomainError>>()?;
    let correlated =
        CorrelationEngine::correlate(scan_id, &target, &observations, observed_at, ids)?;
    let mut normalized = Vec::new();
    for finding in correlated {
        if let Some(original) = analysis.findings.iter().find(|item| {
            finding.rule_ids().contains(&item.rule_id)
                && finding
                    .source_engines()
                    .iter()
                    .any(|engine| engine.as_str() == item.source)
        }) {
            let mut item = original.clone();
            item.severity = finding.severity();
            item.confidence = finding.confidence();
            normalized.push(item);
        }
    }
    normalized.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    analysis.findings = normalized;
    analysis.verdict = assess_file_verdict(&analysis.findings, &analysis.coverage);
    Ok(())
}

struct FileFindingDraft<'a> {
    version: &'a str,
    category: FileFindingCategory,
    rule_id: &'a str,
    title: &'a str,
    severity: Severity,
    confidence: Confidence,
    source: &'a str,
    evidence: Vec<String>,
}

fn file_finding(target: &AuthorizedFileTarget, draft: FileFindingDraft<'_>) -> FileSecurityFinding {
    let FileFindingDraft {
        version,
        category,
        rule_id,
        title,
        severity,
        confidence,
        source,
        evidence,
    } = draft;
    let mut digest = Sha256::new();
    for value in [
        version,
        &target.canonical_path.to_ascii_lowercase(),
        rule_id,
        source,
    ] {
        digest.update((value.len() as u32).to_be_bytes());
        digest.update(value.as_bytes());
    }
    FileSecurityFinding {
        fingerprint_version: version.into(),
        fingerprint: format!("{}-{:x}", version.to_ascii_lowercase(), digest.finalize()),
        category,
        rule_id: rule_id.into(),
        title: title.into(),
        severity,
        confidence,
        source: source.into(),
        evidence,
    }
}

struct SecureOpenedFile {
    file: File,
    canonical_path: String,
    identity: FileIdentity,
}

impl SecureOpenedFile {
    fn open(requested_path: &str, max_file_size: u64) -> Result<Self, FileSecurityError> {
        validate_requested_path(requested_path)?;
        let requested = PathBuf::from(requested_path);
        reject_reparse_components(&requested)?;
        let metadata = std::fs::symlink_metadata(&requested).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                FileSecurityError::new(FileSecurityErrorKind::Missing)
            } else {
                FileSecurityError::new(FileSecurityErrorKind::NotReadable)
            }
        })?;
        if !metadata.is_file() {
            return Err(FileSecurityError::new(
                FileSecurityErrorKind::NotRegularFile,
            ));
        }
        if is_reparse(&metadata) {
            return Err(FileSecurityError::new(FileSecurityErrorKind::ReparsePoint));
        }
        if metadata.len() > max_file_size {
            return Err(FileSecurityError::new(FileSecurityErrorKind::LimitExceeded));
        }
        let canonical = std::fs::canonicalize(&requested)
            .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::NotReadable))?;
        if !is_local_fixed(&canonical) {
            return Err(FileSecurityError::new(
                FileSecurityErrorKind::NotLocalFixedFilesystem,
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            };
            // Refuse existing writers and deny new write/delete handles for this lifetime.
            options
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options
            .open(&canonical)
            .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::NotReadable))?;
        let identity = file_identity(&file)?;
        if !file
            .metadata()
            .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::Io))?
            .is_file()
            || (cfg!(windows) && identity.attributes & 0x400 != 0)
        {
            return Err(FileSecurityError::new(FileSecurityErrorKind::ReparsePoint));
        }
        if identity.size > max_file_size {
            return Err(FileSecurityError::new(FileSecurityErrorKind::LimitExceeded));
        }
        let canonical_path = final_path(&file, &canonical)?;
        reject_reparse_components(&requested)?;
        reject_reparse_components(&canonical)?;
        if !is_local_fixed(Path::new(&canonical_path)) {
            return Err(FileSecurityError::new(
                FileSecurityErrorKind::NotLocalFixedFilesystem,
            ));
        }
        if !eq_path(&canonical_path, &display_path(&canonical)) {
            return Err(FileSecurityError::new(FileSecurityErrorKind::ReparsePoint));
        }
        Ok(Self {
            file,
            canonical_path,
            identity,
        })
    }
}

fn validate_requested_path(value: &str) -> Result<(), FileSecurityError> {
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(char::is_control)
        || value.starts_with(r"\\")
        || value.starts_with("//")
        || value.starts_with(r"\??\")
        || value.starts_with(r"\\?\")
        || value.starts_with(r"\\.\")
    {
        return Err(FileSecurityError::new(FileSecurityErrorKind::InvalidPath));
    }
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(FileSecurityError::new(FileSecurityErrorKind::InvalidPath));
    }
    let normalized = value.replace('/', "\\");
    let colon_count = normalized.bytes().filter(|byte| *byte == b':').count();
    if colon_count != 1 || normalized.as_bytes().get(1) != Some(&b':') {
        return Err(FileSecurityError::new(FileSecurityErrorKind::InvalidPath));
    }
    Ok(())
}

fn reject_reparse_components(path: &Path) -> Result<(), FileSecurityError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if !current.exists() {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::NotReadable))?;
        if is_reparse(&metadata) {
            return Err(FileSecurityError::new(FileSecurityErrorKind::ReparsePoint));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn file_identity(file: &File) -> Result<FileIdentity, FileSecurityError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) };
    if ok == 0 {
        return Err(FileSecurityError::new(FileSecurityErrorKind::Io));
    }
    Ok(FileIdentity {
        volume_id: information.dwVolumeSerialNumber.to_string(),
        file_id: ((u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow))
        .to_string(),
        size: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
        last_write_time: ((u64::from(information.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(information.ftLastWriteTime.dwLowDateTime))
        .to_string(),
        attributes: information.dwFileAttributes,
    })
}

#[cfg(not(windows))]
fn file_identity(file: &File) -> Result<FileIdentity, FileSecurityError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file
        .metadata()
        .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::Io))?;
    Ok(FileIdentity {
        volume_id: metadata.dev().to_string(),
        file_id: metadata.ino().to_string(),
        size: metadata.len(),
        last_write_time: metadata.mtime().to_string(),
        attributes: metadata.mode(),
    })
}

#[cfg(windows)]
fn final_path(file: &File, _fallback: &Path) -> Result<String, FileSecurityError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    };
    let mut buffer = vec![0_u16; 32_768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle().cast(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    validate_final_path_length(length as usize, buffer.len())?;
    let value = String::from_utf16(&buffer[..length as usize])
        .map_err(|_| FileSecurityError::new(FileSecurityErrorKind::Io))?;
    Ok(strip_extended_prefix(&value))
}

#[cfg(windows)]
fn validate_final_path_length(length: usize, capacity: usize) -> Result<(), FileSecurityError> {
    if length == 0 || length >= capacity {
        return Err(FileSecurityError::new(FileSecurityErrorKind::Io));
    }
    Ok(())
}

#[cfg(not(windows))]
fn final_path(_file: &File, fallback: &Path) -> Result<String, FileSecurityError> {
    Ok(display_path(fallback))
}

#[cfg(windows)]
fn is_local_fixed(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumePathNameW};
    const DRIVE_FIXED: u32 = 3;
    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut root = vec![0_u16; 1024];
    let ok =
        unsafe { GetVolumePathNameW(path_wide.as_ptr(), root.as_mut_ptr(), root.len() as u32) };
    ok != 0 && unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_FIXED
}

#[cfg(not(windows))]
fn is_local_fixed(_path: &Path) -> bool {
    true
}

#[cfg(windows)]
fn inspect_authenticode(
    file: &File,
    canonical_path: &str,
    signature_present: bool,
    applicable: bool,
) -> AuthenticodeInspection {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4,
        WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        WinVerifyTrust,
    };
    if !applicable || !signature_present {
        return unsigned_authenticode();
    }
    let wide = std::ffi::OsStr::new(canonical_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: file.as_raw_handle().cast(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: std::ptr::null_mut(),
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4,
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let result = unsafe {
        WinVerifyTrust(
            windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    let state = TrustState(&mut data);
    let mut inspection = map_authenticode_result(result, signature_present);
    inspection.publisher = publisher_from_state(state.0.hWVTStateData);
    inspection
}

#[cfg(windows)]
struct TrustState<'a>(&'a mut windows_sys::Win32::Security::WinTrust::WINTRUST_DATA);

#[cfg(windows)]
impl Drop for TrustState<'_> {
    fn drop(&mut self) {
        use windows_sys::Win32::Security::WinTrust::*;
        self.0.dwStateAction = WTD_STATEACTION_CLOSE;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // Release only the transient trust state. No certificate-store mutation.
        unsafe {
            WinVerifyTrust(
                windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
                &mut action,
                (self.0 as *mut WINTRUST_DATA).cast(),
            );
        }
    }
}

#[cfg(windows)]
fn publisher_from_state(state: windows_sys::Win32::Foundation::HANDLE) -> PublisherMetadata {
    use windows_sys::Win32::Security::Cryptography::*;
    use windows_sys::Win32::Security::WinTrust::*;
    if state.is_null() {
        return PublisherMetadata::default();
    }
    // These pointers are owned by WinTrust and valid until TrustState closes the state.
    unsafe {
        let provider = WTHelperProvDataFromStateData(state);
        if provider.is_null() {
            return PublisherMetadata::default();
        }
        let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
        if signer.is_null() {
            return PublisherMetadata::default();
        }
        let mut metadata = PublisherMetadata {
            timestamp_present: Some((*signer).csCounterSigners > 0),
            ..PublisherMetadata::default()
        };
        if (*signer).csCertChain == 0 {
            return metadata;
        }
        let cert = WTHelperGetProvCertFromChain(signer, 0);
        if cert.is_null() || (*cert).pCert.is_null() {
            return metadata;
        }
        let context = (*cert).pCert;
        let name = |flags| {
            let mut buffer = [0_u16; 2048];
            let length = CertGetNameStringW(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            );
            if length <= 1 || length as usize >= buffer.len() {
                return None;
            }
            Some(sanitize_publisher_text(&String::from_utf16_lossy(
                &buffer[..length as usize - 1],
            )))
        };
        metadata.subject = name(0);
        metadata.issuer = name(CERT_NAME_ISSUER_FLAG);
        if !(*context).pbCertEncoded.is_null() && (1..=65536).contains(&(*context).cbCertEncoded) {
            let bytes = std::slice::from_raw_parts(
                (*context).pbCertEncoded,
                (*context).cbCertEncoded as usize,
            );
            metadata.certificate_fingerprint = Some(format!("{:x}", Sha256::digest(bytes)));
        }
        // sftVerifyAsOf is verification time, not a signing-time assertion. Do not mislabel it.
        metadata
    }
}

#[cfg(windows)]
fn sanitize_publisher_text(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(512)
        .collect()
}

#[cfg(windows)]
fn map_authenticode_result(result: i32, signature_present: bool) -> AuthenticodeInspection {
    use windows_sys::Win32::Foundation::{
        CERT_E_CHAINING, CERT_E_REVOCATION_FAILURE, CERT_E_UNTRUSTEDROOT,
        CRYPT_E_REVOCATION_OFFLINE, TRUST_E_BAD_DIGEST, TRUST_E_NOSIGNATURE,
    };
    let (cryptographic_status, trust_chain_status) = if result == 0 {
        (
            AuthenticodeStatus::SignedValidOffline,
            AuthenticodeStatus::TrustChainValidOffline,
        )
    } else if result == TRUST_E_NOSIGNATURE && !signature_present {
        (AuthenticodeStatus::Unsigned, AuthenticodeStatus::Unsigned)
    } else if matches!(
        result,
        CERT_E_UNTRUSTEDROOT
            | CERT_E_CHAINING
            | CERT_E_REVOCATION_FAILURE
            | CRYPT_E_REVOCATION_OFFLINE
    ) {
        (
            AuthenticodeStatus::Indeterminate,
            AuthenticodeStatus::TrustChainUnavailableOffline,
        )
    } else if result == TRUST_E_BAD_DIGEST {
        (
            AuthenticodeStatus::SignedInvalid,
            AuthenticodeStatus::Indeterminate,
        )
    } else {
        (AuthenticodeStatus::Error, AuthenticodeStatus::Indeterminate)
    };
    AuthenticodeInspection {
        signature_present,
        cryptographic_status,
        trust_chain_status,
        publisher: PublisherMetadata::default(),
        offline_cache_only: true,
    }
}

#[cfg(not(windows))]
fn inspect_authenticode(
    _file: &File,
    _canonical_path: &str,
    signature_present: bool,
    applicable: bool,
) -> AuthenticodeInspection {
    if !applicable || !signature_present {
        unsigned_authenticode()
    } else {
        AuthenticodeInspection {
            signature_present,
            cryptographic_status: AuthenticodeStatus::Indeterminate,
            trust_chain_status: AuthenticodeStatus::Indeterminate,
            publisher: PublisherMetadata::default(),
            offline_cache_only: true,
        }
    }
}

fn unsigned_authenticode() -> AuthenticodeInspection {
    AuthenticodeInspection {
        signature_present: false,
        cryptographic_status: AuthenticodeStatus::Unsigned,
        trust_chain_status: AuthenticodeStatus::Unsigned,
        publisher: PublisherMetadata::default(),
        offline_cache_only: true,
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let array: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(array))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let array: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let array: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

fn probably_text(bytes: &[u8]) -> bool {
    bytes.iter().take(4096).all(|byte| {
        *byte == b'\n' || *byte == b'\r' || *byte == b'\t' || (0x20..=0x7e).contains(byte)
    })
}

fn display_path(path: &Path) -> String {
    strip_extended_prefix(&path.to_string_lossy())
}

fn strip_extended_prefix(value: &str) -> String {
    value.strip_prefix(r"\\?\").unwrap_or(value).to_owned()
}

fn eq_path(left: &str, right: &str) -> bool {
    #[cfg(windows)]
    {
        left.eq_ignore_ascii_case(right)
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

pub fn sha256_digest(value: &str) -> Result<Sha256Digest, FileSecurityError> {
    Sha256Digest::new(value).map_err(|_| FileSecurityError::new(FileSecurityErrorKind::InvalidPath))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Temp(PathBuf);

    impl Temp {
        fn new() -> Self {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../_intake/level2-tests")
                .join(format!(
                    "{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
            std::fs::create_dir_all(&root).unwrap();
            Self(root.canonicalize().unwrap())
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn text(path: &Path) -> String {
        display_path(&path.canonicalize().unwrap())
    }

    fn authorized(path: &Path) -> AuthorizedFileTarget {
        authorize_file_target(
            "018f4c2a-1d3b-7abc-8def-0123456789d1".into(),
            &text(path),
            "2026-09-02T00:00:00Z".into(),
            DEFAULT_MAX_FILE_SIZE,
        )
        .unwrap()
    }

    fn minimal_pe(dll: bool) -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x200];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(0x80_u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x88..0x8c].copy_from_slice(&1234_u32.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        let characteristics = if dll { 0x2022_u16 } else { 0x0022_u16 };
        bytes[0x96..0x98].copy_from_slice(&characteristics.to_le_bytes());
        let optional = 0x98;
        bytes[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x140000000_u64.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3_u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16_u32.to_le_bytes());
        let section = optional + 0xf0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x60000020_u32.to_le_bytes());
        bytes
    }

    #[test]
    #[cfg(windows)]
    fn opened_handle_denies_concurrent_write_delete_and_existing_writers() {
        let temp = Temp::new();
        let path = temp.file("locked.bin", b"benign fixture");
        let opened = SecureOpenedFile::open(&text(&path), DEFAULT_MAX_FILE_SIZE).unwrap();
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, temp.0.join("renamed.bin")).is_err());
        assert!(std::fs::remove_file(&path).is_err());
        assert!(File::open(&path).is_ok());
        drop(opened);
        let writer = OpenOptions::new().write(true).open(&path).unwrap();
        assert!(SecureOpenedFile::open(&text(&path), DEFAULT_MAX_FILE_SIZE).is_err());
        drop(writer);
        assert!(SecureOpenedFile::open(&text(&path), DEFAULT_MAX_FILE_SIZE).is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn final_path_errors_never_fall_back_to_an_unverified_path() {
        assert!(validate_final_path_length(0, 32768).is_err());
        assert!(validate_final_path_length(32768, 32768).is_err());
        assert!(validate_final_path_length(40000, 32768).is_err());
        assert!(validate_final_path_length(32, 32768).is_ok());
    }

    #[test]
    fn target_policy_rejects_missing_directory_oversized_unc_device_ads_and_relative() {
        let temp = Temp::new();
        let directory = text(&temp.0);
        assert_eq!(
            inspect_file_target(&directory, DEFAULT_MAX_FILE_SIZE)
                .unwrap_err()
                .kind(),
            FileSecurityErrorKind::NotRegularFile
        );
        assert_eq!(
            inspect_file_target(r"\\server\share\file.bin", DEFAULT_MAX_FILE_SIZE)
                .unwrap_err()
                .kind(),
            FileSecurityErrorKind::InvalidPath
        );
        assert_eq!(
            inspect_file_target(r"\\?\C:\file.bin", DEFAULT_MAX_FILE_SIZE)
                .unwrap_err()
                .kind(),
            FileSecurityErrorKind::InvalidPath
        );
        assert_eq!(
            inspect_file_target(r"C:\file.bin:stream", DEFAULT_MAX_FILE_SIZE)
                .unwrap_err()
                .kind(),
            FileSecurityErrorKind::InvalidPath
        );
        assert_eq!(
            inspect_file_target("relative.bin", DEFAULT_MAX_FILE_SIZE)
                .unwrap_err()
                .kind(),
            FileSecurityErrorKind::InvalidPath
        );
        let missing = temp.0.join("missing.bin");
        assert_eq!(
            inspect_file_target(&display_path(&missing), DEFAULT_MAX_FILE_SIZE)
                .unwrap_err()
                .kind(),
            FileSecurityErrorKind::Missing
        );
        let large = temp.file("large.bin", b"12345");
        assert_eq!(
            inspect_file_target(&text(&large), 4).unwrap_err().kind(),
            FileSecurityErrorKind::LimitExceeded
        );
    }

    #[test]
    fn hashes_are_lowercase_streaming_and_match_known_vectors() {
        let temp = Temp::new();
        let empty = temp.file("empty.bin", b"");
        let analysis = analyze_authorized_file(&authorized(&empty), || false).unwrap();
        assert_eq!(
            analysis.hashes.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            analysis.hashes.sha512,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce".to_owned()
                + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        let multi = temp.file("multi.bin", &vec![b'x'; HASH_CHUNK_BYTES * 2 + 17]);
        let result = analyze_authorized_file(&authorized(&multi), || false).unwrap();
        assert_eq!(
            result.hashes.bytes_hashed,
            (HASH_CHUNK_BYTES * 2 + 17) as u64
        );
        assert!(
            result
                .hashes
                .sha256
                .bytes()
                .all(|byte| !byte.is_ascii_uppercase())
        );
    }

    #[test]
    fn hashing_cancellation_and_changed_target_fail_without_verdict() {
        let temp = Temp::new();
        let path = temp.file("cancel.bin", &vec![7_u8; HASH_CHUNK_BYTES * 3]);
        let target = authorized(&path);
        let calls = AtomicUsize::new(0);
        let error = analyze_authorized_file(&target, || calls.fetch_add(1, Ordering::SeqCst) > 1)
            .unwrap_err();
        assert_eq!(error.kind(), FileSecurityErrorKind::Cancelled);

        let changed = temp.file("changed.bin", b"before");
        let target = authorized(&changed);
        std::fs::write(&changed, b"after-and-a-different-size").unwrap();
        assert_eq!(
            analyze_authorized_file(&target, || false)
                .unwrap_err()
                .kind(),
            FileSecurityErrorKind::TargetChanged
        );
    }

    #[test]
    fn known_small_text_hashes_and_full_coverage_confidence_are_exact() {
        let temp = Temp::new();
        let path = temp.file("abc.txt", b"abc");
        let mut analysis = analyze_authorized_file(&authorized(&path), || false).unwrap();
        assert_eq!(
            analysis.hashes.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            analysis.hashes.sha512,
            concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
        assert_eq!(analysis.verdict.confidence_score, 66);
        analysis.coverage.yara = CheckState::Completed;
        analysis.coverage.reputation = CheckState::Completed;
        analysis.coverage.unavailable_checks.clear();
        assert_eq!(
            assess_file_verdict(&[], &analysis.coverage).confidence_score,
            100
        );
        analysis.coverage.target_stable = false;
        assert_eq!(
            assess_file_verdict(&[], &analysis.coverage).confidence_score,
            0
        );
    }

    #[test]
    fn chunk_boundaries_match_independently_precomputed_vectors() {
        let temp = Temp::new();
        // Precomputed with Windows/.NET SHA implementations, not this streaming loop.
        for (size, sha256, sha512) in [
            (
                65536,
                "1f8745f0d2d1387ec1af2211a3cf417b2e9e885e853472649c1d979d0e9370e3",
                "b4885e27fb452980bee6ed67f36c8dead0f22f65b6e51b82abdb8a3000d70b63adeac2b1e7be8c0c75a342bd25e9a9f13ecd4b2e72bca634e020a5658b5effed",
            ),
            (
                131089,
                "e3c33f1a7c00a23610a13fa6b862df2882931be5b0262aeada7a47e282f1c679",
                "2a830923e3d2b477fb20bcd8197a4e4f391ab1214024e45a71dae011e9018fa0abe77742f2b8dded20eabc26b053acb2c34c9dbd055f6146ab17d81fbe2f5211",
            ),
        ] {
            let path = temp.file(&format!("boundary-{size}.txt"), &vec![b'x'; size]);
            let analysis = analyze_authorized_file(&authorized(&path), || false).unwrap();
            assert_eq!(analysis.hashes.sha256, sha256);
            assert_eq!(analysis.hashes.sha512, sha512);
            assert_eq!(analysis.hashes.bytes_hashed, size as u64);
        }
    }

    #[test]
    fn core_correlation_keeps_contradictory_indicators_and_deduplicates() {
        struct Ids(u64);
        impl edy_core::FindingIdSource for Ids {
            fn next_id(&mut self) -> edy_core::FindingId {
                self.0 += 1;
                edy_core::FindingId::new(format!("018f4c2a-1d3b-7abc-8def-{:012x}", self.0))
                    .unwrap()
            }
        }
        let temp = Temp::new();
        let path = temp.file("matrix.bin", &minimal_pe(false));
        let mut analysis = analyze_authorized_file(&authorized(&path), || false).unwrap();
        let mut signature = unsigned_authenticode();
        let mut reputation = analysis.reputation.clone();
        // An unavailable provider is a coverage gap, not risk evidence.
        assert!(
            correlate_file_evidence(&analysis.target, None, &signature, &[], &reputation)
                .is_empty()
        );
        signature.signature_present = true;
        signature.cryptographic_status = AuthenticodeStatus::Error;
        assert!(
            correlate_file_evidence(&analysis.target, None, &signature, &[], &reputation)
                .is_empty()
        );
        signature.cryptographic_status = AuthenticodeStatus::SignedInvalid;
        reputation.availability = Availability::Available;
        reputation.provider = Some("synthetic-provider".into());
        reputation.malicious_count = Some(2);
        analysis.findings = correlate_file_evidence(
            &analysis.target,
            Some(PeError::BadPeSignature),
            &signature,
            &[],
            &reputation,
        );
        assert_eq!(analysis.findings.len(), 3);
        analysis.findings.push(analysis.findings[0].clone());
        normalize_file_analysis(
            &mut analysis,
            &edy_core::ScanId::new("018f4c2a-1d3b-7abc-8def-0123456789d2").unwrap(),
            &edy_core::Timestamp::new("2026-09-02T00:00:00Z").unwrap(),
            &mut Ids(0),
        )
        .unwrap();
        assert_eq!(analysis.findings.len(), 3);
        assert_eq!(analysis.verdict.disposition, "suspicious");
        assert!(analysis.verdict.risk_score >= 70);
        signature.cryptographic_status = AuthenticodeStatus::SignedValidOffline;
        let conflicting =
            correlate_file_evidence(&analysis.target, None, &signature, &[], &reputation);
        assert_eq!(conflicting.len(), 1);
        assert_eq!(
            assess_file_verdict(&conflicting, &analysis.coverage).disposition,
            "suspicious"
        );
    }

    #[test]
    #[cfg(windows)]
    fn reparse_parent_is_rejected_without_following_the_fixture_junction() {
        use std::os::windows::process::CommandExt;
        let temp = Temp::new();
        let real = temp.0.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("benign.txt"), b"fixture").unwrap();
        let link = temp.0.join("link");
        let status = std::process::Command::new("cmd.exe")
            .args(["/d", "/c"])
            .raw_arg(format!(
                "mklink /J \"{}\" \"{}\"",
                display_path(&link),
                display_path(&real)
            ))
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "controlled junction fixture creation failed"
        );
        let result = inspect_file_target(
            &display_path(&link.join("benign.txt")),
            DEFAULT_MAX_FILE_SIZE,
        );
        std::fs::remove_dir(&link).unwrap();
        assert_eq!(
            result.unwrap_err().kind(),
            FileSecurityErrorKind::ReparsePoint
        );
    }

    #[test]
    #[cfg(windows)]
    fn publisher_metadata_is_bounded_sanitized_and_absent_state_is_safe() {
        assert_eq!(
            publisher_from_state(std::ptr::null_mut()),
            PublisherMetadata::default()
        );
        assert_eq!(
            sanitize_publisher_text("Publisher\n\u{202e}\t Name"),
            "Publisher Name"
        );
        assert_eq!(sanitize_publisher_text(&"X".repeat(4096)).len(), 512);
    }

    #[test]
    fn malformed_certificate_directory_is_not_classified_as_unsigned() {
        let mut bytes = minimal_pe(false);
        let security = 0x98 + 112 + 32;
        bytes[security..security + 4].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[security + 4..security + 8].copy_from_slice(&16_u32.to_le_bytes());
        assert_eq!(parse_pe(&bytes), Err(PeError::InvalidSecurityDirectory));
    }

    #[test]
    fn pe_parser_is_bounded_deterministic_and_handles_fuzz_like_matrix() {
        let valid = minimal_pe(false);
        let parsed = parse_pe(&valid).unwrap();
        assert_eq!(parsed.architecture, "x86_64");
        assert_eq!(parsed.entry_point_rva, 0x1000);
        assert_eq!(parsed.sections[0].name, ".text");
        assert!(!parsed.is_dll);
        assert!(parse_pe(&minimal_pe(true)).unwrap().is_dll);

        let cases = [
            (vec![0_u8; 2], PeError::TooShort),
            (vec![0_u8; 64], PeError::BadMz),
            (
                {
                    let mut v = valid.clone();
                    v[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
                    v
                },
                PeError::PeOffsetOutsideFile,
            ),
            (
                {
                    let mut v = valid.clone();
                    v[0x80] = b'X';
                    v
                },
                PeError::BadPeSignature,
            ),
            (
                {
                    let mut v = valid.clone();
                    v.truncate(0x88);
                    v
                },
                PeError::TruncatedCoff,
            ),
            (
                {
                    let mut v = valid.clone();
                    v[0x94..0x96].copy_from_slice(&0x1000_u16.to_le_bytes());
                    v
                },
                PeError::TruncatedOptionalHeader,
            ),
            (
                {
                    let mut v = valid.clone();
                    v[0x86..0x88].copy_from_slice(&97_u16.to_le_bytes());
                    v
                },
                PeError::AbsurdSectionCount,
            ),
            (
                {
                    let mut v = valid.clone();
                    v[0x86..0x88].copy_from_slice(&4_u16.to_le_bytes());
                    v
                },
                PeError::SectionTableOverflow,
            ),
        ];
        for (bytes, expected) in cases {
            assert_eq!(parse_pe(&bytes), Err(expected));
        }
    }

    #[test]
    #[cfg(windows)]
    fn offline_authenticode_result_mapping_never_invents_valid_crypto() {
        use windows_sys::Win32::Foundation::{
            CERT_E_UNTRUSTEDROOT, CRYPT_E_REVOCATION_OFFLINE, TRUST_E_BAD_DIGEST,
            TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_NOT_TRUSTED,
        };
        let valid = map_authenticode_result(0, true);
        assert_eq!(
            valid.cryptographic_status,
            AuthenticodeStatus::SignedValidOffline
        );
        assert_eq!(
            valid.trust_chain_status,
            AuthenticodeStatus::TrustChainValidOffline
        );
        for status in [CERT_E_UNTRUSTEDROOT, CRYPT_E_REVOCATION_OFFLINE] {
            let unavailable = map_authenticode_result(status, true);
            assert_eq!(
                unavailable.cryptographic_status,
                AuthenticodeStatus::Indeterminate
            );
            assert_eq!(
                unavailable.trust_chain_status,
                AuthenticodeStatus::TrustChainUnavailableOffline
            );
        }
        assert_eq!(
            map_authenticode_result(TRUST_E_BAD_DIGEST, true).cryptographic_status,
            AuthenticodeStatus::SignedInvalid
        );
        assert_eq!(
            map_authenticode_result(TRUST_E_SUBJECT_NOT_TRUSTED, true).cryptographic_status,
            AuthenticodeStatus::Error
        );
        assert_eq!(
            map_authenticode_result(-1, true).cryptographic_status,
            AuthenticodeStatus::Error
        );
        let malformed = map_authenticode_result(TRUST_E_NOSIGNATURE, true);
        assert!(malformed.signature_present);
        assert_eq!(malformed.cryptographic_status, AuthenticodeStatus::Error);
        let unsigned = map_authenticode_result(TRUST_E_NOSIGNATURE, false);
        assert!(!unsigned.signature_present);
        assert_eq!(unsigned.cryptographic_status, AuthenticodeStatus::Unsigned);
    }

    #[test]
    fn unsigned_file_and_conflicting_evidence_never_claim_safe() {
        let temp = Temp::new();
        let pe_path = temp.file("minimal-pe-synthetic.bin", &minimal_pe(false));
        let target = authorized(&pe_path);
        let analysis = analyze_authorized_file(&target, || false).unwrap();
        assert_eq!(
            analysis.authenticode.cryptographic_status,
            AuthenticodeStatus::Unsigned
        );
        assert_eq!(analysis.verdict.disposition, "insufficient_coverage");
        assert!(!analysis.verdict.disposition.contains("safe"));

        let signed = AuthenticodeInspection {
            signature_present: true,
            cryptographic_status: AuthenticodeStatus::SignedValidOffline,
            trust_chain_status: AuthenticodeStatus::TrustChainValidOffline,
            publisher: PublisherMetadata::default(),
            offline_cache_only: true,
        };
        let yara = YaraFileObservation {
            rule_id: "suspicious_fixture".into(),
            severity: Severity::High,
            synthetic_benign_marker: false,
            ruleset: YaraRulesetTrust {
                source: "project".into(),
                version: "1".into(),
                digest_sha256: "c".repeat(64),
                policy_state: "approved_fixture".into(),
            },
        };
        let findings =
            correlate_file_evidence(&target, None, &signed, &[yara], &analysis.reputation);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FileFindingCategory::YaraMatch);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn synthetic_marker_is_test_evidence_not_a_malicious_finding() {
        use crate::adapters::{CaptureOutcome, CapturedOutput, EngineAdapter, YaraXAdapter};
        let rules = include_bytes!("../tests/fixtures/level2/benign-marker.yar");
        let parsed = YaraXAdapter.parse(CapturedOutput {
            outcome: CaptureOutcome::Exited(0),
            stdout: br#"{"version":"1.20.0","matches":[{"rule":"EDY_LEVEL2_BENIGN_MARKER","file":"benign-text.txt"}]}"#,
            stderr: &[],
        }).unwrap();
        assert_eq!(parsed.observations.len(), 1);
        assert_eq!(
            parsed.observations[0].identifier,
            "EDY_LEVEL2_BENIGN_MARKER"
        );
        let temp = Temp::new();
        let file = temp.file("benign-text.txt", b"EDY_LEVEL2_BENIGN_MARKER");
        let target = authorized(&file);
        let analysis = analyze_authorized_file(&target, || false).unwrap();
        let marker = YaraFileObservation {
            rule_id: "EDY_LEVEL2_BENIGN_MARKER".into(),
            severity: Severity::Info,
            synthetic_benign_marker: true,
            ruleset: YaraRulesetTrust {
                source: "project-synthetic".into(),
                version: "1".into(),
                digest_sha256: format!("{:x}", Sha256::digest(rules)),
                policy_state: "synthetic_only".into(),
            },
        };
        assert!(
            correlate_file_evidence(
                &target,
                None,
                &analysis.authenticode,
                &[marker],
                &analysis.reputation
            )
            .is_empty()
        );
    }
}
