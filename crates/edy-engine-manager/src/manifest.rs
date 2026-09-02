use crate::receipt::EngineReceipt;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};

pub const ENGINE_MANIFEST_SCHEMA_VERSION: u32 = 2;
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PROCESS_TIMEOUT_MS: u64 = 600_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    ManifestVersionUnsupported { found: Option<u64>, supported: u32 },
    InvalidManifest(&'static str),
    PolicyBlocked(&'static str),
    SerializationFailed,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestVersionUnsupported { found, supported } => write!(
                formatter,
                "ManifestVersionUnsupported: found {}, expected schema_version {}; migrate to V2",
                found.map_or_else(|| "missing".to_owned(), |value| value.to_string()),
                supported
            ),
            Self::InvalidManifest(reason) => write!(formatter, "InvalidManifest: {reason}"),
            Self::PolicyBlocked(reason) => write!(formatter, "PolicyBlocked: {reason}"),
            Self::SerializationFailed => formatter.write_str("canonical serialization failed"),
        }
    }
}

impl std::error::Error for ContractError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineManifest {
    pub schema_version: u32,
    pub identity: EngineIdentity,
    pub source: EngineSource,
    pub artifact: EngineArtifact,
    pub provenance: Provenance,
    pub license: EngineLicense,
    pub extraction: ExtractionPolicy,
    pub process: ProcessPolicy,
    pub version_probe: VersionProbe,
    pub review: ContractReview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineIdentity {
    pub id: String,
    pub version: String,
    pub platform: Platform,
    pub architecture: Architecture,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Linux,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineSource {
    pub official_source: String,
    pub release_url: String,
    pub asset_url: String,
    pub asset_name: String,
    pub asset_size: u64,
    pub archive_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineArtifact {
    pub format: ArtifactFormat,
    pub entrypoint: String,
    pub entrypoint_size: u64,
    pub executable_sha256: String,
    pub auxiliary_hashes: Vec<AuxiliaryHash>,
    pub closed_set: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuxiliaryHash {
    pub relative_path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub evidence: Vec<ProvenanceEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceEvidence {
    #[serde(rename = "type")]
    pub evidence_type: ProvenanceType,
    pub status: EvidenceStatus,
    pub source: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<EvidenceDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceType {
    PublishedChecksum,
    SourceCommit,
    SignedCommit,
    SignedTag,
    Authenticode,
    Sigstore,
    Slsa,
    InToto,
    ReproducibleBuild,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Verified,
    PresentUnverified,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDigest {
    pub algorithm: DigestAlgorithm,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    Sha256,
    GitSha1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineLicense {
    pub spdx: String,
    pub source: String,
    pub redistribution_policy: RedistributionPolicy,
    pub notice_required: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RedistributionPolicy {
    Permitted,
    ReviewRequired,
    Prohibited,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtractionPolicy {
    pub max_archive_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_entries: u32,
    pub allowed_formats: Vec<ArtifactFormat>,
    pub reject_absolute_paths: bool,
    pub reject_parent_traversal: bool,
    pub reject_ads: bool,
    pub reject_links: bool,
    pub reject_case_collisions: bool,
    pub reject_duplicate_paths: bool,
}

impl ExtractionPolicy {
    pub fn secure_defaults(format: ArtifactFormat) -> Self {
        Self {
            max_archive_bytes: 128 * 1024 * 1024,
            max_expanded_bytes: 512 * 1024 * 1024,
            max_entries: 4096,
            allowed_formats: vec![format],
            reject_absolute_paths: true,
            reject_parent_traversal: true,
            reject_ads: true,
            reject_links: true,
            reject_case_collisions: true,
            reject_duplicate_paths: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    Zip,
    TarGz,
    RawExecutable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessPolicy {
    pub timeout_ms: u64,
    pub stdout_limit_bytes: u64,
    pub stderr_limit_bytes: u64,
    pub stdin_limit_bytes: u64,
    pub kill_process_tree: bool,
    pub shell: bool,
    pub network_policy: NetworkPolicy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    Deny,
    ProbeOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VersionProbe {
    pub args: Vec<String>,
    pub expected_exit_codes: Vec<i32>,
    pub expected_output: String,
    pub output_stream: OutputStream,
    pub network: bool,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
    Either,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContractReview {
    pub reviewed_at: String,
    pub reviewed_by_role: ReviewerRole,
    pub policy_version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerRole {
    JrOrchestrator,
}

impl EngineManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ContractError::InvalidManifest("manifest exceeds 256 KiB"));
        }
        let value = parse_unique_json(bytes)?;
        let found = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64);
        if found != Some(u64::from(ENGINE_MANIFEST_SCHEMA_VERSION)) {
            return Err(ContractError::ManifestVersionUnsupported {
                found,
                supported: ENGINE_MANIFEST_SCHEMA_VERSION,
            });
        }
        let manifest: Self = serde_json::from_value(value)
            .map_err(|_| ContractError::InvalidManifest("JSON does not match Contract V2"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != ENGINE_MANIFEST_SCHEMA_VERSION {
            return Err(ContractError::ManifestVersionUnsupported {
                found: Some(u64::from(self.schema_version)),
                supported: ENGINE_MANIFEST_SCHEMA_VERSION,
            });
        }
        if !canonical_token(&self.identity.id) || !version_token(&self.identity.version) {
            return Err(ContractError::InvalidManifest("invalid engine identity"));
        }
        self.source.validate()?;
        self.extraction.validate()?;
        if self.source.asset_size > self.extraction.max_archive_bytes
            || self.extraction.allowed_formats != [self.artifact.format]
        {
            return Err(ContractError::InvalidManifest(
                "asset size/format disagrees with extraction policy",
            ));
        }
        self.artifact.validate(&self.identity, &self.extraction)?;
        self.provenance.validate(&self.source, &self.artifact)?;
        self.license.validate()?;
        self.process.validate()?;
        self.version_probe.validate(&self.process)?;
        self.review.validate()?;
        Ok(())
    }

    /// Deterministic JSON V1: validated typed data, fixed struct field order, compact UTF-8,
    /// no maps, and canonically sorted set-like arrays. This is not RFC 8785/JCS.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut normalized = self.clone();
        normalized.artifact.auxiliary_hashes.sort_by(|left, right| {
            left.relative_path
                .to_ascii_lowercase()
                .cmp(&right.relative_path.to_ascii_lowercase())
        });
        normalized.provenance.evidence.sort_by(|left, right| {
            left.evidence_type
                .cmp(&right.evidence_type)
                .then_with(|| left.subject.cmp(&right.subject))
                .then_with(|| left.source.cmp(&right.source))
        });
        normalized.extraction.allowed_formats.sort();
        normalized.version_probe.expected_exit_codes.sort_unstable();
        serde_json::to_vec(&normalized).map_err(|_| ContractError::SerializationFailed)
    }

    pub fn canonical_sha256(&self) -> Result<String, ContractError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    pub fn declared_artifact_set_sha256(&self) -> Result<String, ContractError> {
        self.validate()?;
        let files = vec![ArtifactSetRecord {
            relative_path: self.artifact.entrypoint.clone(),
            sha256: self.artifact.executable_sha256.clone(),
            size: self.artifact.entrypoint_size,
        }]
        .into_iter()
        .chain(
            self.artifact
                .auxiliary_hashes
                .iter()
                .map(|file| ArtifactSetRecord {
                    relative_path: file.relative_path.clone(),
                    sha256: file.sha256.clone(),
                    size: file.size,
                }),
        )
        .collect();
        artifact_set_sha256(files)
    }
}

impl EngineSource {
    fn validate(&self) -> Result<(), ContractError> {
        if !https_url(&self.official_source)
            || !https_url(&self.release_url)
            || !https_url(&self.asset_url)
            || self.release_url.to_ascii_lowercase().contains("/latest")
            || self.asset_url.to_ascii_lowercase().contains("/latest")
            || !safe_component(&self.asset_name)
            || self.asset_size == 0
            || self.asset_size > MAX_ARCHIVE_BYTES
            || !sha256_valid(&self.archive_sha256)
        {
            return Err(ContractError::InvalidManifest(
                "invalid source or asset metadata",
            ));
        }
        Ok(())
    }
}

impl EngineArtifact {
    fn validate(
        &self,
        identity: &EngineIdentity,
        extraction: &ExtractionPolicy,
    ) -> Result<(), ContractError> {
        if !safe_relative(&self.entrypoint)
            || (identity.platform == Platform::Windows
                && !self.entrypoint.to_ascii_lowercase().ends_with(".exe"))
            || self.entrypoint_size == 0
            || !sha256_valid(&self.executable_sha256)
            || !self.closed_set
            || self.auxiliary_hashes.len() + 1 > extraction.max_entries as usize
        {
            return Err(ContractError::InvalidManifest(
                "invalid artifact identity or closed set",
            ));
        }
        let mut paths = BTreeSet::new();
        paths.insert(self.entrypoint.to_ascii_lowercase());
        let mut expanded_size = self.entrypoint_size;
        for file in &self.auxiliary_hashes {
            expanded_size = expanded_size
                .checked_add(file.size)
                .ok_or(ContractError::InvalidManifest("artifact sizes overflow"))?;
            if !safe_relative(&file.relative_path)
                || !sha256_valid(&file.sha256)
                || file.size == 0
                || !paths.insert(file.relative_path.to_ascii_lowercase())
            {
                return Err(ContractError::InvalidManifest(
                    "invalid or duplicate auxiliary artifact",
                ));
            }
        }
        if expanded_size > extraction.max_expanded_bytes {
            return Err(ContractError::InvalidManifest(
                "artifact set exceeds extraction policy",
            ));
        }
        Ok(())
    }
}

impl Provenance {
    fn validate(
        &self,
        source: &EngineSource,
        artifact: &EngineArtifact,
    ) -> Result<(), ContractError> {
        if self.evidence.is_empty() || self.evidence.len() > 32 {
            return Err(ContractError::InvalidManifest("invalid evidence count"));
        }
        let mut identities = BTreeSet::new();
        for evidence in &self.evidence {
            evidence.validate(source, artifact)?;
            let identity = format!(
                "{:?}\0{}\0{}",
                evidence.evidence_type,
                evidence.subject.to_ascii_lowercase(),
                evidence.source.to_ascii_lowercase()
            );
            if !identities.insert(identity) {
                return Err(ContractError::InvalidManifest(
                    "duplicate provenance evidence",
                ));
            }
        }
        Ok(())
    }
}

impl ProvenanceEvidence {
    fn validate(
        &self,
        source: &EngineSource,
        artifact: &EngineArtifact,
    ) -> Result<(), ContractError> {
        if !https_url(&self.source) || !bounded_text(&self.subject, 2048) {
            return Err(ContractError::InvalidManifest(
                "invalid evidence source or subject",
            ));
        }
        if let Some(digest) = &self.digest {
            digest.validate()?;
        }
        match self.status {
            EvidenceStatus::Verified => {
                if self.digest.is_none()
                    || !self
                        .verifier
                        .as_deref()
                        .is_some_and(|value| bounded_text(value, 128))
                    || !self.verified_at.as_deref().is_some_and(utc_timestamp_valid)
                {
                    return Err(ContractError::InvalidManifest(
                        "verified evidence lacks digest, verifier, or timestamp",
                    ));
                }
            }
            EvidenceStatus::PresentUnverified | EvidenceStatus::Unavailable => {
                if self.verifier.is_some() || self.verified_at.is_some() {
                    return Err(ContractError::InvalidManifest(
                        "unverified evidence cannot claim verifier or verification time",
                    ));
                }
                if self.status == EvidenceStatus::Unavailable && self.digest.is_some() {
                    return Err(ContractError::InvalidManifest(
                        "unavailable evidence cannot carry a digest",
                    ));
                }
            }
            EvidenceStatus::Failed => {
                if !self
                    .verifier
                    .as_deref()
                    .is_some_and(|value| bounded_text(value, 128))
                    || !self.verified_at.as_deref().is_some_and(utc_timestamp_valid)
                {
                    return Err(ContractError::InvalidManifest(
                        "failed verification must identify verifier and time",
                    ));
                }
            }
        }
        match self.evidence_type {
            ProvenanceType::PublishedChecksum | ProvenanceType::ReproducibleBuild => {
                if self.status != EvidenceStatus::Unavailable
                    && (self.subject != source.asset_name
                        || !matches!(
                            &self.digest,
                            Some(EvidenceDigest {
                                algorithm: DigestAlgorithm::Sha256,
                                value,
                            }) if value == &source.archive_sha256
                        ))
                {
                    return Err(ContractError::InvalidManifest(
                        "asset provenance is not bound to the selected asset hash",
                    ));
                }
            }
            ProvenanceType::Authenticode => {
                if self.status != EvidenceStatus::Unavailable
                    && (self.subject != artifact.entrypoint
                        || !matches!(
                            &self.digest,
                            Some(EvidenceDigest {
                                algorithm: DigestAlgorithm::Sha256,
                                value,
                            }) if value == &artifact.executable_sha256
                        ))
                {
                    return Err(ContractError::InvalidManifest(
                        "Authenticode evidence is not bound to the entrypoint hash",
                    ));
                }
            }
            ProvenanceType::Sigstore | ProvenanceType::Slsa | ProvenanceType::InToto => {
                if self.status != EvidenceStatus::Unavailable
                    && (self.subject != source.asset_name
                        || !matches!(
                            &self.digest,
                            Some(EvidenceDigest {
                                algorithm: DigestAlgorithm::Sha256,
                                value,
                            }) if value == &source.archive_sha256
                        ))
                {
                    return Err(ContractError::InvalidManifest(
                        "artifact attestation is not bound to the selected asset hash",
                    ));
                }
            }
            ProvenanceType::SourceCommit
            | ProvenanceType::SignedCommit
            | ProvenanceType::SignedTag => {
                if self.status != EvidenceStatus::Unavailable
                    && (!matches!(
                        &self.digest,
                        Some(EvidenceDigest {
                            algorithm: DigestAlgorithm::GitSha1,
                            ..
                        })
                    ) || !matches!(&self.digest, Some(EvidenceDigest { value, .. }) if value == &self.subject))
                {
                    return Err(ContractError::InvalidManifest(
                        "source/tag evidence must identify an exact Git object",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl EvidenceDigest {
    fn validate(&self) -> Result<(), ContractError> {
        let valid = match self.algorithm {
            DigestAlgorithm::Sha256 => sha256_valid(&self.value),
            DigestAlgorithm::GitSha1 => lowercase_hex(&self.value, 40),
        };
        if !valid {
            return Err(ContractError::InvalidManifest("invalid evidence digest"));
        }
        Ok(())
    }
}

impl EngineLicense {
    fn validate(&self) -> Result<(), ContractError> {
        if !spdx_expression(&self.spdx) || !https_url(&self.source) {
            return Err(ContractError::InvalidManifest(
                "invalid license declaration",
            ));
        }
        Ok(())
    }
}

impl ExtractionPolicy {
    fn validate(&self) -> Result<(), ContractError> {
        let formats: BTreeSet<_> = self.allowed_formats.iter().copied().collect();
        if self.max_archive_bytes == 0
            || self.max_archive_bytes > MAX_ARCHIVE_BYTES
            || self.max_expanded_bytes < self.max_archive_bytes
            || self.max_expanded_bytes > MAX_EXPANDED_BYTES
            || self.max_entries == 0
            || self.max_entries > 100_000
            || formats.len() != self.allowed_formats.len()
            || formats.is_empty()
            || !self.reject_absolute_paths
            || !self.reject_parent_traversal
            || !self.reject_ads
            || !self.reject_links
            || !self.reject_case_collisions
            || !self.reject_duplicate_paths
        {
            return Err(ContractError::InvalidManifest("unsafe extraction policy"));
        }
        Ok(())
    }
}

impl ProcessPolicy {
    fn validate(&self) -> Result<(), ContractError> {
        if self.timeout_ms == 0
            || self.timeout_ms > MAX_PROCESS_TIMEOUT_MS
            || self.stdout_limit_bytes == 0
            || self.stdout_limit_bytes > 16 * 1024 * 1024
            || self.stderr_limit_bytes == 0
            || self.stderr_limit_bytes > 4 * 1024 * 1024
            || self.stdin_limit_bytes > 1024 * 1024
            || !self.kill_process_tree
            || self.shell
        {
            return Err(ContractError::InvalidManifest("unsafe process policy"));
        }
        Ok(())
    }
}

impl VersionProbe {
    fn validate(&self, process: &ProcessPolicy) -> Result<(), ContractError> {
        let exit_codes: BTreeSet<_> = self.expected_exit_codes.iter().copied().collect();
        if self.args.is_empty()
            || self.args.len() > 16
            || self.args.iter().any(|argument| !probe_argument(argument))
            || self.expected_exit_codes.is_empty()
            || self.expected_exit_codes.len() > 8
            || self
                .expected_exit_codes
                .iter()
                .any(|code| !(-255..=255).contains(code))
            || exit_codes.len() != self.expected_exit_codes.len()
            || !bounded_text(&self.expected_output, 256)
            || self.timeout_ms == 0
            || self.timeout_ms > process.timeout_ms
            || (self.network && process.network_policy != NetworkPolicy::ProbeOnly)
        {
            return Err(ContractError::InvalidManifest("unsafe version probe"));
        }
        Ok(())
    }
}

impl ContractReview {
    fn validate(&self) -> Result<(), ContractError> {
        if !utc_timestamp_valid(&self.reviewed_at) || !version_token(&self.policy_version) {
            return Err(ContractError::InvalidManifest("invalid review metadata"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineTrustPolicy {
    required_evidence: Vec<ProvenanceType>,
    minimum_verified_evidence: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allowed,
}

impl EngineTrustPolicy {
    pub fn new(
        required_evidence: Vec<ProvenanceType>,
        minimum_verified_evidence: usize,
    ) -> Result<Self, ContractError> {
        let unique: BTreeSet<_> = required_evidence.iter().copied().collect();
        if required_evidence.is_empty()
            || required_evidence.len() > 16
            || unique.len() != required_evidence.len()
            || minimum_verified_evidence == 0
            || minimum_verified_evidence > 32
            || minimum_verified_evidence < required_evidence.len()
        {
            return Err(ContractError::PolicyBlocked("invalid trust policy"));
        }
        Ok(Self {
            required_evidence,
            minimum_verified_evidence,
        })
    }

    pub fn evaluate(&self, manifest: &EngineManifest) -> Result<PolicyDecision, ContractError> {
        manifest.validate()?;
        if manifest
            .provenance
            .evidence
            .iter()
            .any(|item| item.status == EvidenceStatus::Failed)
        {
            return Err(ContractError::PolicyBlocked(
                "provenance verification failed",
            ));
        }
        let verified: Vec<_> = manifest
            .provenance
            .evidence
            .iter()
            .filter(|item| item.status == EvidenceStatus::Verified)
            .collect();
        if verified.len() < self.minimum_verified_evidence
            || self
                .required_evidence
                .iter()
                .any(|required| !verified.iter().any(|item| item.evidence_type == *required))
        {
            return Err(ContractError::PolicyBlocked(
                "required verified provenance evidence is unavailable",
            ));
        }
        Ok(PolicyDecision::Allowed)
    }
}

pub struct EnginePaths {
    pub install: PathBuf,
    pub staging: PathBuf,
    pub receipts: PathBuf,
}

impl EnginePaths {
    pub fn from_root(root: &Path, manifest: &EngineManifest) -> Result<Self, ContractError> {
        manifest.validate()?;
        if !root.is_absolute() {
            return Err(ContractError::InvalidManifest(
                "absolute tools root required",
            ));
        }
        Ok(Self {
            install: root
                .join(&manifest.identity.id)
                .join(&manifest.identity.version),
            staging: root.join(".staging"),
            receipts: root.join("receipts"),
        })
    }
}

/// Acquisition remains deliberately disabled until a separate authorization.
pub trait Acquisition {
    fn acquire(
        &self,
        manifest: &EngineManifest,
        paths: &EnginePaths,
    ) -> Result<EngineReceipt, ContractError>;
}

pub struct DisabledAcquisition;

impl Acquisition for DisabledAcquisition {
    fn acquire(&self, _: &EngineManifest, _: &EnginePaths) -> Result<EngineReceipt, ContractError> {
        Err(ContractError::PolicyBlocked(
            "engine acquisition is not authorized in Level -1D.1",
        ))
    }
}

pub fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.contains([':', '\0', '\\'])
        && !value.starts_with('/')
        && value.split('/').all(safe_component)
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn safe_component(value: &str) -> bool {
    if !value.is_ascii()
        || value.is_empty()
        || value == "."
        || value == ".."
        || value.len() > 255
        || value.ends_with(['.', ' '])
        || value
            .chars()
            .any(|character| character < ' ' || "<>:\"/\\|?*".contains(character))
    {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) && !["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

pub fn sha256_valid(value: &str) -> bool {
    lowercase_hex(value, 64)
}

pub fn utc_timestamp_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || !bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| {
        std::str::from_utf8(&bytes[range])
            .ok()
            .and_then(|part| part.parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (2000..=9999).contains(&year)
        && (1..=max_day).contains(&day)
        && matches!(number(11..13), Some(0..=23))
        && matches!(number(14..16), Some(0..=59))
        && matches!(number(17..19), Some(0..=59))
}

pub(crate) fn canonical_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.contains("--")
        && !value.ends_with('-')
}

pub(crate) fn version_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        && !value.contains("..")
        && !value.eq_ignore_ascii_case("latest")
}

fn https_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    value.starts_with("https://")
        && value.len() <= 2048
        && rest.contains('/')
        && host.contains('.')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && !value.contains(['@', '\\', ' ', '\r', '\n', '\t', '\0', '#'])
        && !value.contains("/../")
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .chars()
            .any(|character| character == '\0' || character == '\r' || character == '\n')
}

fn spdx_expression(value: &str) -> bool {
    matches!(value, "MIT" | "Apache-2.0" | "BSD-3-Clause")
}

fn probe_argument(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('@')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && value != "."
        && value != ".."
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Serialize)]
pub(crate) struct ArtifactSetRecord {
    pub relative_path: String,
    pub sha256: String,
    pub size: u64,
}

pub(crate) fn artifact_set_sha256(
    mut files: Vec<ArtifactSetRecord>,
) -> Result<String, ContractError> {
    #[derive(Serialize)]
    struct ArtifactSet {
        files: Vec<ArtifactSetRecord>,
    }
    files.sort_by_key(|file| file.relative_path.to_ascii_lowercase());
    let bytes = serde_json::to_vec(&ArtifactSet { files })
        .map_err(|_| ContractError::SerializationFailed)?;
    Ok(sha256_hex(&bytes))
}

pub(crate) fn parse_unique_json(bytes: &[u8]) -> Result<serde_json::Value, ContractError> {
    let UniqueJson(value) = serde_json::from_slice(bytes)
        .map_err(|_| ContractError::InvalidManifest("malformed or duplicate-key JSON"))?;
    Ok(value)
}

struct UniqueJson(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(UniqueJson(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(UniqueJson(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        let mut object = serde_json::Map::new();
        while let Some((key, UniqueJson(value))) = map.next_entry::<String, UniqueJson>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            object.insert(key, value);
        }
        Ok(UniqueJson(serde_json::Value::Object(object)))
    }
}
