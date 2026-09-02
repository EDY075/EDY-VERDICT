use crate::{
    Availability, DomainError, EngineId, EvidenceId, FindingFingerprint, FindingId, FindingStatus,
    RemediationId, ScanId, ScanState, TargetId, Timestamp, ValidationErrorKind, validation,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn base_risk_score(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 20,
            Self::Medium => 40,
            Self::High => 70,
            Self::Critical => 90,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Repository,
    File,
    Binary,
    InstalledApplication,
    Url,
    Website,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "TargetLocatorWire")]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum TargetLocator {
    LocalPath(String),
    InstalledApplicationId(String),
    HttpsUrl(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
enum TargetLocatorWire {
    LocalPath(String),
    InstalledApplicationId(String),
    HttpsUrl(String),
}

impl TryFrom<TargetLocatorWire> for TargetLocator {
    type Error = DomainError;

    fn try_from(wire: TargetLocatorWire) -> Result<Self, Self::Error> {
        match wire {
            TargetLocatorWire::LocalPath(value) => Self::new_local_path(value),
            TargetLocatorWire::InstalledApplicationId(value) => Self::new_application_id(value),
            TargetLocatorWire::HttpsUrl(value) => Self::new_https_url(value),
        }
    }
}

impl TargetLocator {
    pub fn new_local_path(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validation::bounded_text("local_path", &value, 4096)?;
        let normalized = value.replace('\\', "/");
        let absolute = normalized.starts_with('/')
            || (normalized.len() >= 3
                && normalized.as_bytes()[0].is_ascii_alphabetic()
                && normalized.as_bytes()[1] == b':'
                && normalized.as_bytes()[2] == b'/');
        if !absolute
            || normalized
                .split('/')
                .any(|part| part == ".." || part == ".")
        {
            return Err(DomainError::new(
                "local_path",
                ValidationErrorKind::InvalidFormat,
            ));
        }
        Ok(Self::LocalPath(normalized))
    }

    pub fn new_application_id(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validation::bounded_text("application_id", &value, 512)?;
        Ok(Self::InstalledApplicationId(value))
    }

    pub fn new_https_url(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validation::bounded_text("https_url", &value, 2048)?;
        let Some(authority_and_path) = value.strip_prefix("https://") else {
            return Err(DomainError::new(
                "https_url",
                ValidationErrorKind::InvalidFormat,
            ));
        };
        if value.bytes().any(|byte| byte.is_ascii_whitespace()) || !value.is_ascii() {
            return Err(DomainError::new(
                "https_url",
                ValidationErrorKind::InvalidFormat,
            ));
        }
        let authority_end = authority_and_path
            .find(['/', '?'])
            .unwrap_or(authority_and_path.len());
        let authority = &authority_and_path[..authority_end];
        let (host, port) = authority
            .rsplit_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        let valid_host = !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            });
        let valid_port = port.is_none_or(|port| {
            !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|value| value != 0)
        });
        if authority.is_empty()
            || authority.contains('@')
            || !valid_host
            || !valid_port
            || value.contains('#')
            || authority_and_path[authority_end..].contains('\\')
        {
            return Err(DomainError::new(
                "https_url",
                ValidationErrorKind::InvalidFormat,
            ));
        }
        Ok(Self::HttpsUrl(value))
    }

    pub fn canonical(&self) -> String {
        match self {
            Self::LocalPath(value) => value.to_ascii_lowercase(),
            Self::InstalledApplicationId(value) => value.trim().to_ascii_lowercase(),
            Self::HttpsUrl(value) => {
                let suffix_start = value[8..]
                    .find(['/', '?'])
                    .map_or(value.len(), |index| index + 8);
                format!(
                    "{}{}",
                    value[..suffix_start].to_ascii_lowercase(),
                    &value[suffix_start..]
                )
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, try_from = "TargetWire")]
pub struct Target {
    id: TargetId,
    kind: TargetKind,
    locator: TargetLocator,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetWire {
    id: TargetId,
    kind: TargetKind,
    locator: TargetLocator,
}

impl TryFrom<TargetWire> for Target {
    type Error = DomainError;

    fn try_from(wire: TargetWire) -> Result<Self, Self::Error> {
        Self::new(wire.id, wire.kind, wire.locator)
    }
}

impl Target {
    pub fn new(
        id: TargetId,
        kind: TargetKind,
        locator: TargetLocator,
    ) -> Result<Self, DomainError> {
        let matches = matches!(
            (kind, &locator),
            (
                TargetKind::Repository | TargetKind::File | TargetKind::Binary,
                TargetLocator::LocalPath(_)
            ) | (
                TargetKind::InstalledApplication,
                TargetLocator::InstalledApplicationId(_)
            ) | (
                TargetKind::Url | TargetKind::Website,
                TargetLocator::HttpsUrl(_)
            )
        );
        if !matches {
            return Err(DomainError::new(
                "target_locator",
                ValidationErrorKind::Incoherent,
            ));
        }
        Ok(Self { id, kind, locator })
    }

    pub fn id(&self) -> &TargetId {
        &self.id
    }

    pub const fn kind(&self) -> TargetKind {
        self.kind
    }

    pub fn locator(&self) -> &TargetLocator {
        &self.locator
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(DomainError::new(
                "sha256",
                ValidationErrorKind::InvalidFormat,
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    EngineOutput,
    FileMetadata,
    Signature,
    VulnerabilityRecord,
    Reputation,
    Verification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "StructuredFactWire")]
#[serde(deny_unknown_fields)]
pub struct StructuredFact {
    pub key: String,
    pub value: String,
    pub redacted: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredFactWire {
    key: String,
    value: String,
    redacted: bool,
}

impl TryFrom<StructuredFactWire> for StructuredFact {
    type Error = DomainError;

    fn try_from(wire: StructuredFactWire) -> Result<Self, Self::Error> {
        Self::new(wire.key, wire.value, wire.redacted)
    }
}

impl StructuredFact {
    pub fn new(
        key: impl Into<String>,
        value: impl Into<String>,
        redacted: bool,
    ) -> Result<Self, DomainError> {
        let key = key.into();
        let value = value.into();
        validation::canonical_token("fact_key", &key, 64)?;
        validation::bounded_text("fact_value", &value, 2048)?;
        Ok(Self {
            key,
            value,
            redacted,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub producer: String,
    pub producer_version: String,
    pub observed_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "EvidenceDraft")]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    id: EvidenceId,
    kind: EvidenceKind,
    source: String,
    timestamp: Timestamp,
    digest: Sha256Digest,
    summary: String,
    structured_payload: Vec<StructuredFact>,
    raw_reference: Option<String>,
    provenance: EvidenceProvenance,
    redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDraft {
    pub id: EvidenceId,
    pub kind: EvidenceKind,
    pub source: String,
    pub timestamp: Timestamp,
    pub digest: Sha256Digest,
    pub summary: String,
    pub structured_payload: Vec<StructuredFact>,
    pub raw_reference: Option<String>,
    pub provenance: EvidenceProvenance,
    pub redacted: bool,
}

impl Evidence {
    pub fn new(draft: EvidenceDraft) -> Result<Self, DomainError> {
        let EvidenceDraft {
            id,
            kind,
            source,
            timestamp,
            digest,
            summary,
            structured_payload,
            raw_reference,
            provenance,
            redacted,
        } = draft;
        validation::bounded_text("evidence_source", &source, 256)?;
        validation::bounded_text("evidence_summary", &summary, 1024)?;
        validation::bounded_text("evidence_producer", &provenance.producer, 256)?;
        validation::bounded_text(
            "evidence_producer_version",
            &provenance.producer_version,
            64,
        )?;
        if structured_payload.len() > 128 {
            return Err(DomainError::new(
                "structured_payload",
                ValidationErrorKind::LimitExceeded,
            ));
        }
        let mut keys = BTreeSet::new();
        if structured_payload
            .iter()
            .any(|fact| !keys.insert(&fact.key))
        {
            return Err(DomainError::new(
                "structured_payload",
                ValidationErrorKind::Duplicate,
            ));
        }
        if let Some(reference) = &raw_reference {
            validation::bounded_text("raw_reference", reference, 2048)?;
        }
        Ok(Self {
            id,
            kind,
            source,
            timestamp,
            digest,
            summary,
            structured_payload,
            raw_reference,
            provenance,
            redacted,
        })
    }

    pub fn id(&self) -> &EvidenceId {
        &self.id
    }

    pub const fn kind(&self) -> EvidenceKind {
        self.kind
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
    pub fn summary(&self) -> &str {
        &self.summary
    }
    pub fn structured_payload(&self) -> &[StructuredFact] {
        &self.structured_payload
    }
    pub fn raw_reference(&self) -> Option<&str> {
        self.raw_reference.as_deref()
    }
    pub fn provenance(&self) -> &EvidenceProvenance {
        &self.provenance
    }
    pub const fn is_redacted(&self) -> bool {
        self.redacted
    }
}

impl TryFrom<EvidenceDraft> for Evidence {
    type Error = DomainError;

    fn try_from(draft: EvidenceDraft) -> Result<Self, Self::Error> {
        Self::new(draft)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSignal {
    Informational,
    Suspicious,
    Vulnerability,
    Malicious,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    Weak,
    Moderate,
    Strong,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "EngineObservationWire")]
#[serde(deny_unknown_fields)]
pub struct EngineObservation {
    pub engine: EngineId,
    pub engine_version: String,
    pub target_id: TargetId,
    pub rule_id: String,
    pub semantic_key: String,
    pub category: String,
    pub severity: Severity,
    pub location: String,
    pub message: String,
    pub evidence_id: EvidenceId,
    pub signal: ObservationSignal,
    pub evidence_strength: EvidenceStrength,
    pub parser_confidence: Confidence,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineObservationWire {
    engine: EngineId,
    engine_version: String,
    target_id: TargetId,
    rule_id: String,
    semantic_key: String,
    category: String,
    severity: Severity,
    location: String,
    message: String,
    evidence_id: EvidenceId,
    signal: ObservationSignal,
    evidence_strength: EvidenceStrength,
    parser_confidence: Confidence,
}

impl EngineObservation {
    pub fn validate(&self) -> Result<(), DomainError> {
        validation::bounded_text("engine_version", &self.engine_version, 64)?;
        validation::bounded_text("rule_id", &self.rule_id, 256)?;
        validation::bounded_text("semantic_key", &self.semantic_key, 512)?;
        validation::canonical_token("category", &self.category, 64)?;
        validation::bounded_text("location", &self.location, 4096)?;
        validation::bounded_text("message", &self.message, 2048)
    }
}

impl TryFrom<EngineObservationWire> for EngineObservation {
    type Error = DomainError;

    fn try_from(wire: EngineObservationWire) -> Result<Self, Self::Error> {
        let observation = Self {
            engine: wire.engine,
            engine_version: wire.engine_version,
            target_id: wire.target_id,
            rule_id: wire.rule_id,
            semantic_key: wire.semantic_key,
            category: wire.category,
            severity: wire.severity,
            location: wire.location,
            message: wire.message,
            evidence_id: wire.evidence_id,
            signal: wire.signal,
            evidence_strength: wire.evidence_strength,
            parser_confidence: wire.parser_confidence,
        };
        observation.validate()?;
        Ok(observation)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineRunState {
    Passed,
    Failed,
    Skipped,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct CoverageTask {
    pub engine: EngineId,
    pub target_id: TargetId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineCoverage {
    pub engine: EngineId,
    pub target_id: TargetId,
    pub state: EngineRunState,
    pub evidence_obtained: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "ProviderCoverageWire")]
#[serde(deny_unknown_fields)]
pub struct ProviderCoverage {
    pub id: String,
    pub availability: Availability,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderCoverageWire {
    id: String,
    availability: Availability,
}

impl TryFrom<ProviderCoverageWire> for ProviderCoverage {
    type Error = DomainError;

    fn try_from(wire: ProviderCoverageWire) -> Result<Self, Self::Error> {
        Self::new(wire.id, wire.availability)
    }
}

impl ProviderCoverage {
    pub fn new(id: impl Into<String>, availability: Availability) -> Result<Self, DomainError> {
        let id = id.into();
        validation::canonical_token("provider_id", &id, 64)?;
        Ok(Self { id, availability })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "ScanCoverageWire")]
#[serde(deny_unknown_fields)]
pub struct ScanCoverage {
    expected_tasks: Vec<CoverageTask>,
    engine_results: Vec<EngineCoverage>,
    provider_results: Vec<ProviderCoverage>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanCoverageWire {
    expected_tasks: Vec<CoverageTask>,
    engine_results: Vec<EngineCoverage>,
    #[serde(default)]
    provider_results: Vec<ProviderCoverage>,
}

impl ScanCoverage {
    pub fn new(
        expected_tasks: Vec<CoverageTask>,
        mut engine_results: Vec<EngineCoverage>,
    ) -> Result<Self, DomainError> {
        if expected_tasks.is_empty() || expected_tasks.len() > 64 {
            return Err(DomainError::new(
                "expected_tasks",
                ValidationErrorKind::OutOfRange,
            ));
        }
        let expected: BTreeSet<_> = expected_tasks.iter().collect();
        if expected.len() != expected_tasks.len() {
            return Err(DomainError::new(
                "expected_tasks",
                ValidationErrorKind::Duplicate,
            ));
        }
        let actual: BTreeSet<_> = engine_results
            .iter()
            .map(|result| (&result.engine, &result.target_id))
            .collect();
        let expected_keys: BTreeSet<_> = expected_tasks
            .iter()
            .map(|task| (&task.engine, &task.target_id))
            .collect();
        if actual.len() != engine_results.len() || actual != expected_keys {
            return Err(DomainError::new(
                "engine_results",
                ValidationErrorKind::Incoherent,
            ));
        }
        engine_results.sort_by(|left, right| {
            (&left.engine, &left.target_id).cmp(&(&right.engine, &right.target_id))
        });
        let mut expected_tasks = expected_tasks;
        expected_tasks.sort();
        Ok(Self {
            expected_tasks,
            engine_results,
            provider_results: Vec::new(),
        })
    }

    pub fn with_provider_results(
        mut self,
        mut provider_results: Vec<ProviderCoverage>,
    ) -> Result<Self, DomainError> {
        if provider_results.len() > 64 {
            return Err(DomainError::new(
                "provider_results",
                ValidationErrorKind::LimitExceeded,
            ));
        }
        for result in &provider_results {
            validation::canonical_token("provider_id", &result.id, 64)?;
        }
        provider_results.sort_by(|left, right| left.id.cmp(&right.id));
        if provider_results
            .windows(2)
            .any(|pair| pair[0].id == pair[1].id)
        {
            return Err(DomainError::new(
                "provider_results",
                ValidationErrorKind::Duplicate,
            ));
        }
        self.provider_results = provider_results;
        Ok(self)
    }

    pub fn expected_tasks(&self) -> &[CoverageTask] {
        &self.expected_tasks
    }

    pub fn engine_results(&self) -> &[EngineCoverage] {
        &self.engine_results
    }

    pub fn provider_results(&self) -> &[ProviderCoverage] {
        &self.provider_results
    }

    pub fn passed_count(&self) -> usize {
        self.engine_results
            .iter()
            .filter(|result| result.state == EngineRunState::Passed)
            .count()
    }

    pub fn evidence_count(&self) -> u32 {
        self.engine_results
            .iter()
            .map(|result| result.evidence_obtained)
            .sum()
    }

    pub fn is_complete(&self) -> bool {
        self.passed_count() == self.expected_tasks.len()
            && self
                .provider_results
                .iter()
                .all(|result| result.availability == Availability::Available)
    }

    pub fn has_failures(&self) -> bool {
        self.has_engine_failures() || self.has_provider_failures()
    }

    pub fn has_engine_failures(&self) -> bool {
        self.engine_results
            .iter()
            .any(|result| result.state != EngineRunState::Passed)
    }

    pub fn has_provider_failures(&self) -> bool {
        self.provider_results
            .iter()
            .any(|result| result.availability != Availability::Available)
    }
}

impl TryFrom<ScanCoverageWire> for ScanCoverage {
    type Error = DomainError;

    fn try_from(wire: ScanCoverageWire) -> Result<Self, Self::Error> {
        Self::new(wire.expected_tasks, wire.engine_results)?
            .with_provider_results(wire.provider_results)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "FindingWire")]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub(crate) id: FindingId,
    pub(crate) scan_id: ScanId,
    pub(crate) target_id: TargetId,
    pub(crate) source_engines: Vec<EngineId>,
    pub(crate) rule_ids: Vec<String>,
    pub(crate) title: String,
    pub(crate) description: String,
    pub(crate) category: String,
    pub(crate) severity: Severity,
    pub(crate) confidence: Confidence,
    pub(crate) status: FindingStatus,
    pub(crate) fingerprint: FindingFingerprint,
    pub(crate) first_seen: Timestamp,
    pub(crate) last_seen: Timestamp,
    pub(crate) evidence_ids: Vec<EvidenceId>,
    pub(crate) remediation_ids: Vec<RemediationId>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingWire {
    id: FindingId,
    scan_id: ScanId,
    target_id: TargetId,
    source_engines: Vec<EngineId>,
    rule_ids: Vec<String>,
    title: String,
    description: String,
    category: String,
    severity: Severity,
    confidence: Confidence,
    status: FindingStatus,
    fingerprint: FindingFingerprint,
    first_seen: Timestamp,
    last_seen: Timestamp,
    evidence_ids: Vec<EvidenceId>,
    remediation_ids: Vec<RemediationId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FindingDraft {
    pub id: FindingId,
    pub scan_id: ScanId,
    pub target_id: TargetId,
    pub source_engine: EngineId,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub fingerprint: FindingFingerprint,
    pub observed_at: Timestamp,
    pub evidence_id: EvidenceId,
}

impl Finding {
    pub fn new(draft: FindingDraft) -> Result<Self, DomainError> {
        let FindingDraft {
            id,
            scan_id,
            target_id,
            source_engine,
            rule_id,
            title,
            description,
            category,
            severity,
            confidence,
            fingerprint,
            observed_at,
            evidence_id,
        } = draft;
        validation::bounded_text("rule_id", &rule_id, 256)?;
        validation::bounded_text("title", &title, 256)?;
        validation::bounded_text("description", &description, 4096)?;
        validation::canonical_token("category", &category, 64)?;
        Ok(Self {
            id,
            scan_id,
            target_id,
            source_engines: vec![source_engine],
            rule_ids: vec![rule_id],
            title,
            description,
            category,
            severity,
            confidence,
            status: FindingStatus::Open,
            fingerprint,
            first_seen: observed_at.clone(),
            last_seen: observed_at,
            evidence_ids: vec![evidence_id],
            remediation_ids: Vec::new(),
        })
    }

    pub fn id(&self) -> &FindingId {
        &self.id
    }
    pub fn scan_id(&self) -> &ScanId {
        &self.scan_id
    }
    pub fn target_id(&self) -> &TargetId {
        &self.target_id
    }
    pub fn fingerprint(&self) -> &FindingFingerprint {
        &self.fingerprint
    }
    pub const fn severity(&self) -> Severity {
        self.severity
    }
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }
    pub const fn status(&self) -> FindingStatus {
        self.status
    }
    pub fn source_engines(&self) -> &[EngineId] {
        &self.source_engines
    }
    pub fn rule_ids(&self) -> &[String] {
        &self.rule_ids
    }
    pub fn title(&self) -> &str {
        &self.title
    }
    pub fn description(&self) -> &str {
        &self.description
    }
    pub fn category(&self) -> &str {
        &self.category
    }
    pub fn first_seen(&self) -> &Timestamp {
        &self.first_seen
    }
    pub fn last_seen(&self) -> &Timestamp {
        &self.last_seen
    }
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }
    pub fn remediation_ids(&self) -> &[RemediationId] {
        &self.remediation_ids
    }

    pub fn change_status(&mut self, next: FindingStatus) -> Result<(), DomainError> {
        self.status = self.status.transition(next)?;
        Ok(())
    }

    pub(crate) fn merge_observation(
        &mut self,
        observation: &EngineObservation,
        observed_at: &Timestamp,
    ) -> Result<(), DomainError> {
        if observation.target_id != self.target_id || observed_at < &self.first_seen {
            return Err(DomainError::new(
                "observation",
                ValidationErrorKind::Incoherent,
            ));
        }
        if !self.source_engines.contains(&observation.engine) {
            self.source_engines.push(observation.engine.clone());
            self.source_engines.sort();
        }
        if !self.rule_ids.contains(&observation.rule_id) {
            self.rule_ids.push(observation.rule_id.clone());
            self.rule_ids.sort();
        }
        if !self.evidence_ids.contains(&observation.evidence_id) {
            self.evidence_ids.push(observation.evidence_id.clone());
            self.evidence_ids.sort();
        }
        self.severity = self.severity.max(observation.severity);
        self.confidence = self.confidence.max(observation.parser_confidence);
        self.last_seen = observed_at.clone();
        Ok(())
    }

    pub fn reopen_regression(&mut self, observed_at: Timestamp) -> Result<(), DomainError> {
        if observed_at < self.last_seen {
            return Err(DomainError::new(
                "last_seen",
                ValidationErrorKind::Incoherent,
            ));
        }
        self.status = self.status.reopen_regression()?;
        self.last_seen = observed_at;
        Ok(())
    }
}

impl TryFrom<FindingWire> for Finding {
    type Error = DomainError;

    fn try_from(mut wire: FindingWire) -> Result<Self, Self::Error> {
        validation::bounded_text("title", &wire.title, 256)?;
        validation::bounded_text("description", &wire.description, 4096)?;
        validation::canonical_token("category", &wire.category, 64)?;
        if wire.source_engines.is_empty()
            || wire.source_engines.len() > 64
            || wire.rule_ids.is_empty()
            || wire.rule_ids.len() > 128
            || wire.evidence_ids.is_empty()
            || wire.evidence_ids.len() > 256
            || wire.remediation_ids.len() > 128
            || wire.first_seen > wire.last_seen
        {
            return Err(DomainError::new("finding", ValidationErrorKind::Incoherent));
        }
        for rule_id in &wire.rule_ids {
            validation::bounded_text("rule_id", rule_id, 256)?;
        }
        let unique = |length: usize, unique_length: usize| length == unique_length;
        if !unique(
            wire.source_engines.len(),
            wire.source_engines.iter().collect::<BTreeSet<_>>().len(),
        ) || !unique(
            wire.rule_ids.len(),
            wire.rule_ids.iter().collect::<BTreeSet<_>>().len(),
        ) || !unique(
            wire.evidence_ids.len(),
            wire.evidence_ids.iter().collect::<BTreeSet<_>>().len(),
        ) || !unique(
            wire.remediation_ids.len(),
            wire.remediation_ids.iter().collect::<BTreeSet<_>>().len(),
        ) {
            return Err(DomainError::new("finding", ValidationErrorKind::Duplicate));
        }
        wire.source_engines.sort();
        wire.rule_ids.sort();
        wire.evidence_ids.sort();
        wire.remediation_ids.sort();
        Ok(Self {
            id: wire.id,
            scan_id: wire.scan_id,
            target_id: wire.target_id,
            source_engines: wire.source_engines,
            rule_ids: wire.rule_ids,
            title: wire.title,
            description: wire.description,
            category: wire.category,
            severity: wire.severity,
            confidence: wire.confidence,
            status: wire.status,
            fingerprint: wire.fingerprint,
            first_seen: wire.first_seen,
            last_seen: wire.last_seen,
            evidence_ids: wire.evidence_ids,
            remediation_ids: wire.remediation_ids,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "ScanWire")]
#[serde(deny_unknown_fields)]
pub struct Scan {
    pub id: ScanId,
    pub targets: Vec<Target>,
    pub state: ScanState,
    pub created_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanWire {
    id: ScanId,
    targets: Vec<Target>,
    state: ScanState,
    created_at: Timestamp,
    started_at: Option<Timestamp>,
    finished_at: Option<Timestamp>,
}

impl TryFrom<ScanWire> for Scan {
    type Error = DomainError;

    fn try_from(wire: ScanWire) -> Result<Self, Self::Error> {
        if wire
            .started_at
            .as_ref()
            .is_some_and(|started| started < &wire.created_at)
            || wire.finished_at.as_ref().is_some_and(|finished| {
                finished < wire.started_at.as_ref().unwrap_or(&wire.created_at)
            })
        {
            return Err(DomainError::new(
                "scan_timestamps",
                ValidationErrorKind::Incoherent,
            ));
        }
        let coherent_state = match wire.state {
            ScanState::Queued => wire.started_at.is_none() && wire.finished_at.is_none(),
            ScanState::Preparing | ScanState::CancellationRequested => wire.finished_at.is_none(),
            ScanState::Running => wire.started_at.is_some() && wire.finished_at.is_none(),
            ScanState::Cancelled
            | ScanState::Completed
            | ScanState::Partial
            | ScanState::Failed => wire.finished_at.is_some(),
        };
        if !coherent_state {
            return Err(DomainError::new(
                "scan_state",
                ValidationErrorKind::Incoherent,
            ));
        }
        let mut scan = Self::new(wire.id, wire.targets, wire.created_at)?;
        scan.state = wire.state;
        scan.started_at = wire.started_at;
        scan.finished_at = wire.finished_at;
        Ok(scan)
    }
}

impl Scan {
    pub fn new(
        id: ScanId,
        targets: Vec<Target>,
        created_at: Timestamp,
    ) -> Result<Self, DomainError> {
        if targets.is_empty() || targets.len() > 128 {
            return Err(DomainError::new("targets", ValidationErrorKind::OutOfRange));
        }
        let unique: BTreeSet<_> = targets.iter().map(Target::id).collect();
        if unique.len() != targets.len() {
            return Err(DomainError::new("targets", ValidationErrorKind::Duplicate));
        }
        Ok(Self {
            id,
            targets,
            state: ScanState::Queued,
            created_at,
            started_at: None,
            finished_at: None,
        })
    }

    pub fn start(&mut self, at: Timestamp) -> Result<(), DomainError> {
        if at < self.created_at {
            return Err(DomainError::new(
                "started_at",
                ValidationErrorKind::Incoherent,
            ));
        }
        self.state = self
            .state
            .transition(ScanState::Preparing)?
            .transition(ScanState::Running)?;
        self.started_at = Some(at);
        Ok(())
    }

    pub fn finish(&mut self, state: ScanState, at: Timestamp) -> Result<(), DomainError> {
        if !matches!(
            state,
            ScanState::Completed | ScanState::Partial | ScanState::Failed | ScanState::Cancelled
        ) || self.started_at.as_ref().is_none_or(|started| at < *started)
        {
            return Err(DomainError::new(
                "finished_at",
                ValidationErrorKind::Incoherent,
            ));
        }
        self.state = if state == ScanState::Cancelled {
            self.state
                .transition(ScanState::CancellationRequested)?
                .transition(state)?
        } else {
            self.state.transition(state)?
        };
        self.finished_at = Some(at);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "UnavailableCheckWire")]
#[serde(deny_unknown_fields)]
pub struct UnavailableCheck {
    pub id: String,
    pub availability: Availability,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnavailableCheckWire {
    id: String,
    availability: Availability,
}

impl UnavailableCheck {
    pub fn new(id: impl Into<String>, availability: Availability) -> Result<Self, DomainError> {
        let id = id.into();
        validation::canonical_token("unavailable_check_id", &id, 64)?;
        if availability == Availability::Available {
            return Err(DomainError::new(
                "unavailable_check",
                ValidationErrorKind::Incoherent,
            ));
        }
        Ok(Self { id, availability })
    }
}

impl TryFrom<UnavailableCheckWire> for UnavailableCheck {
    type Error = DomainError;

    fn try_from(wire: UnavailableCheckWire) -> Result<Self, Self::Error> {
        Self::new(wire.id, wire.availability)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id<T>(constructor: impl FnOnce(String) -> Result<T, DomainError>, suffix: &str) -> T {
        constructor(format!("018f4c2a-1d3b-7abc-8def-0123456789{suffix}")).unwrap()
    }

    #[test]
    fn target_kind_and_locator_must_agree() {
        let target_id = id(TargetId::new, "ab");
        assert!(
            Target::new(
                target_id.clone(),
                TargetKind::Repository,
                TargetLocator::new_local_path("D:/fixture").unwrap()
            )
            .is_ok()
        );
        assert!(
            Target::new(
                target_id,
                TargetKind::Website,
                TargetLocator::new_local_path("D:/fixture").unwrap()
            )
            .is_err()
        );
        assert!(TargetLocator::new_https_url("http://example.invalid").is_err());
        assert!(TargetLocator::new_https_url("https://bad host.invalid").is_err());
        assert!(TargetLocator::new_local_path("relative/path").is_err());
        assert_ne!(
            TargetLocator::new_https_url("https://example.invalid/Case")
                .unwrap()
                .canonical(),
            TargetLocator::new_https_url("https://example.invalid/case")
                .unwrap()
                .canonical()
        );
    }

    #[test]
    fn coverage_never_turns_failure_into_complete() {
        let target_id = id(TargetId::new, "ad");
        let expected = vec![
            CoverageTask {
                engine: EngineId::new("a").unwrap(),
                target_id: target_id.clone(),
            },
            CoverageTask {
                engine: EngineId::new("b").unwrap(),
                target_id: target_id.clone(),
            },
        ];
        let coverage = ScanCoverage::new(
            expected,
            vec![
                EngineCoverage {
                    engine: EngineId::new("a").unwrap(),
                    target_id: target_id.clone(),
                    state: EngineRunState::Passed,
                    evidence_obtained: 1,
                },
                EngineCoverage {
                    engine: EngineId::new("b").unwrap(),
                    target_id,
                    state: EngineRunState::Failed,
                    evidence_obtained: 0,
                },
            ],
        )
        .unwrap();
        assert!(!coverage.is_complete());
        assert!(coverage.has_failures());
        let serialized = serde_json::to_value(&coverage).unwrap();
        assert_eq!(
            serde_json::from_value::<ScanCoverage>(serialized.clone()).unwrap(),
            coverage
        );
        let mut invalid = serialized;
        invalid["engine_results"] = serde_json::json!([]);
        assert!(serde_json::from_value::<ScanCoverage>(invalid).is_err());
    }

    #[test]
    fn evidence_rejects_duplicate_structured_keys() {
        let fact = StructuredFact::new("key", "value", false).unwrap();
        assert!(
            Evidence::new(EvidenceDraft {
                id: id(EvidenceId::new, "ac"),
                kind: EvidenceKind::EngineOutput,
                source: "fixture".into(),
                timestamp: Timestamp::new("2026-09-02T03:00:00Z").unwrap(),
                digest: Sha256Digest::new("a".repeat(64)).unwrap(),
                summary: "summary".into(),
                structured_payload: vec![fact.clone(), fact],
                raw_reference: None,
                provenance: EvidenceProvenance {
                    producer: "fixture".into(),
                    producer_version: "1".into(),
                    observed_at: Timestamp::new("2026-09-02T03:00:00Z").unwrap()
                },
                redacted: false,
            })
            .is_err()
        );
    }

    #[test]
    fn deserialization_reapplies_domain_validation() {
        let invalid_target = r#"{
            "id":"018f4c2a-1d3b-7abc-8def-0123456789ab",
            "kind":"website",
            "locator":{"type":"https_url","value":"http://example.invalid"}
        }"#;
        assert!(serde_json::from_str::<Target>(invalid_target).is_err());

        let evidence = Evidence::new(EvidenceDraft {
            id: id(EvidenceId::new, "ac"),
            kind: EvidenceKind::EngineOutput,
            source: "fixture".into(),
            timestamp: Timestamp::new("2026-09-02T03:00:00Z").unwrap(),
            digest: Sha256Digest::new("a".repeat(64)).unwrap(),
            summary: "summary".into(),
            structured_payload: vec![StructuredFact::new("key", "value", false).unwrap()],
            raw_reference: None,
            provenance: EvidenceProvenance {
                producer: "fixture".into(),
                producer_version: "1".into(),
                observed_at: Timestamp::new("2026-09-02T03:00:00Z").unwrap(),
            },
            redacted: false,
        })
        .unwrap();
        let evidence_value = serde_json::to_value(&evidence).unwrap();
        assert_eq!(
            serde_json::from_value::<Evidence>(evidence_value.clone()).unwrap(),
            evidence
        );
        let mut invalid_evidence = evidence_value;
        invalid_evidence["summary"] = serde_json::json!("");
        assert!(serde_json::from_value::<Evidence>(invalid_evidence).is_err());

        let finding = Finding::new(FindingDraft {
            id: id(FindingId::new, "ae"),
            scan_id: id(ScanId::new, "ab"),
            target_id: id(TargetId::new, "ad"),
            source_engine: EngineId::new("fixture").unwrap(),
            rule_id: "rule-1".into(),
            title: "synthetic finding".into(),
            description: "synthetic description".into(),
            category: "test".into(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            fingerprint: FindingFingerprint::parse("ffp1-00000000000000000000000000000000")
                .unwrap(),
            observed_at: Timestamp::new("2026-09-02T03:00:00Z").unwrap(),
            evidence_id: id(EvidenceId::new, "af"),
        })
        .unwrap();
        let finding_value = serde_json::to_value(&finding).unwrap();
        assert_eq!(
            serde_json::from_value::<Finding>(finding_value.clone()).unwrap(),
            finding
        );
        let mut invalid_finding = finding_value;
        invalid_finding["source_engines"] = serde_json::json!([]);
        assert!(serde_json::from_value::<Finding>(invalid_finding).is_err());

        let invalid_scan = r#"{
            "id":"018f4c2a-1d3b-7abc-8def-0123456789ab",
            "targets":[{
                "id":"018f4c2a-1d3b-7abc-8def-0123456789ac",
                "kind":"file",
                "locator":{"type":"local_path","value":"D:/fixture"}
            }],
            "state":"queued",
            "created_at":"2026-09-02T03:00:00Z",
            "started_at":null,
            "finished_at":"2026-09-02T03:01:00Z"
        }"#;
        assert!(serde_json::from_str::<Scan>(invalid_scan).is_err());
    }
}
