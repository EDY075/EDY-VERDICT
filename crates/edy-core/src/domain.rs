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
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum TargetLocator {
    LocalPath(String),
    InstalledApplicationId(String),
    HttpsUrl(String),
}

impl TargetLocator {
    pub fn new_local_path(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validation::bounded_text("local_path", &value, 4096)?;
        let normalized = value.replace('\\', "/");
        if normalized
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
        let authority = authority_and_path.split('/').next().unwrap_or("");
        if authority.is_empty()
            || authority.contains('@')
            || authority.starts_with('.')
            || authority.ends_with('.')
            || value.contains('#')
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
            Self::HttpsUrl(value) => value.to_ascii_lowercase(),
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
#[serde(deny_unknown_fields)]
pub struct StructuredFact {
    pub key: String,
    pub value: String,
    pub redacted: bool,
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
#[serde(deny_unknown_fields)]
pub struct ScanCoverage {
    expected_tasks: Vec<CoverageTask>,
    engine_results: Vec<EngineCoverage>,
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
        })
    }

    pub fn expected_tasks(&self) -> &[CoverageTask] {
        &self.expected_tasks
    }

    pub fn engine_results(&self) -> &[EngineCoverage] {
        &self.engine_results
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
    }

    pub fn has_failures(&self) -> bool {
        self.engine_results
            .iter()
            .any(|result| result.state != EngineRunState::Passed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scan {
    pub id: ScanId,
    pub targets: Vec<Target>,
    pub state: ScanState,
    pub created_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
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
#[serde(deny_unknown_fields)]
pub struct UnavailableCheck {
    pub id: String,
    pub availability: Availability,
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
}
