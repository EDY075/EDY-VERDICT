use crate::{AuthorizedRepositoryTarget, RepositoryFindingCategory, RepositoryObservation};
use edy_core::{
    Confidence, CorrelationEngine, EngineId, EngineObservation, EvidenceId, EvidenceStrength,
    Finding, FindingId, FindingIdSource, ObservationSignal, ScanId, Severity, Timestamp,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryEvidenceReference {
    pub evidence_id: String,
    pub source: String,
    pub rule_id: String,
    pub confidence: String,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorrelatedRepositoryFinding {
    pub id: String,
    pub fingerprint: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub status: String,
    pub affected_component: String,
    pub primary_source: String,
    pub supporting_sources: Vec<String>,
    pub rule_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub remediation_guidance: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryCorrelationResult {
    pub findings: Vec<CorrelatedRepositoryFinding>,
    pub evidence: Vec<RepositoryEvidenceReference>,
    pub unavailable_sources: Vec<String>,
}

pub fn correlate_repository_observations(
    scan_id: ScanId,
    target: &AuthorizedRepositoryTarget,
    observations: &[RepositoryObservation],
    unavailable_sources: &[String],
    observed_at: Timestamp,
) -> Result<RepositoryCorrelationResult, RepositoryCorrelationError> {
    let canonical_vulnerabilities = vulnerability_canonical_ids(observations);
    let mut normalized = Vec::new();
    let mut evidence = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, observation) in observations.iter().enumerate() {
        let identity = semantic_identity(observation, canonical_vulnerabilities.get(&index));
        let evidence_seed = format!(
            "{}\0{}\0{}",
            observation.engine_id, observation.fingerprint, identity
        );
        let evidence_id = EvidenceId::new(uuid_v7_from_seed(&evidence_seed))
            .map_err(|_| RepositoryCorrelationError::InvalidObservation)?;
        let unique = format!(
            "{}\0{}\0{}",
            observation.engine_id, identity, observation.location
        );
        if !seen.insert(unique) {
            continue;
        }
        let engine = EngineId::new(&observation.engine_id)
            .map_err(|_| RepositoryCorrelationError::InvalidObservation)?;
        normalized.push(EngineObservation {
            engine,
            engine_version: observation.engine_version.clone(),
            target_id: target.target().id().clone(),
            rule_id: observation.rule_id.clone(),
            semantic_key: identity,
            category: observation.category.token().into(),
            severity: severity(&observation.severity)?,
            location: observation.location.clone(),
            message: observation.description.clone(),
            evidence_id: evidence_id.clone(),
            signal: signal(observation.category),
            evidence_strength: if matches!(
                observation.category,
                RepositoryFindingCategory::SupplyChain | RepositoryFindingCategory::License
            ) {
                EvidenceStrength::Moderate
            } else {
                EvidenceStrength::Strong
            },
            parser_confidence: confidence(&observation.confidence)?,
        });
        evidence.push(RepositoryEvidenceReference {
            evidence_id: evidence_id.to_string(),
            source: observation.engine_id.clone(),
            rule_id: observation.rule_id.clone(),
            confidence: observation.confidence.clone(),
            location: observation.location.clone(),
        });
    }
    normalized.sort_by(|a, b| {
        (&a.category, &a.semantic_key, &a.location, &a.engine).cmp(&(
            &b.category,
            &b.semantic_key,
            &b.location,
            &b.engine,
        ))
    });
    evidence.sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));
    let mut ids = DeterministicFindingIds {
        scan: scan_id.to_string(),
        index: 0,
    };
    let findings = CorrelationEngine::correlate(
        &scan_id,
        target.target(),
        &normalized,
        &observed_at,
        &mut ids,
    )
    .map_err(|_| RepositoryCorrelationError::Domain)?;
    let evidence_by_id = evidence
        .iter()
        .map(|item| (item.evidence_id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let mut correlated = findings
        .iter()
        .map(|finding| correlated_finding(finding, &evidence_by_id))
        .collect::<Vec<_>>();
    correlated.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    let mut unavailable_sources = unavailable_sources.to_vec();
    unavailable_sources.sort();
    unavailable_sources.dedup();
    Ok(RepositoryCorrelationResult {
        findings: correlated,
        evidence,
        unavailable_sources,
    })
}

fn correlated_finding(
    finding: &Finding,
    evidence: &BTreeMap<&str, &RepositoryEvidenceReference>,
) -> CorrelatedRepositoryFinding {
    let supporting_sources = finding
        .source_engines()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let affected_component = finding
        .evidence_ids()
        .iter()
        .find_map(|id| evidence.get(id.as_str()).map(|item| item.location.clone()))
        .unwrap_or_else(|| "repository".into());
    CorrelatedRepositoryFinding {
        id: finding.id().to_string(), fingerprint: finding.fingerprint().to_string(), title: finding.title().into(),
        description: finding.description().into(), category: finding.category().into(), severity: severity_label(finding.severity()).into(),
        confidence: confidence_label(finding.confidence()).into(), status: "open".into(), affected_component,
        primary_source: supporting_sources.first().cloned().unwrap_or_else(|| "unavailable".into()), supporting_sources,
        rule_ids: finding.rule_ids().to_vec(), evidence_ids: finding.evidence_ids().iter().map(ToString::to_string).collect(),
        remediation_guidance: remediation(finding.category()).into(),
        limitations: vec!["Live engine execution remains policy-blocked; this result is synthetic or parser-validated.".into()],
    }
}

fn semantic_identity(
    observation: &RepositoryObservation,
    canonical_vulnerability: Option<&String>,
) -> String {
    match observation.category {
        RepositoryFindingCategory::VulnerableDependency => format!(
            "{}:{}:{}",
            observation.package.as_deref().unwrap_or("unknown"),
            observation
                .installed_version
                .as_deref()
                .unwrap_or("unknown"),
            canonical_vulnerability
                .or(observation.vulnerability_id.as_ref())
                .map(String::as_str)
                .unwrap_or(&observation.rule_id)
        ),
        RepositoryFindingCategory::Secret => format!(
            "{}:{}",
            observation.rule_id,
            observation
                .secret_digest
                .as_deref()
                .unwrap_or(&observation.fingerprint)
        ),
        RepositoryFindingCategory::Misconfiguration => observation.rule_id.clone(),
        RepositoryFindingCategory::SupplyChain => format!(
            "{}:{}",
            observation.rule_id,
            observation.package.as_deref().unwrap_or("repository")
        ),
        RepositoryFindingCategory::License => format!(
            "{}:{}:{}",
            observation.rule_id,
            observation.package.as_deref().unwrap_or("repository"),
            observation
                .metadata
                .get("license_status")
                .map(String::as_str)
                .unwrap_or("unknown")
        ),
        RepositoryFindingCategory::SuspiciousRepositoryArtifact => observation.rule_id.clone(),
    }
}

fn vulnerability_canonical_ids(observations: &[RepositoryObservation]) -> BTreeMap<usize, String> {
    let mut result = BTreeMap::new();
    for (index, item) in observations
        .iter()
        .enumerate()
        .filter(|(_, item)| item.category == RepositoryFindingCategory::VulnerableDependency)
    {
        let mut equivalent = identifiers(item);
        loop {
            let before = equivalent.len();
            for other in observations
                .iter()
                .filter(|other| other.category == RepositoryFindingCategory::VulnerableDependency)
            {
                let other_ids = identifiers(other);
                if !equivalent.is_disjoint(&other_ids) {
                    equivalent.extend(other_ids);
                }
            }
            if equivalent.len() == before {
                break;
            }
        }
        if let Some(canonical) = equivalent
            .into_iter()
            .min_by_key(|id| (identifier_priority(id), id.clone()))
        {
            result.insert(index, canonical);
        }
    }
    result
}
fn identifiers(item: &RepositoryObservation) -> BTreeSet<String> {
    item.vulnerability_id
        .iter()
        .chain(item.aliases.iter())
        .map(|id| id.to_ascii_uppercase())
        .collect()
}
fn identifier_priority(id: &str) -> u8 {
    if id.starts_with("CVE-") {
        0
    } else if id.starts_with("GHSA-") {
        1
    } else {
        2
    }
}
fn severity(value: &str) -> Result<Severity, RepositoryCorrelationError> {
    match value {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(RepositoryCorrelationError::InvalidObservation),
    }
}
fn confidence(value: &str) -> Result<Confidence, RepositoryCorrelationError> {
    match value {
        "low" => Ok(Confidence::Low),
        "medium" => Ok(Confidence::Medium),
        "high" => Ok(Confidence::High),
        _ => Err(RepositoryCorrelationError::InvalidObservation),
    }
}
fn signal(category: RepositoryFindingCategory) -> ObservationSignal {
    match category {
        RepositoryFindingCategory::VulnerableDependency => ObservationSignal::Vulnerability,
        RepositoryFindingCategory::Secret
        | RepositoryFindingCategory::Misconfiguration
        | RepositoryFindingCategory::SuspiciousRepositoryArtifact => ObservationSignal::Suspicious,
        RepositoryFindingCategory::SupplyChain | RepositoryFindingCategory::License => {
            ObservationSignal::Informational
        }
    }
}
fn severity_label(value: Severity) -> &'static str {
    match value {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
fn confidence_label(value: Confidence) -> &'static str {
    match value {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}
fn remediation(category: &str) -> &'static str {
    match category {
        "secret" => {
            "Revoke the credential if real, remove it from history, and verify with a rescan."
        }
        "vulnerable_dependency" => {
            "Review the authoritative advisory and upgrade to a verified fixed version when available."
        }
        "misconfiguration" => {
            "Review the rule, apply the smallest safe configuration change, and verify it."
        }
        "supply_chain" => {
            "Restore deterministic dependency metadata or vulnerability-data coverage and reassess."
        }
        "license" => "Perform technical policy review and obtain legal review when required.",
        _ => "Review the evidence and verify the affected component.",
    }
}

struct DeterministicFindingIds {
    scan: String,
    index: u64,
}
impl FindingIdSource for DeterministicFindingIds {
    fn next_id(&mut self) -> FindingId {
        let seed = format!("{}:{}", self.scan, self.index);
        self.index += 1;
        FindingId::new(uuid_v7_from_seed(&seed)).expect("derived UUID is valid")
    }
}
fn uuid_v7_from_seed(seed: &str) -> String {
    let mut bytes: [u8; 16] = Sha256::digest(seed.as_bytes())[..16]
        .try_into()
        .expect("digest length");
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryCorrelationError {
    InvalidObservation,
    Domain,
}
impl std::fmt::Display for RepositoryCorrelationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("repository correlation failed safely")
    }
}
impl std::error::Error for RepositoryCorrelationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RepositoryLimits, finding_fingerprint};
    use edy_core::TargetId;
    use std::{collections::BTreeMap, fs, path::PathBuf};
    fn target() -> AuthorizedRepositoryTarget {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/correlation-fixture");
        fs::create_dir_all(&root).unwrap();
        let canonical = fs::canonicalize(root).unwrap();
        let text = canonical.to_string_lossy();
        let portable = text.strip_prefix(r"\\?\").unwrap_or(&text);
        AuthorizedRepositoryTarget::authorize(
            portable,
            TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789b1").unwrap(),
            "018f4c2a-1d3b-7abc-8def-0123456789b2",
            "2026-09-02T13:00:00Z",
            RepositoryLimits::default(),
        )
        .unwrap()
    }
    fn observation(
        target: &AuthorizedRepositoryTarget,
        engine: &str,
        category: RepositoryFindingCategory,
        rule: &str,
        location: &str,
    ) -> RepositoryObservation {
        RepositoryObservation {
            engine_id: engine.into(),
            engine_version: "1.0.0".into(),
            category,
            rule_id: rule.into(),
            description: format!("{category:?} synthetic observation"),
            location: location.into(),
            line: Some(1),
            severity: "high".into(),
            confidence: "high".into(),
            fingerprint_version: "TEST_V1".into(),
            fingerprint: finding_fingerprint("TEST_V1", target, &[rule, location]),
            package: None,
            installed_version: None,
            vulnerability_id: None,
            aliases: vec![],
            affected_range: None,
            fixed_version: None,
            source: Some(engine.into()),
            secret_class: None,
            secret_preview: None,
            secret_digest: None,
            license: None,
            metadata: BTreeMap::new(),
        }
    }
    fn correlate(
        target: &AuthorizedRepositoryTarget,
        items: &[RepositoryObservation],
    ) -> RepositoryCorrelationResult {
        correlate_repository_observations(
            ScanId::new("018f4c2a-1d3b-7abc-8def-0123456789b3").unwrap(),
            target,
            items,
            &["offline-data".into()],
            Timestamp::new("2026-09-02T13:00:01Z").unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn same_vulnerability_from_osv_and_trivy_aliases_merges_without_evidence_loss() {
        let t = target();
        let mut a = observation(
            &t,
            "osv-scanner",
            RepositoryFindingCategory::VulnerableDependency,
            "GHSA-TEST",
            "Cargo.lock",
        );
        a.package = Some("crates.io:demo".into());
        a.installed_version = Some("1.0.0".into());
        a.vulnerability_id = Some("GHSA-TEST".into());
        a.aliases = vec!["CVE-2099-0001".into()];
        let mut b = observation(
            &t,
            "trivy",
            RepositoryFindingCategory::VulnerableDependency,
            "CVE-2099-0001",
            "Cargo.lock",
        );
        b.package = a.package.clone();
        b.installed_version = a.installed_version.clone();
        b.vulnerability_id = Some("CVE-2099-0001".into());
        b.aliases = vec!["GHSA-TEST".into()];
        let result = correlate(&t, &[a, b]);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].supporting_sources,
            vec!["osv-scanner", "trivy"]
        );
        assert_eq!(result.findings[0].evidence_ids.len(), 2);
    }
    #[test]
    fn different_vulnerabilities_same_package_do_not_merge() {
        let t = target();
        let mut a = observation(
            &t,
            "osv-scanner",
            RepositoryFindingCategory::VulnerableDependency,
            "CVE-2099-0001",
            "Cargo.lock",
        );
        a.package = Some("demo".into());
        a.installed_version = Some("1".into());
        a.vulnerability_id = Some("CVE-2099-0001".into());
        let mut b = a.clone();
        b.rule_id = "CVE-2099-0002".into();
        b.vulnerability_id = Some("CVE-2099-0002".into());
        assert_eq!(correlate(&t, &[a, b]).findings.len(), 2);
    }
    #[test]
    fn secrets_deduplicate_by_digest_and_location_but_not_across_files() {
        let t = target();
        let mut a = observation(
            &t,
            "gitleaks",
            RepositoryFindingCategory::Secret,
            "token",
            "a.env",
        );
        a.secret_digest = Some("digest-a".into());
        let duplicate = a.clone();
        let mut other = a.clone();
        other.location = "b.env".into();
        let result = correlate(&t, &[a, duplicate, other]);
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.evidence.len(), 2);
    }
    #[test]
    fn duplicate_misconfiguration_merges_and_unavailable_source_is_preserved() {
        let t = target();
        let a = observation(
            &t,
            "trivy",
            RepositoryFindingCategory::Misconfiguration,
            "CFG-1",
            "config.json",
        );
        let mut b = a.clone();
        b.engine_id = "config-audit".into();
        let first = correlate(&t, &[a.clone(), b.clone()]);
        let second = correlate(&t, &[b, a]);
        assert_eq!(first, second);
        assert_eq!(first.findings.len(), 1);
        assert_eq!(first.findings[0].evidence_ids.len(), 2);
        assert_eq!(first.unavailable_sources, vec!["offline-data"]);
    }
    #[test]
    fn conflicting_source_metadata_does_not_discard_sources() {
        let t = target();
        let mut a = observation(
            &t,
            "osv-scanner",
            RepositoryFindingCategory::VulnerableDependency,
            "CVE-2099-0001",
            "Cargo.lock",
        );
        a.package = Some("demo".into());
        a.installed_version = Some("1".into());
        a.vulnerability_id = Some("CVE-2099-0001".into());
        a.fixed_version = Some("2".into());
        let mut b = a.clone();
        b.engine_id = "trivy".into();
        b.fixed_version = Some("3".into());
        let result = correlate(&t, &[a, b]);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].supporting_sources.len(), 2);
    }
}
