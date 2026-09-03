//! Deterministic, bounded Level 5 cross-target correlation and investigation contracts.
//! Strong identity is required for every automatic relationship. Correlation groups
//! evidence; it never proves causation, compromise, or organization-wide impact.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const INVESTIGATION_SCHEMA: &str = "LEVEL5_INVESTIGATION_V1";
pub const ENTITY_ID_SCHEMA: &str = "ENTITY_ID_V1";
pub const RULE_SHARED_CVE: &str = "L5-RULE-SHARED-CVE-V1";
pub const RULE_SHARED_ARTIFACT: &str = "L5-RULE-SHARED-ARTIFACT-V1";
pub const RULE_SHARED_COMPONENT: &str = "L5-RULE-SHARED-COMPONENT-V1";
pub const RULE_SHARED_ORIGIN: &str = "L5-RULE-SHARED-WEB-ORIGIN-V1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Repository,
    SoftwarePackage,
    InstalledApplication,
    FileArtifact,
    Vulnerability,
    Url,
    WebOrigin,
    Domain,
    Publisher,
    ScanTarget,
    Finding,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierKind {
    RepositorySnapshot,
    Purl,
    Cpe,
    MsiProduct,
    MsixPackage,
    Sha256,
    Cve,
    CanonicalUrl,
    WebOrigin,
    Domain,
    ProviderIdentity,
    StableTarget,
    StableFinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StrongIdentity {
    pub kind: IdentifierKind,
    pub canonical_value: String,
}

impl StrongIdentity {
    pub fn new(kind: IdentifierKind, value: impl Into<String>) -> Result<Self, InvestigationError> {
        let value = value.into();
        if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
            return Err(InvestigationError::InvalidIdentity);
        }
        let valid = match kind {
            IdentifierKind::Sha256 => is_lower_hex(&value, 64),
            IdentifierKind::Cve => canonical_cve(&value).as_deref() == Some(value.as_str()),
            IdentifierKind::Purl => {
                value.starts_with("pkg:") && !value.contains(char::is_whitespace)
            }
            IdentifierKind::Cpe => {
                value.starts_with("cpe:2.3:") && !value.contains(char::is_whitespace)
            }
            IdentifierKind::WebOrigin => {
                (value.starts_with("https://") || value.starts_with("http://"))
                    && !value.contains('@')
                    && !value.contains('?')
                    && !value.contains('#')
            }
            IdentifierKind::CanonicalUrl => {
                (value.starts_with("https://") || value.starts_with("http://"))
                    && !value.contains('@')
                    && !value.contains('#')
            }
            IdentifierKind::Domain => valid_domain(&value),
            _ => value.len() <= 512,
        };
        if !valid || forbidden_material(&value) {
            return Err(InvestigationError::InvalidIdentity);
        }
        Ok(Self {
            kind,
            canonical_value: value,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntityNode {
    pub entity_id: String,
    pub schema: String,
    pub kind: EntityKind,
    pub identity: StrongIdentity,
    pub label_safe: String,
}

impl EntityNode {
    pub fn new(
        kind: EntityKind,
        identity: StrongIdentity,
        label: &str,
    ) -> Result<Self, InvestigationError> {
        let label_safe = safe_text(label, 160)?;
        let mut digest = Sha256::new();
        digest.update(ENTITY_ID_SCHEMA.as_bytes());
        digest.update([0]);
        digest.update(format!("{:?}", kind).as_bytes());
        digest.update([0]);
        digest.update(format!("{:?}", identity.kind).as_bytes());
        digest.update([0]);
        digest.update(identity.canonical_value.as_bytes());
        Ok(Self {
            entity_id: format!("ent-v1-{:x}", digest.finalize()),
            schema: ENTITY_ID_SCHEMA.into(),
            kind,
            identity,
            label_safe,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    Repository,
    File,
    InstalledApplication,
    WebUrl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorrelationFinding {
    pub finding_id: String,
    pub target_id: String,
    pub target_type: TargetType,
    pub target_identity: StrongIdentity,
    pub affected_identity: StrongIdentity,
    pub vulnerability_id: Option<String>,
    pub artifact_sha256: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub web_origin: Option<String>,
    pub web_domain: Option<String>,
    pub evidence_ids: Vec<String>,
    pub source_scans: Vec<String>,
    pub severity_points: u8,
    pub kev: bool,
    pub epss_basis_points: Option<u16>,
    pub provider_available: bool,
    pub parser_certain: bool,
    pub conflicting_evidence: bool,
    pub first_seen: String,
    pub last_seen: String,
    pub occurrence_count: u32,
    pub reopened: bool,
}

impl CorrelationFinding {
    pub fn validate(&self) -> Result<(), InvestigationError> {
        if self.finding_id.is_empty()
            || self.finding_id.len() > 128
            || self.target_id.is_empty()
            || self.target_id.len() > 128
            || self.evidence_ids.is_empty()
            || self.evidence_ids.len() > 32
            || self.source_scans.is_empty()
            || self.source_scans.len() > 32
            || self.severity_points > 100
            || self.occurrence_count == 0
            || forbidden_material(&self.finding_id)
            || forbidden_material(&self.target_id)
        {
            return Err(InvestigationError::InvalidFinding);
        }
        if let Some(cve) = &self.vulnerability_id
            && canonical_cve(cve).as_ref() != Some(cve)
        {
            return Err(InvestigationError::InvalidFinding);
        }
        if let Some(hash) = &self.artifact_sha256
            && !is_lower_hex(hash, 64)
        {
            return Err(InvestigationError::InvalidFinding);
        }
        if self.epss_basis_points.is_some_and(|value| value > 10_000)
            || self
                .evidence_ids
                .iter()
                .any(|v| v.is_empty() || v.len() > 128 || forbidden_material(v))
            || self
                .source_scans
                .iter()
                .any(|v| v.is_empty() || v.len() > 128 || forbidden_material(v))
        {
            return Err(InvestigationError::InvalidFinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    TargetContainsComponent,
    FindingAffectsEntity,
    PackageHasVulnerability,
    ApplicationHasVulnerability,
    FileHasHash,
    FileAssociatedWithApplication,
    UrlBelongsToOrigin,
    OriginBelongsToDomain,
    FindingSupportedByEvidence,
    FindingsShareVulnerability,
    FindingsShareArtifact,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelationshipEdge {
    pub edge_id: String,
    pub relationship: RelationshipType,
    pub from_entity: String,
    pub to_entity: String,
    pub rule_id: String,
    pub evidence_ids: Vec<String>,
    pub source_scans: Vec<String>,
    pub created_by: String,
    pub confidence: u8,
    pub reasoning_safe: String,
    pub schema_version: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ClusterType {
    SharedVulnerability,
    SharedArtifact,
    SharedComponent,
    SharedWebOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FindingCluster {
    pub cluster_id: String,
    pub cluster_type: ClusterType,
    pub member_findings: Vec<String>,
    pub member_entities: Vec<String>,
    pub supporting_edges: Vec<String>,
    pub target_count: u32,
    pub evidence_count: u32,
    pub first_seen: String,
    pub last_seen: String,
    pub explanation_safe: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Suggested,
    Open,
    Investigating,
    Remediating,
    VerificationPending,
    Resolved,
    AcceptedRisk,
    Ignored,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CasePriority {
    Immediate,
    High,
    Normal,
    Low,
    Review,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BlastRadius {
    pub observed_only: bool,
    pub unique_affected_targets: u32,
    pub unique_affected_components: u32,
    pub unique_findings: u32,
    pub unique_vulnerability_ids: u32,
    pub target_types_affected: Vec<TargetType>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionAssessment {
    pub risk: u8,
    pub confidence: u8,
    pub coverage: u8,
    pub priority: CasePriority,
    pub risk_reasons: Vec<String>,
    pub confidence_reasons: Vec<String>,
    pub coverage_reasons: Vec<String>,
    pub priority_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimelineEvent {
    pub sequence: u32,
    pub timestamp: String,
    pub event_type: String,
    pub summary_safe: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaseTransition {
    pub from: CaseStatus,
    pub to: CaseStatus,
    pub timestamp: String,
    pub actor_source: String,
    pub reason_safe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InvestigationCase {
    pub case_id: String,
    pub title_safe: String,
    pub status: CaseStatus,
    pub suggested: bool,
    pub finding_ids: Vec<String>,
    pub cluster_ids: Vec<String>,
    pub entity_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub blast_radius: BlastRadius,
    pub assessment: DecisionAssessment,
    pub timeline: Vec<TimelineEvent>,
    pub transitions: Vec<CaseTransition>,
}

impl InvestigationCase {
    pub fn transition(
        &mut self,
        to: CaseStatus,
        timestamp: &str,
        actor: &str,
        reason: &str,
    ) -> Result<(), InvestigationError> {
        let allowed = matches!(
            (self.status, to),
            (CaseStatus::Suggested, CaseStatus::Open)
                | (
                    CaseStatus::Open,
                    CaseStatus::Investigating | CaseStatus::AcceptedRisk | CaseStatus::Ignored
                )
                | (
                    CaseStatus::Investigating,
                    CaseStatus::Remediating | CaseStatus::Resolved | CaseStatus::AcceptedRisk
                )
                | (CaseStatus::Remediating, CaseStatus::VerificationPending)
                | (
                    CaseStatus::VerificationPending,
                    CaseStatus::Resolved | CaseStatus::Investigating
                )
                | (CaseStatus::Resolved, CaseStatus::Open)
        );
        if !allowed {
            return Err(InvestigationError::InvalidTransition);
        }
        let transition = CaseTransition {
            from: self.status,
            to,
            timestamp: safe_text(timestamp, 40)?,
            actor_source: safe_text(actor, 80)?,
            reason_safe: safe_text(reason, 512)?,
        };
        self.status = to;
        self.transitions.push(transition.clone());
        self.timeline.push(TimelineEvent {
            sequence: self.timeline.len() as u32 + 1,
            timestamp: transition.timestamp,
            event_type: if transition.from == CaseStatus::Resolved && to == CaseStatus::Open {
                "finding_reopened".into()
            } else {
                "lifecycle_changed".into()
            },
            summary_safe: format!("Case moved from {:?} to {:?}", transition.from, to),
            source: transition.actor_source,
        });
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphLimits {
    pub nodes_per_run: usize,
    pub edges_per_run: usize,
    pub findings_per_case: usize,
    pub clusters_per_case: usize,
    pub evidence_refs_per_relation: usize,
    pub timeline_events: usize,
    pub traversal_depth: usize,
}

impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            nodes_per_run: 10_000,
            edges_per_run: 20_000,
            findings_per_case: 1_000,
            clusters_per_case: 500,
            evidence_refs_per_relation: 32,
            timeline_events: 2_000,
            traversal_depth: 16,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationRunState {
    Complete,
    PartialCorrelation,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorrelationResult {
    pub schema: String,
    pub state: CorrelationRunState,
    pub limit_reached: bool,
    pub nodes: Vec<EntityNode>,
    pub edges: Vec<RelationshipEdge>,
    pub clusters: Vec<FindingCluster>,
    pub suggested_cases: Vec<InvestigationCase>,
    pub findings_preserved: u32,
    pub rules_executed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvestigationError {
    InvalidIdentity,
    InvalidFinding,
    UnsafeText,
    InvalidTransition,
    DuplicateFinding,
}

impl std::fmt::Display for InvestigationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidIdentity => "Strong identity was refused",
            Self::InvalidFinding => "Correlation finding was refused",
            Self::UnsafeText => "Unsafe investigation text was refused",
            Self::InvalidTransition => "Case lifecycle transition was refused",
            Self::DuplicateFinding => "Duplicate finding identifier was refused",
        })
    }
}
impl std::error::Error for InvestigationError {}

pub fn correlate_investigation<F: FnMut() -> bool>(
    mut findings: Vec<CorrelationFinding>,
    limits: GraphLimits,
    mut cancelled: F,
) -> Result<CorrelationResult, InvestigationError> {
    findings.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    let mut seen = BTreeSet::new();
    for finding in &findings {
        finding.validate()?;
        if !seen.insert(finding.finding_id.clone()) {
            return Err(InvestigationError::DuplicateFinding);
        }
    }
    if cancelled() {
        return Ok(cancelled_result());
    }
    let original_count = findings.len() as u32;
    let mut nodes = BTreeMap::<String, EntityNode>::new();
    let mut finding_entities = BTreeMap::new();
    let mut affected_entities = BTreeMap::new();
    for finding in &findings {
        if cancelled() {
            return Ok(cancelled_result());
        }
        let finding_node = EntityNode::new(
            EntityKind::Finding,
            StrongIdentity::new(IdentifierKind::StableFinding, finding.finding_id.clone())?,
            "Correlated finding",
        )?;
        let target_node = EntityNode::new(
            EntityKind::ScanTarget,
            finding.target_identity.clone(),
            target_label(finding.target_type),
        )?;
        let affected_kind = match finding.target_type {
            TargetType::Repository => EntityKind::SoftwarePackage,
            TargetType::File => EntityKind::FileArtifact,
            TargetType::InstalledApplication => EntityKind::InstalledApplication,
            TargetType::WebUrl => EntityKind::Url,
        };
        let affected_node = EntityNode::new(
            affected_kind,
            finding.affected_identity.clone(),
            "Affected component",
        )?;
        finding_entities.insert(finding.finding_id.clone(), finding_node.entity_id.clone());
        affected_entities.insert(finding.finding_id.clone(), affected_node.entity_id.clone());
        for node in [finding_node, target_node, affected_node] {
            nodes.entry(node.entity_id.clone()).or_insert(node);
        }
        for (kind, value, entity_kind, label) in [
            (
                IdentifierKind::Cve,
                finding.vulnerability_id.as_ref(),
                EntityKind::Vulnerability,
                "Vulnerability",
            ),
            (
                IdentifierKind::Sha256,
                finding.artifact_sha256.as_ref(),
                EntityKind::FileArtifact,
                "File artifact",
            ),
            (
                IdentifierKind::Purl,
                finding.purl.as_ref(),
                EntityKind::SoftwarePackage,
                "Package",
            ),
            (
                IdentifierKind::Cpe,
                finding.cpe.as_ref(),
                EntityKind::SoftwarePackage,
                "CPE component",
            ),
            (
                IdentifierKind::WebOrigin,
                finding.web_origin.as_ref(),
                EntityKind::WebOrigin,
                "Web origin",
            ),
            (
                IdentifierKind::Domain,
                finding.web_domain.as_ref(),
                EntityKind::Domain,
                "Domain",
            ),
        ] {
            if let Some(value) = value {
                let node = EntityNode::new(
                    entity_kind,
                    StrongIdentity::new(kind, value.clone())?,
                    label,
                )?;
                nodes.entry(node.entity_id.clone()).or_insert(node);
            }
        }
        if nodes.len() > limits.nodes_per_run {
            return Ok(partial_result(nodes, original_count));
        }
    }
    let mut edges = Vec::new();
    let mut clusters = Vec::new();
    build_keyed_clusters(
        &findings,
        &finding_entities,
        &affected_entities,
        &mut edges,
        &mut clusters,
        &limits,
        |f| f.vulnerability_id.clone(),
        ClusterType::SharedVulnerability,
        RelationshipType::FindingsShareVulnerability,
        RULE_SHARED_CVE,
        "These findings share an exact canonical CVE but affect separate assets; they were clustered and not deduplicated.",
    )?;
    build_keyed_clusters(
        &findings,
        &finding_entities,
        &affected_entities,
        &mut edges,
        &mut clusters,
        &limits,
        |f| f.artifact_sha256.clone(),
        ClusterType::SharedArtifact,
        RelationshipType::FindingsShareArtifact,
        RULE_SHARED_ARTIFACT,
        "These findings share an exact SHA-256 artifact identity.",
    )?;
    build_keyed_clusters(
        &findings,
        &finding_entities,
        &affected_entities,
        &mut edges,
        &mut clusters,
        &limits,
        |f| f.purl.clone().or_else(|| f.cpe.clone()),
        ClusterType::SharedComponent,
        RelationshipType::TargetContainsComponent,
        RULE_SHARED_COMPONENT,
        "These findings share an exact PURL or CPE component identity.",
    )?;
    build_keyed_clusters(
        &findings,
        &finding_entities,
        &affected_entities,
        &mut edges,
        &mut clusters,
        &limits,
        |f| f.web_origin.clone(),
        ClusterType::SharedWebOrigin,
        RelationshipType::UrlBelongsToOrigin,
        RULE_SHARED_ORIGIN,
        "These findings share one normalized web origin; URL paths remain separate.",
    )?;
    if edges.len() > limits.edges_per_run || clusters.len() > limits.clusters_per_case {
        return Ok(partial_result(nodes, original_count));
    }
    if cancelled() {
        return Ok(cancelled_result());
    }
    clusters.sort_by(|a, b| a.cluster_id.cmp(&b.cluster_id));
    edges.sort_by(|a, b| a.edge_id.cmp(&b.edge_id));
    let suggested_cases = clusters
        .iter()
        .filter_map(|cluster| suggest_case(cluster, &findings, &affected_entities, &limits).ok())
        .collect();
    Ok(CorrelationResult {
        schema: INVESTIGATION_SCHEMA.into(),
        state: CorrelationRunState::Complete,
        limit_reached: false,
        nodes: nodes.into_values().collect(),
        edges,
        clusters,
        suggested_cases,
        findings_preserved: original_count,
        rules_executed: vec![
            RULE_SHARED_CVE.into(),
            RULE_SHARED_ARTIFACT.into(),
            RULE_SHARED_COMPONENT.into(),
            RULE_SHARED_ORIGIN.into(),
        ],
    })
}

#[allow(clippy::too_many_arguments)]
fn build_keyed_clusters<K: Fn(&CorrelationFinding) -> Option<String>>(
    findings: &[CorrelationFinding],
    finding_entities: &BTreeMap<String, String>,
    affected_entities: &BTreeMap<String, String>,
    edges: &mut Vec<RelationshipEdge>,
    clusters: &mut Vec<FindingCluster>,
    limits: &GraphLimits,
    key: K,
    cluster_type: ClusterType,
    relation: RelationshipType,
    rule: &str,
    explanation: &str,
) -> Result<(), InvestigationError> {
    let mut index: BTreeMap<String, Vec<&CorrelationFinding>> = BTreeMap::new();
    for finding in findings {
        if let Some(value) = key(finding) {
            index.entry(value).or_default().push(finding);
        }
    }
    for (identity, members) in index.into_iter().filter(|(_, m)| m.len() > 1) {
        let target_count = members
            .iter()
            .map(|f| &f.target_id)
            .collect::<BTreeSet<_>>()
            .len();
        if target_count < 2 && cluster_type != ClusterType::SharedWebOrigin {
            continue;
        }
        let mut member_findings = members
            .iter()
            .map(|f| f.finding_id.clone())
            .collect::<Vec<_>>();
        member_findings.sort();
        if member_findings.len() > limits.findings_per_case {
            continue;
        }
        let member_entities = members
            .iter()
            .filter_map(|f| affected_entities.get(&f.finding_id).cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut evidence = members
            .iter()
            .flat_map(|f| f.evidence_ids.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        evidence.truncate(limits.evidence_refs_per_relation);
        let scans = members
            .iter()
            .flat_map(|f| f.source_scans.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut supporting = Vec::new();
        for pair in member_findings.windows(2) {
            let from = finding_entities[&pair[0]].clone();
            let to = finding_entities[&pair[1]].clone();
            let edge_id = stable_id("edge-v1", &[rule, &from, &to, &identity]);
            supporting.push(edge_id.clone());
            edges.push(RelationshipEdge {
                edge_id,
                relationship: relation,
                from_entity: from,
                to_entity: to,
                rule_id: rule.into(),
                evidence_ids: evidence.clone(),
                source_scans: scans.clone(),
                created_by: "deterministic-rule-engine".into(),
                confidence: if members.iter().any(|f| f.conflicting_evidence) {
                    70
                } else {
                    95
                },
                reasoning_safe: explanation.into(),
                schema_version: 1,
            });
        }
        let first_seen = members
            .iter()
            .map(|f| f.first_seen.as_str())
            .min()
            .unwrap_or_default()
            .to_string();
        let last_seen = members
            .iter()
            .map(|f| f.last_seen.as_str())
            .max()
            .unwrap_or_default()
            .to_string();
        clusters.push(FindingCluster {
            cluster_id: stable_id("cluster-v1", &[rule, &identity, &member_findings.join("|")]),
            cluster_type,
            member_findings,
            member_entities,
            supporting_edges: supporting,
            target_count: target_count as u32,
            evidence_count: evidence.len() as u32,
            first_seen,
            last_seen,
            explanation_safe: explanation.into(),
        });
    }
    Ok(())
}

fn suggest_case(
    cluster: &FindingCluster,
    findings: &[CorrelationFinding],
    affected: &BTreeMap<String, String>,
    limits: &GraphLimits,
) -> Result<InvestigationCase, InvestigationError> {
    let members = findings
        .iter()
        .filter(|f| cluster.member_findings.binary_search(&f.finding_id).is_ok())
        .collect::<Vec<_>>();
    let targets = members
        .iter()
        .map(|f| f.target_id.clone())
        .collect::<BTreeSet<_>>();
    let types = members
        .iter()
        .map(|f| f.target_type)
        .collect::<BTreeSet<_>>();
    let vulns = members
        .iter()
        .filter_map(|f| f.vulnerability_id.clone())
        .collect::<BTreeSet<_>>();
    let blast = BlastRadius {
        observed_only: true,
        unique_affected_targets: targets.len() as u32,
        unique_affected_components: cluster.member_entities.len() as u32,
        unique_findings: members.len() as u32,
        unique_vulnerability_ids: vulns.len() as u32,
        target_types_affected: types.into_iter().collect(),
    };
    let assessment = assess_case(&members, &blast);
    let case_id = stable_id("case-v1", &[&cluster.cluster_id]);
    let evidence = members
        .iter()
        .flat_map(|f| f.evidence_ids.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(limits.evidence_refs_per_relation * limits.clusters_per_case.min(4))
        .collect();
    let entities = members
        .iter()
        .filter_map(|f| affected.get(&f.finding_id).cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(InvestigationCase{case_id,title_safe:"Suggested cross-target investigation".into(),status:CaseStatus::Suggested,suggested:true,finding_ids:cluster.member_findings.clone(),cluster_ids:vec![cluster.cluster_id.clone()],entity_ids:entities,evidence_ids:evidence,blast_radius:blast,assessment,timeline:vec![TimelineEvent{sequence:1,timestamp:cluster.last_seen.clone(),event_type:"case_suggested".into(),summary_safe:"A strong deterministic cross-target correlation suggested review; no incident is claimed.".into(),source:"correlation-rule-engine".into()}],transitions:Vec::new()})
}

fn assess_case(findings: &[&CorrelationFinding], blast: &BlastRadius) -> DecisionAssessment {
    let severity = findings
        .iter()
        .map(|f| f.severity_points)
        .max()
        .unwrap_or(0);
    let kev = findings.iter().any(|f| f.kev);
    let high_epss = findings
        .iter()
        .any(|f| f.epss_basis_points.is_some_and(|v| v >= 7000));
    let strong_sources = findings
        .iter()
        .flat_map(|f| f.source_scans.iter())
        .collect::<BTreeSet<_>>()
        .len()
        > 1;
    let mut risk = severity;
    let mut risk_reasons = vec![format!(
        "Maximum original technical severity contributes {severity} points"
    )];
    if kev {
        risk = risk.saturating_add(15);
        risk_reasons.push("Synthetic/validated KEV signal is present".into());
    }
    if high_epss {
        risk = risk.saturating_add(10);
        risk_reasons.push("High EPSS signal is present".into());
    }
    if blast.unique_affected_targets > 1 {
        risk = risk.saturating_add(10);
        risk_reasons.push(format!(
            "{} observed targets are affected",
            blast.unique_affected_targets
        ));
    }
    if blast.target_types_affected.len() > 1 {
        risk = risk.saturating_add(5);
        risk_reasons.push(format!(
            "{} target types are represented",
            blast.target_types_affected.len()
        ));
    }
    risk = risk.min(100);
    let unavailable = findings.iter().filter(|f| !f.provider_available).count() as u8;
    let conflicts = findings.iter().filter(|f| f.conflicting_evidence).count() as u8;
    let uncertain = findings.iter().filter(|f| !f.parser_certain).count() as u8;
    let confidence = (70u8 + (if strong_sources { 15 } else { 0 }))
        .saturating_sub(unavailable.saturating_mul(10))
        .saturating_sub(conflicts.saturating_mul(15))
        .saturating_sub(uncertain.saturating_mul(10))
        .min(100);
    let coverage = 100u8
        .saturating_sub(unavailable.saturating_mul(20))
        .min(100);
    let priority = if kev && risk >= 70 {
        CasePriority::Immediate
    } else if risk >= 70 {
        CasePriority::High
    } else if confidence < 50 {
        CasePriority::Review
    } else if risk >= 35 {
        CasePriority::Normal
    } else {
        CasePriority::Low
    };
    let mut priority_reasons = Vec::new();
    if kev {
        priority_reasons.push("Known exploited vulnerability signal".into());
    }
    if blast.unique_affected_targets > 1 {
        priority_reasons.push(format!(
            "{} affected targets",
            blast.unique_affected_targets
        ));
    }
    if strong_sources {
        priority_reasons.push("Strong deterministic multi-source identity".into());
    }
    DecisionAssessment {
        risk,
        confidence,
        coverage,
        priority,
        risk_reasons,
        confidence_reasons: vec![
            format!(
                "Independent sources: {}",
                if strong_sources { "multiple" } else { "single" }
            ),
            format!("Conflicting evidence records: {conflicts}"),
        ],
        coverage_reasons: vec![
            format!("Unavailable providers: {unavailable}"),
            "Coverage applies only to associated analyzed targets".into(),
        ],
        priority_reasons,
    }
}

fn cancelled_result() -> CorrelationResult {
    CorrelationResult {
        schema: INVESTIGATION_SCHEMA.into(),
        state: CorrelationRunState::Cancelled,
        limit_reached: false,
        nodes: Vec::new(),
        edges: Vec::new(),
        clusters: Vec::new(),
        suggested_cases: Vec::new(),
        findings_preserved: 0,
        rules_executed: Vec::new(),
    }
}
fn partial_result(nodes: BTreeMap<String, EntityNode>, count: u32) -> CorrelationResult {
    CorrelationResult {
        schema: INVESTIGATION_SCHEMA.into(),
        state: CorrelationRunState::PartialCorrelation,
        limit_reached: true,
        nodes: nodes.into_values().collect(),
        edges: Vec::new(),
        clusters: Vec::new(),
        suggested_cases: Vec::new(),
        findings_preserved: count,
        rules_executed: Vec::new(),
    }
}
fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut d = Sha256::new();
    d.update(prefix.as_bytes());
    for part in parts {
        d.update([0]);
        d.update(part.as_bytes());
    }
    format!("{prefix}-{:x}", d.finalize())
}
fn target_label(kind: TargetType) -> &'static str {
    match kind {
        TargetType::Repository => "Repository target",
        TargetType::File => "File target",
        TargetType::InstalledApplication => "Installed application target",
        TargetType::WebUrl => "Web URL target",
    }
}
fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn canonical_cve(value: &str) -> Option<String> {
    let parts = value.split('-').collect::<Vec<_>>();
    if parts.len() == 3
        && parts[0] == "CVE"
        && parts[1].len() == 4
        && parts[1].bytes().all(|b| b.is_ascii_digit())
        && parts[2].len() >= 4
        && parts[2].bytes().all(|b| b.is_ascii_digit())
    {
        Some(value.into())
    } else {
        None
    }
}
fn valid_domain(value: &str) -> bool {
    value.len() <= 253
        && !value.is_empty()
        && !value.contains("..")
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn forbidden_material(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("edy_fake_secret")
        || lower.contains("edy_fake_cookie")
        || lower.contains("edy_fake_query")
        || lower.contains("authorization: bearer")
        || lower.contains("private key")
}
fn safe_text(value: &str, max: usize) -> Result<String, InvestigationError> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(char::is_control)
        || forbidden_material(value)
    {
        Err(InvestigationError::UnsafeText)
    } else {
        Ok(value.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn f(
        id: &str,
        target: &str,
        target_type: TargetType,
        cve: Option<&str>,
        hash: Option<&str>,
        purl: Option<&str>,
        origin: Option<&str>,
    ) -> CorrelationFinding {
        CorrelationFinding {
            finding_id: id.into(),
            target_id: target.into(),
            target_type,
            target_identity: StrongIdentity::new(IdentifierKind::StableTarget, target).unwrap(),
            affected_identity: StrongIdentity::new(
                match target_type {
                    TargetType::Repository => IdentifierKind::Purl,
                    TargetType::File => IdentifierKind::Sha256,
                    TargetType::InstalledApplication => IdentifierKind::MsiProduct,
                    TargetType::WebUrl => IdentifierKind::CanonicalUrl,
                },
                match target_type {
                    TargetType::Repository => purl.unwrap_or("pkg:npm/other@1.0.0"),
                    TargetType::File => hash.unwrap_or(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    TargetType::InstalledApplication => target,
                    TargetType::WebUrl => "https://example.synthetic/path",
                },
            )
            .unwrap(),
            vulnerability_id: cve.map(str::to_string),
            artifact_sha256: hash.map(str::to_string),
            purl: purl.map(str::to_string),
            cpe: None,
            web_origin: origin.map(str::to_string),
            web_domain: origin.map(|_| "example.synthetic".into()),
            evidence_ids: vec![format!("evidence-{id}")],
            source_scans: vec![format!("scan-{id}")],
            severity_points: 70,
            kev: cve == Some("CVE-2099-1001"),
            epss_basis_points: Some(8000),
            provider_available: true,
            parser_certain: true,
            conflicting_evidence: false,
            first_seen: "2099-01-01T00:00:00Z".into(),
            last_seen: "2099-01-02T00:00:00Z".into(),
            occurrence_count: 1,
            reopened: false,
        }
    }
    #[test]
    fn synthetic_cross_target_matrix_preserves_findings_and_clusters_strong_ids() {
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let input = vec![
            f(
                "repo",
                "r",
                TargetType::Repository,
                Some("CVE-2099-1001"),
                None,
                Some("pkg:npm/edy-synthetic-lib@1.0.0"),
                None,
            ),
            f(
                "app",
                "a",
                TargetType::InstalledApplication,
                Some("CVE-2099-1001"),
                Some(hash),
                None,
                None,
            ),
            f("file", "x", TargetType::File, None, Some(hash), None, None),
            f(
                "web-a",
                "w1",
                TargetType::WebUrl,
                None,
                None,
                None,
                Some("https://example.synthetic"),
            ),
            f(
                "web-b",
                "w2",
                TargetType::WebUrl,
                None,
                None,
                None,
                Some("https://example.synthetic"),
            ),
        ];
        let result =
            correlate_investigation(input.clone(), GraphLimits::default(), || false).unwrap();
        assert_eq!(result.state, CorrelationRunState::Complete);
        assert_eq!(result.findings_preserved, input.len() as u32);
        assert_eq!(
            result
                .clusters
                .iter()
                .filter(|c| c.cluster_type == ClusterType::SharedVulnerability)
                .count(),
            1
        );
        assert_eq!(
            result
                .clusters
                .iter()
                .filter(|c| c.cluster_type == ClusterType::SharedArtifact)
                .count(),
            1
        );
        assert!(
            result
                .suggested_cases
                .iter()
                .any(|c| c.assessment.priority == CasePriority::Immediate)
        );
        assert_eq!(
            result,
            correlate_investigation(input, GraphLimits::default(), || false).unwrap()
        );
    }
    #[test]
    fn similar_names_domains_severity_and_different_hash_do_not_merge() {
        let mut a = f(
            "a",
            "a",
            TargetType::Repository,
            None,
            None,
            Some("pkg:npm/alpha@1.0.0"),
            None,
        );
        let mut b = f(
            "b",
            "b",
            TargetType::Repository,
            None,
            None,
            Some("pkg:npm/alpha-tools@1.0.0"),
            None,
        );
        a.artifact_sha256 =
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        b.artifact_sha256 =
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
        let r = correlate_investigation(vec![a, b], GraphLimits::default(), || false).unwrap();
        assert!(r.clusters.is_empty());
    }
    #[test]
    fn conflicting_and_unavailable_data_reduce_confidence_not_risk() {
        let a = f(
            "a",
            "a",
            TargetType::Repository,
            Some("CVE-2099-1001"),
            None,
            Some("pkg:npm/a@1.0.0"),
            None,
        );
        let mut b = f(
            "b",
            "b",
            TargetType::InstalledApplication,
            Some("CVE-2099-1001"),
            None,
            None,
            None,
        );
        b.provider_available = false;
        b.conflicting_evidence = true;
        let r =
            correlate_investigation(vec![a.clone(), b], GraphLimits::default(), || false).unwrap();
        let c = &r.suggested_cases[0];
        assert!(c.assessment.risk >= a.severity_points);
        assert!(c.assessment.confidence < 85);
        assert!(c.assessment.coverage < 100);
    }
    #[test]
    fn cancellation_promotes_no_partial_graph_and_limits_fail_bounded() {
        let input = vec![f(
            "a",
            "a",
            TargetType::Repository,
            None,
            None,
            Some("pkg:npm/a@1.0.0"),
            None,
        )];
        let cancelled =
            correlate_investigation(input.clone(), GraphLimits::default(), || true).unwrap();
        assert_eq!(cancelled.state, CorrelationRunState::Cancelled);
        assert!(cancelled.nodes.is_empty());
        let partial = correlate_investigation(
            input,
            GraphLimits {
                nodes_per_run: 1,
                ..GraphLimits::default()
            },
            || false,
        )
        .unwrap();
        assert_eq!(partial.state, CorrelationRunState::PartialCorrelation);
        assert!(partial.limit_reached);
    }
    #[test]
    fn case_lifecycle_is_audited_and_recurrence_reopens() {
        let r = correlate_investigation(
            vec![
                f(
                    "a",
                    "a",
                    TargetType::Repository,
                    Some("CVE-2099-1001"),
                    None,
                    Some("pkg:npm/a@1.0.0"),
                    None,
                ),
                f(
                    "b",
                    "b",
                    TargetType::InstalledApplication,
                    Some("CVE-2099-1001"),
                    None,
                    None,
                    None,
                ),
            ],
            GraphLimits::default(),
            || false,
        )
        .unwrap();
        let mut c = r.suggested_cases[0].clone();
        c.transition(
            CaseStatus::Open,
            "2099-01-03T00:00:00Z",
            "user",
            "Review approved",
        )
        .unwrap();
        c.transition(
            CaseStatus::Investigating,
            "2099-01-04T00:00:00Z",
            "user",
            "Evidence review",
        )
        .unwrap();
        c.transition(
            CaseStatus::Resolved,
            "2099-01-05T00:00:00Z",
            "user",
            "Observed condition resolved",
        )
        .unwrap();
        c.transition(
            CaseStatus::Open,
            "2099-01-06T00:00:00Z",
            "correlation",
            "Recurrence observed",
        )
        .unwrap();
        assert_eq!(c.timeline.last().unwrap().event_type, "finding_reopened");
        assert_eq!(c.transitions.len(), 4);
    }
    #[test]
    fn graph_rejects_secret_material_and_hostile_labels() {
        assert!(
            StrongIdentity::new(IdentifierKind::StableTarget, "EDY_FAKE_SECRET_LEVEL5").is_err()
        );
        assert!(
            EntityNode::new(
                EntityKind::Finding,
                StrongIdentity::new(IdentifierKind::StableFinding, "f").unwrap(),
                "<script>\n"
            )
            .is_err()
        );
    }
    #[test]
    fn hundreds_of_findings_are_indexed_deterministically() {
        let input = (0..600)
            .map(|i| {
                f(
                    &format!("f{i:04}"),
                    &format!("t{i:04}"),
                    if i % 2 == 0 {
                        TargetType::Repository
                    } else {
                        TargetType::InstalledApplication
                    },
                    Some("CVE-2099-1001"),
                    None,
                    if i % 2 == 0 {
                        Some("pkg:npm/scale@1.0.0")
                    } else {
                        None
                    },
                    None,
                )
            })
            .collect::<Vec<_>>();
        let a = correlate_investigation(input.clone(), GraphLimits::default(), || false).unwrap();
        let b = correlate_investigation(input, GraphLimits::default(), || false).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.findings_preserved, 600);
    }
}
