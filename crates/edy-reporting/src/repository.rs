//! Secret-safe Level 1 repository reports in deterministic JSON and HTML.

use crate::ReportKind;
use edy_repository::{RepositoryFindingCategory, RepositoryInventory, RepositoryObservation};
use serde::Serialize;

pub const LEVEL1_REPORT_SCHEMA: &str = "LEVEL1_REPOSITORY_REPORT_V1";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReport {
    pub schema: &'static str,
    pub kind: ReportKind,
    pub scan_id: String,
    pub verdict: String,
    pub risk: String,
    pub confidence: String,
    pub coverage_complete: bool,
    pub inventory: RepositoryInventory,
    pub findings: Vec<RepositoryObservation>,
    pub secret_count: u32,
    pub vulnerable_dependency_count: u32,
    pub unavailable_checks: Vec<String>,
    pub limitations: Vec<String>,
}

impl RepositoryReport {
    pub fn capture(
        kind: ReportKind,
        scan_id: &str,
        inventory: &RepositoryInventory,
        observations: &[RepositoryObservation],
        unavailable_checks: &[String],
    ) -> Self {
        let mut findings = observations.to_vec();
        findings.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        for finding in &mut findings {
            if finding.category == RepositoryFindingCategory::Secret {
                finding.description =
                    "Potential secret detected; plaintext permanently omitted".into();
                finding.secret_preview = Some(
                    finding
                        .secret_preview
                        .clone()
                        .unwrap_or_else(|| "[REDACTED]".into()),
                );
            }
        }
        let secret_count = findings
            .iter()
            .filter(|f| f.category == RepositoryFindingCategory::Secret)
            .count() as u32;
        let vulnerable_dependency_count = findings
            .iter()
            .filter(|f| f.category == RepositoryFindingCategory::VulnerableDependency)
            .count() as u32;
        let coverage_complete = unavailable_checks.is_empty()
            && matches!(inventory.status, edy_repository::InventoryStatus::Complete);
        Self {
            schema: LEVEL1_REPORT_SCHEMA,
            kind,
            scan_id: scan_id.into(),
            verdict: if coverage_complete {
                "review_required"
            } else {
                "inconclusive"
            }
            .into(),
            risk: if findings.iter().any(|f| f.severity == "critical") {
                "critical"
            } else if findings.iter().any(|f| f.severity == "high") {
                "high"
            } else {
                "medium"
            }
            .into(),
            confidence: if coverage_complete { "high" } else { "medium" }.into(),
            coverage_complete,
            inventory: inventory.clone(),
            findings,
            secret_count,
            vulnerable_dependency_count,
            unavailable_checks: unavailable_checks.to_vec(),
            limitations: if coverage_complete {
                vec![]
            } else {
                vec!["Coverage is incomplete; unavailable checks may change the conclusion.".into()]
            },
        }
    }

    pub fn json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn html(&self) -> String {
        let findings = self
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape(finding.category.token()),
                    escape(&finding.severity),
                    escape(&finding.location),
                    escape(&finding.rule_id),
                )
            })
            .collect::<String>();
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>EDY VERDICT</title></head><body><h1>EDY VERDICT — Repository Security</h1><p>Verdict: {}</p><p>Risk: {} · Confidence: {}</p><p>Coverage complete: {}</p><table><thead><tr><th>Category</th><th>Severity</th><th>Location</th><th>Rule</th></tr></thead><tbody>{findings}</tbody></table></body></html>",
            escape(&self.verdict),
            escape(&self.risk),
            escape(&self.confidence),
            self.coverage_complete
        )
    }
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn inventory() -> RepositoryInventory {
        RepositoryInventory {
            snapshot_version: "REPOSITORY_SNAPSHOT_V1".into(),
            structural_fingerprint: "rsv1-test".into(),
            canonical_root: "D:/fixture".into(),
            file_count: 1,
            directory_count: 0,
            total_bytes: 1,
            oversized_files: 0,
            extensions: BTreeMap::new(),
            documents: vec![],
            ecosystems: vec![],
            exclusions: vec![],
            limits: Default::default(),
            status: edy_repository::InventoryStatus::Complete,
            security_events: vec![],
            gitignore_support: "deferred_builtin_exclusions_only".into(),
        }
    }

    #[test]
    fn html_escapes_and_reports_never_contain_fixture_secret() {
        let observation = RepositoryObservation {
            engine_id: "gitleaks".into(),
            engine_version: "8.30.0".into(),
            category: RepositoryFindingCategory::Secret,
            rule_id: "<script>".into(),
            description: "safe".into(),
            location: "a<&.env".into(),
            line: Some(1),
            severity: "high".into(),
            confidence: "high".into(),
            fingerprint_version: "SECRET_FINDING_V1".into(),
            fingerprint: "secret-fp".into(),
            package: None,
            installed_version: None,
            vulnerability_id: None,
            aliases: vec![],
            affected_range: None,
            fixed_version: None,
            source: None,
            secret_class: Some("token".into()),
            secret_preview: Some("EDY_************".into()),
            secret_digest: Some("digest".into()),
            license: None,
            metadata: BTreeMap::new(),
        };
        let report = RepositoryReport::capture(
            ReportKind::Technical,
            "scan",
            &inventory(),
            &[observation],
            &["real_engine_execution_policy_blocked".into()],
        );
        let json = report.json().unwrap();
        let html = report.html();
        assert!(!json.contains("EDY_FAKE_TEST_TOKEN_"));
        assert!(!html.contains("EDY_FAKE_TEST_TOKEN_"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }
}
