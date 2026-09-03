//! Secret-safe Level 1 repository reports in deterministic JSON and HTML.

use crate::ReportKind;
use edy_repository::{CorrelatedRepositoryFinding, RepositoryInventory};
use serde::Serialize;

pub const LEVEL1_REPORT_SCHEMA: &str = "LEVEL1_REPOSITORY_REPORT_V1";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReport {
    pub schema: &'static str,
    pub product_version: String,
    pub kind: ReportKind,
    pub scan_id: String,
    pub verdict: String,
    pub risk: String,
    pub confidence: String,
    pub coverage_complete: bool,
    pub inventory: RepositoryInventory,
    pub findings: Vec<CorrelatedRepositoryFinding>,
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
        correlated_findings: &[CorrelatedRepositoryFinding],
        unavailable_checks: &[String],
    ) -> Self {
        let mut findings = correlated_findings.to_vec();
        findings.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        let secret_count = findings.iter().filter(|f| f.category == "secret").count() as u32;
        let vulnerable_dependency_count = findings
            .iter()
            .filter(|f| f.category == "vulnerable_dependency")
            .count() as u32;
        let coverage_complete = unavailable_checks.is_empty()
            && matches!(inventory.status, edy_repository::InventoryStatus::Complete);
        Self {
            schema: LEVEL1_REPORT_SCHEMA,
            product_version: crate::PRODUCT_VERSION.into(),
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
                    escape(&finding.category),
                    escape(&finding.severity),
                    escape(&finding.affected_component),
                    escape(&finding.rule_ids.join(", ")),
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
        let finding = CorrelatedRepositoryFinding {
            id: "018f4c2a-1d3b-7abc-8def-0123456789ac".into(),
            fingerprint: "secret-fp".into(),
            title: "Potential secret detected; plaintext permanently omitted".into(),
            description: "safe".into(),
            category: "secret".into(),
            severity: "high".into(),
            confidence: "high".into(),
            status: "open".into(),
            affected_component: "a<&.env".into(),
            primary_source: "gitleaks".into(),
            supporting_sources: vec!["gitleaks".into()],
            rule_ids: vec!["<script>".into()],
            evidence_ids: vec!["018f4c2a-1d3b-7abc-8def-0123456789ad".into()],
            remediation_guidance: "Revoke if real and rescan".into(),
            limitations: vec!["Synthetic only".into()],
        };
        let report = RepositoryReport::capture(
            ReportKind::Technical,
            "scan",
            &inventory(),
            &[finding],
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
