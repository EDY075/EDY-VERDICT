//! Deterministic Level 3 installed-application reports. Outputs are local-only artifacts.

use crate::ReportKind;
use edy_core::{InstalledAppFinding, InstalledApplicationSnapshot};
use serde::{Deserialize, Serialize};

pub const LEVEL3_REPORT_SCHEMA: &str = "LEVEL3_INSTALLED_APPLICATION_REPORT_V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DatasetStatus {
    pub provider: String,
    pub state: String,
    pub dataset_version: Option<String>,
    pub fetched_at_utc: Option<String>,
    pub sha256: Option<String>,
    pub freshness: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstalledApplicationReport {
    pub schema: &'static str,
    pub product_version: String,
    pub kind: ReportKind,
    pub scan_id: String,
    pub verdict: String,
    pub application_count: u32,
    pub affected_count: u32,
    pub identity_review_count: u32,
    pub inventory_coverage: edy_core::InventoryCoverage,
    pub provider_status: Vec<DatasetStatus>,
    pub findings: Vec<InstalledAppFinding>,
    pub limitations: Vec<String>,
}

impl InstalledApplicationReport {
    pub fn capture(
        kind: ReportKind,
        scan_id: &str,
        snapshot: &InstalledApplicationSnapshot,
        findings: &[InstalledAppFinding],
        mut provider_status: Vec<DatasetStatus>,
    ) -> Self {
        let mut findings = findings.to_vec();
        findings.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        provider_status.sort_by(|a, b| a.provider.cmp(&b.provider));
        let identity_review_count = snapshot
            .applications
            .iter()
            .filter(|application| !application.identity.state.permits_automatic_cve())
            .count() as u32;
        let unavailable = provider_status
            .iter()
            .any(|provider| provider.state != "ready" && provider.state != "stale_cache");
        let mut limitations = snapshot.coverage.limitations.clone();
        limitations.extend([
            "No finding means only that no affected application was established from available identities and data; it is not a clean guarantee.".into(),
            "Fixed-version metadata does not prove that an update is available on this host.".into(),
            "CISA KEV and EPSS affect priority only and do not prove exploitation of this host.".into(),
            "Reports never include uninstall commands, registry exports, API keys or credentials.".into(),
        ]);
        limitations.sort();
        limitations.dedup();
        Self {
            schema: LEVEL3_REPORT_SCHEMA,
            product_version: crate::PRODUCT_VERSION.into(),
            kind,
            scan_id: scan_id.into(),
            verdict: if unavailable {
                "inconclusive"
            } else if findings.is_empty() {
                "no_known_affected_application_from_available_data"
            } else {
                "review_required"
            }
            .into(),
            application_count: snapshot.applications.len() as u32,
            affected_count: findings.len() as u32,
            identity_review_count,
            inventory_coverage: snapshot.coverage.clone(),
            provider_status,
            findings,
            limitations,
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
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td></tr>",
                    escape(&finding.application_name),
                    escape(&finding.installed_version),
                    escape(&finding.cve),
                    finding.priority,
                    escape(finding.cvss_severity.as_deref().unwrap_or("unavailable")),
                    escape(finding.fixed_version.as_deref().unwrap_or("unavailable"))
                )
            })
            .collect::<String>();
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>EDY VERDICT installed applications</title></head><body><main><h1>EDY VERDICT — Installed Application Security</h1><p>Verdict: {}</p><p>Applications: {} · affected findings: {} · identity review: {}</p><table><thead><tr><th>Application</th><th>Installed version</th><th>CVE</th><th>Priority</th><th>CVSS</th><th>Fixed version</th></tr></thead><tbody>{}</tbody></table><h2>Limitations</h2><ul>{}</ul></main></body></html>",
            escape(&self.verdict),
            self.application_count,
            self.affected_count,
            self.identity_review_count,
            findings,
            self.limitations
                .iter()
                .map(|item| format!("<li>{}</li>", escape(item)))
                .collect::<String>()
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
    use edy_core::*;
    fn snapshot() -> InstalledApplicationSnapshot {
        normalize_inventory(
            vec![RawInstalledApplication {
                source: InventorySource {
                    kind: InventorySourceKind::Registry,
                    scope: InventoryScope::Machine,
                    view: RegistryView::Registry64,
                    source_id: "fixture".into(),
                },
                display_name: Some("<script>fixture</script>".into()),
                display_version: Some("1.0.0".into()),
                publisher: None,
                install_location: None,
                display_icon: None,
                install_date: None,
                windows_installer: None,
                system_component: None,
                release_type: None,
                product_code: None,
                package_family_name: None,
            }],
            &[],
            InventoryCoverage {
                registry_machine_64: true,
                registry_machine_32: true,
                registry_current_user_64: true,
                registry_current_user_32: true,
                msix_current_user: false,
                other_users: false,
                portable_applications: false,
                filesystem_crawl: false,
                limitations: vec!["MSIX unavailable".into()],
            },
        )
    }
    #[test]
    fn reports_are_deterministic_escaped_and_never_claim_clean() {
        let snap = snapshot();
        let status = vec![DatasetStatus {
            provider: "NVD".into(),
            state: "ready".into(),
            dataset_version: Some("2.0".into()),
            fetched_at_utc: None,
            sha256: Some("a".repeat(64)),
            freshness: "live_smoke".into(),
        }];
        let finding = InstalledAppFinding {
            fingerprint_version: INSTALLED_APP_VULNERABILITY_V1.into(),
            fingerprint: "iav1-fixture".into(),
            application_id: "fixture".into(),
            application_name: "<script>fixture</script>".into(),
            installed_version: "1.0.0".into(),
            cve: "CVE-2099-0001".into(),
            affected: AffectedState::Affected,
            identity_state: IdentityMatchState::Curated,
            priority: PriorityBand::Review,
            priority_reasons: vec!["fixture".into()],
            cvss_score: None,
            cvss_severity: None,
            kev: None,
            epss: None,
            fixed_version: None,
            sources: vec!["fixture".into()],
            limitations: vec![],
        };
        let report = InstalledApplicationReport::capture(
            ReportKind::Technical,
            "018f4c2a-1d3b-7abc-8def-0123456789aa",
            &snap,
            &[finding],
            status,
        );
        let json = report.json().unwrap();
        let html = report.html();
        assert!(!json.to_ascii_lowercase().contains("guaranteed clean"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
    }
}
