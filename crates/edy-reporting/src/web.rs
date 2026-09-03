//! Deterministic, local-only Level 4 passive web-security reports.

use crate::ReportKind;
use edy_core::PassiveWebAnalysis;
use serde::Serialize;

pub const LEVEL4_REPORT_SCHEMA: &str = "LEVEL4_PASSIVE_WEB_REPORT_V1";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebSecurityReport {
    pub schema: &'static str,
    pub kind: ReportKind,
    pub scan_id: String,
    pub conclusion: String,
    pub analysis: PassiveWebAnalysis,
    pub limitations: Vec<String>,
}

impl WebSecurityReport {
    pub fn capture(kind: ReportKind, analysis: &PassiveWebAnalysis) -> Self {
        let mut limitations = analysis.coverage.limitations.clone();
        limitations.extend([
            "Passive, point-in-time observations do not prove that a site is safe or exploitable."
                .into(),
            "No page body, JavaScript, form, authenticated session, crawler or exploit probe was used."
                .into(),
            "Query values, cookie values, credentials and unrestricted response headers are not retained."
                .into(),
            "Reputation coverage is exact-match and provider-specific; no match is not a clean guarantee."
                .into(),
        ]);
        limitations.sort();
        limitations.dedup();
        let conclusion = if analysis.state == "completed" && analysis.findings.is_empty() {
            "No security issue was established from the available passive evidence."
        } else if analysis.state == "completed" {
            "Passive observations require review."
        } else {
            "Coverage is incomplete; no conclusive safety assessment is available."
        };
        Self {
            schema: LEVEL4_REPORT_SCHEMA,
            kind,
            scan_id: analysis.scan_id.clone(),
            conclusion: conclusion.into(),
            analysis: analysis.clone(),
            limitations,
        }
    }

    pub fn json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn html(&self) -> String {
        let findings = self
            .analysis
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "<tr><td>{}</td><td>{:?}</td><td>{:?}</td><td>{}</td></tr>",
                    escape(&finding.title),
                    finding.severity,
                    finding.confidence,
                    escape(&finding.guidance)
                )
            })
            .collect::<String>();
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>EDY VERDICT web security</title></head><body><main><h1>EDY VERDICT — Passive Web / URL Security</h1><p>Target: {}</p><p>{}</p><p>State: {} · risk: {:?} · confidence: {:?}</p><table><thead><tr><th>Observation</th><th>Severity</th><th>Confidence</th><th>Guidance</th></tr></thead><tbody>{}</tbody></table><h2>Limitations</h2><ul>{}</ul></main></body></html>",
            escape(&self.analysis.target.display_url),
            escape(&self.conclusion),
            escape(&self.analysis.state),
            self.analysis.risk,
            self.analysis.confidence,
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

    fn fixture() -> PassiveWebAnalysis {
        PassiveWebAnalysis {
            schema: WEB_ANALYSIS_SCHEMA.into(),
            scan_id: "018f4c2a-1d3b-7abc-8def-0123456789ab".into(),
            state: "partial".into(),
            query_policy: QueryPolicy::Send,
            target: SanitizedUrlTarget {
                display_url: "https://example.com/?token=[REDACTED]".into(),
                scheme: "https".into(),
                canonical_host: "example.com".into(),
                path: "/".into(),
                port: 443,
                query_present: true,
                query_parameter_names: vec!["token".into()],
                fragment_present: false,
                idna_ascii: false,
                public_ip_literal: false,
            },
            final_target: None,
            dns: vec![],
            tls: vec![],
            redirects: vec![],
            final_http_status: None,
            headers: vec![],
            cookies: vec![],
            reputation: ReputationObservation {
                provider: "URLhaus".into(),
                state: "unavailable".into(),
                exact_match: None,
                dataset_version: None,
                explanation: "Not checked".into(),
            },
            findings: vec![],
            risk: Severity::Info,
            confidence: Confidence::Low,
            coverage: WebCoverage {
                dns: "ready".into(),
                tls: "unavailable".into(),
                http: "unavailable".into(),
                redirects: "unavailable".into(),
                headers: "unavailable".into(),
                cookies: "unavailable".into(),
                reputation: "unavailable".into(),
                limitations: vec![],
            },
        }
    }

    #[test]
    fn output_is_deterministic_escaped_and_contains_no_fixture_secrets() {
        let report = WebSecurityReport::capture(ReportKind::Technical, &fixture());
        let json = report.json().unwrap();
        let html = report.html();
        assert_eq!(json, report.json().unwrap());
        assert!(!json.contains("EDY_FAKE_QUERY_SECRET_LEVEL4"));
        assert!(!html.contains("EDY_FAKE_COOKIE_SECRET_LEVEL4"));
        assert!(!html.contains("<script"));
        assert!(!html.to_ascii_lowercase().contains("guaranteed clean"));
    }
}
