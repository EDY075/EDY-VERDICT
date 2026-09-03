//! Deterministic local-only Level 5 case reports.
use edy_core::InvestigationCase;
use serde::Serialize;

pub const LEVEL5_REPORT_SCHEMA: &str = "LEVEL5_INVESTIGATION_REPORT_V1";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InvestigationReport {
    pub schema: &'static str,
    pub case: InvestigationCase,
    pub conclusion: String,
    pub limitations: Vec<String>,
}

impl InvestigationReport {
    pub fn capture(case: &InvestigationCase) -> Self {
        Self{schema:LEVEL5_REPORT_SCHEMA,case:case.clone(),conclusion:"Correlated evidence requires analyst review; this case does not establish causation, compromise, breach, or a complete attack chain.".into(),limitations:vec!["Correlation does not prove causation.".into(),"A shared CVE does not mean the same asset or compromise.".into(),"A suggested case does not prove an incident occurred.".into(),"Blast radius is observed only across associated analyzed targets.".into(),"Unavailable providers reduce case coverage and confidence.".into(),"Priority is distinct from severity; confidence is distinct from risk.".into()]}
    }
    pub fn json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    pub fn html(&self) -> String {
        let reasons = self
            .case
            .assessment
            .priority_reasons
            .iter()
            .map(|v| format!("<li>{}</li>", escape(v)))
            .collect::<String>();
        let timeline = self
            .case
            .timeline
            .iter()
            .map(|v| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape(&v.timestamp),
                    escape(&v.event_type),
                    escape(&v.summary_safe)
                )
            })
            .collect::<String>();
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>EDY VERDICT investigation</title></head><body><main><h1>{}</h1><p>{}</p><dl><dt>Status</dt><dd>{:?}</dd><dt>Priority</dt><dd>{:?}</dd><dt>Risk</dt><dd>{}</dd><dt>Confidence</dt><dd>{}</dd><dt>Coverage</dt><dd>{}</dd><dt>Observed targets</dt><dd>{}</dd></dl><h2>Priority reasons</h2><ul>{}</ul><h2>Timeline</h2><table><tbody>{}</tbody></table><h2>Limitations</h2><ul>{}</ul></main></body></html>",
            escape(&self.case.title_safe),
            escape(&self.conclusion),
            self.case.status,
            self.case.assessment.priority,
            self.case.assessment.risk,
            self.case.assessment.confidence,
            self.case.assessment.coverage,
            self.case.blast_radius.unique_affected_targets,
            reasons,
            timeline,
            self.limitations
                .iter()
                .map(|v| format!("<li>{}</li>", escape(v)))
                .collect::<String>()
        )
    }
}
fn escape(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use edy_core::*;
    #[test]
    fn report_is_local_escaped_and_never_claims_incident() {
        let c = InvestigationCase {
            case_id: "case-v1-test".into(),
            title_safe: "Review <img onerror=x>".into(),
            status: CaseStatus::Suggested,
            suggested: true,
            finding_ids: vec!["f".into()],
            cluster_ids: vec!["c".into()],
            entity_ids: vec!["e".into()],
            evidence_ids: vec!["v".into()],
            blast_radius: BlastRadius {
                observed_only: true,
                unique_affected_targets: 2,
                unique_affected_components: 2,
                unique_findings: 2,
                unique_vulnerability_ids: 1,
                target_types_affected: vec![
                    TargetType::Repository,
                    TargetType::InstalledApplication,
                ],
            },
            assessment: DecisionAssessment {
                risk: 80,
                confidence: 90,
                coverage: 75,
                priority: CasePriority::Immediate,
                risk_reasons: vec![],
                confidence_reasons: vec![],
                coverage_reasons: vec![],
                priority_reasons: vec!["Exact CVE".into()],
            },
            timeline: vec![],
            transitions: vec![],
        };
        let r = InvestigationReport::capture(&c);
        let json = r.json().unwrap();
        let html = r.html();
        assert!(html.contains("&lt;img"));
        assert!(!html.contains("<script"));
        assert!(!json.contains("EDY_FAKE_SECRET_LEVEL5"));
        assert!(r.conclusion.contains("does not establish"));
    }
}
