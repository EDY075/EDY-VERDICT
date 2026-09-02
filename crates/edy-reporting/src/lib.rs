#![forbid(unsafe_code)]
//! Deterministic, local-only Level 0 report contracts.

use edy_core::{Confidence, EngineRunState, FindingStatus, ScanResult, Severity, VerdictKind};
use serde::{Deserialize, Serialize};

pub const REPORT_SCHEMA: &str = "REPORT_SCHEMA_V1";
pub const HTML_RENDERER_STATUS: &str = "DEFERRED";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    Executive,
    Technical,
    Developer,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportEvidence {
    id: String,
    summary: String,
    provenance: String,
    redacted: bool,
}

impl ReportEvidence {
    pub fn from_preclassified(
        id: impl Into<String>,
        summary: impl Into<String>,
        provenance: impl Into<String>,
        contains_sensitive_data: bool,
    ) -> Self {
        Self {
            id: id.into(),
            summary: if contains_sensitive_data {
                "[REDACTED]".into()
            } else {
                summary.into()
            },
            provenance: provenance.into(),
            redacted: contains_sensitive_data,
        }
    }

    fn enforce_redaction(mut self) -> Self {
        if self.redacted {
            self.summary = "[REDACTED]".into();
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageSummary {
    pub expected: u32,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub cancelled: u32,
    pub evidence_obtained: u32,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FindingSummary {
    pub id: String,
    pub scan_id: String,
    pub target_id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: FindingStatus,
    pub fingerprint: String,
    pub source_engines: Vec<String>,
    pub rule_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub remediation_ids: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "contract", content = "details", rename_all = "snake_case")]
pub enum ReportContract {
    Executive {
        major_finding_ids: Vec<String>,
        business_impact: Vec<String>,
    },
    Technical {
        engine_runs: Vec<String>,
        affected_components: Vec<String>,
        errors_or_partial_checks: Vec<String>,
    },
    Developer {
        components_and_rules: Vec<String>,
        remediation_guidance: Vec<String>,
        verification_steps: Vec<String>,
        rescan_status: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportDocument {
    pub schema: String,
    pub kind: ReportKind,
    pub scan_id: String,
    pub verdict: VerdictKind,
    pub risk_score: u8,
    pub risk: Severity,
    pub confidence_score: u8,
    pub confidence: Confidence,
    pub coverage: CoverageSummary,
    pub headline: String,
    pub limitations: Vec<String>,
    pub recommended_priorities: Vec<String>,
    pub findings: Vec<FindingSummary>,
    pub evidence: Vec<ReportEvidence>,
    pub explanation: Vec<String>,
    pub contract: ReportContract,
}

impl ReportDocument {
    pub fn build(
        kind: ReportKind,
        result: &ScanResult,
        mut evidence: Vec<ReportEvidence>,
        mut limitations: Vec<String>,
    ) -> Self {
        let runs = result.coverage.engine_results();
        let count = |state| runs.iter().filter(|run| run.state == state).count() as u32;
        let coverage = CoverageSummary {
            expected: result.coverage.expected_tasks().len() as u32,
            passed: count(EngineRunState::Passed),
            failed: count(EngineRunState::Failed),
            skipped: count(EngineRunState::Skipped),
            cancelled: count(EngineRunState::Cancelled),
            evidence_obtained: result.coverage.evidence_count(),
            complete: result.coverage.is_complete(),
        };
        if !coverage.complete {
            limitations.push(
                "Coverage was incomplete; unavailable checks may change the conclusion.".into(),
            );
        }
        limitations.extend(
            result
                .verdict
                .unavailable_checks
                .iter()
                .map(|check| format!("Unavailable check: {check}")),
        );
        limitations.sort();
        limitations.dedup();
        evidence = evidence
            .into_iter()
            .map(ReportEvidence::enforce_redaction)
            .collect();
        evidence.sort_by(|left, right| left.id.cmp(&right.id));
        evidence.dedup_by(|left, right| left.id == right.id);
        let mut findings: Vec<_> = result
            .findings
            .iter()
            .map(|finding| FindingSummary {
                id: finding.id().to_string(),
                scan_id: finding.scan_id().to_string(),
                target_id: finding.target_id().to_string(),
                title: finding.title().into(),
                description: finding.description().into(),
                category: finding.category().into(),
                severity: finding.severity(),
                confidence: finding.confidence(),
                status: finding.status(),
                fingerprint: finding.fingerprint().to_string(),
                source_engines: finding
                    .source_engines()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                rule_ids: finding.rule_ids().to_vec(),
                evidence_ids: finding
                    .evidence_ids()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                remediation_ids: finding
                    .remediation_ids()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                first_seen: finding.first_seen().to_string(),
                last_seen: finding.last_seen().to_string(),
            })
            .collect();
        findings.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
        let headline = match result.verdict.kind {
            VerdictKind::Malicious => "Strong malicious indicators require immediate review.",
            VerdictKind::Suspicious => "Suspicious indicators require investigation.",
            VerdictKind::Vulnerable => "Known vulnerability indicators require prioritization.",
            VerdictKind::NeedsReview => "Available evidence requires analyst review.",
            VerdictKind::NoKnownIndicators => {
                "No known indicators were observed by the completed planned checks."
            }
            VerdictKind::InsufficientCoverage => {
                "Coverage is insufficient for a broader conclusion."
            }
        }
        .into();
        let mut recommended_priorities = findings
            .iter()
            .filter(|finding| finding.status != FindingStatus::Resolved)
            .map(|finding| {
                format!(
                    "Review {} finding {}",
                    format!("{:?}", finding.severity).to_ascii_lowercase(),
                    finding.id
                )
            })
            .collect::<Vec<_>>();
        recommended_priorities.sort();
        if recommended_priorities.is_empty() && !coverage.complete {
            recommended_priorities
                .push("Restore unavailable checks and run verification again.".into());
        }
        let mut explanation = result.verdict.reasons.clone();
        explanation.extend(result.verdict.risk.reasons.clone());
        explanation.extend(result.verdict.confidence.reasons.clone());
        let contract = build_contract(kind, result, &findings, &coverage);
        Self {
            schema: REPORT_SCHEMA.into(),
            kind,
            scan_id: result.request_id.to_string(),
            verdict: result.verdict.kind,
            risk_score: result.verdict.risk.score.value(),
            risk: result.verdict.risk.band,
            confidence_score: result.verdict.confidence.score.value(),
            confidence: result.verdict.confidence.band,
            coverage,
            headline,
            limitations,
            recommended_priorities,
            findings,
            evidence,
            explanation,
            contract,
        }
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

fn build_contract(
    kind: ReportKind,
    result: &ScanResult,
    findings: &[FindingSummary],
    coverage: &CoverageSummary,
) -> ReportContract {
    match kind {
        ReportKind::Executive => {
            let major_finding_ids = findings
                .iter()
                .filter(|finding| {
                    finding.status != FindingStatus::Resolved && finding.severity >= Severity::High
                })
                .map(|finding| finding.id.clone())
                .collect();
            let mut business_impact = Vec::new();
            if findings.iter().any(|finding| {
                finding.status != FindingStatus::Resolved && finding.severity >= Severity::Critical
            }) {
                business_impact.push(
                    "Critical technical exposure may materially affect operations or data; validate scope immediately."
                        .into(),
                );
            } else if findings.iter().any(|finding| {
                finding.status != FindingStatus::Resolved && finding.severity >= Severity::High
            }) {
                business_impact.push(
                    "High technical exposure may affect operations or data; prioritize validation."
                        .into(),
                );
            } else {
                business_impact.push(
                    "No material impact was established by the completed checks; this is not a security guarantee."
                        .into(),
                );
            }
            if !coverage.complete {
                business_impact.push(
                    "Incomplete coverage limits business-impact assessment and requires additional checks."
                        .into(),
                );
            }
            ReportContract::Executive {
                major_finding_ids,
                business_impact,
            }
        }
        ReportKind::Technical => {
            let mut engine_runs = result
                .coverage
                .engine_results()
                .iter()
                .map(|run| format!("{}:{}:{:?}", run.engine, run.target_id, run.state))
                .collect::<Vec<_>>();
            engine_runs.sort();
            let mut affected_components = findings
                .iter()
                .map(|finding| finding.target_id.clone())
                .collect::<Vec<_>>();
            affected_components.sort();
            affected_components.dedup();
            let errors_or_partial_checks = result
                .coverage
                .engine_results()
                .iter()
                .filter(|run| run.state != EngineRunState::Passed)
                .map(|run| format!("{}:{}:{:?}", run.engine, run.target_id, run.state))
                .collect();
            ReportContract::Technical {
                engine_runs,
                affected_components,
                errors_or_partial_checks,
            }
        }
        ReportKind::Developer => {
            let components_and_rules = findings
                .iter()
                .map(|finding| {
                    format!(
                        "{}:{}:{}",
                        finding.target_id,
                        finding.category,
                        finding.rule_ids.join(",")
                    )
                })
                .collect();
            let remediation_guidance = findings
                .iter()
                .filter(|finding| finding.status != FindingStatus::Resolved)
                .map(|finding| {
                    if finding.remediation_ids.is_empty() {
                        format!("{}: manual review required", finding.id)
                    } else {
                        format!(
                            "{}: follow remediation plan {}",
                            finding.id,
                            finding.remediation_ids.join(",")
                        )
                    }
                })
                .collect();
            let verification_steps = findings
                .iter()
                .map(|finding| format!("{}: verify evidence then rescan target", finding.id))
                .collect();
            let rescan_status = findings
                .iter()
                .map(|finding| format!("{}:{:?}", finding.id, finding.status))
                .collect();
            ReportContract::Developer {
                components_and_rules,
                remediation_guidance,
                verification_steps,
                rescan_status,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edy_core::{
        ConfidenceAssessment, ConfidenceScore, CoverageTask, EngineCoverage, EngineId, EvidenceId,
        Finding, FindingDraft, FindingFingerprint, FindingId, RiskAssessment, RiskScore,
        ScanCoverage, ScanId, TargetId, Timestamp, Verdict,
    };

    fn fixture(complete: bool) -> ScanResult {
        let states = if complete {
            [EngineRunState::Passed, EngineRunState::Passed]
        } else {
            [EngineRunState::Passed, EngineRunState::Failed]
        };
        let engines = [EngineId::new("a").unwrap(), EngineId::new("b").unwrap()];
        let target_id = TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789ac").unwrap();
        let tasks = engines
            .iter()
            .cloned()
            .map(|engine| CoverageTask {
                engine,
                target_id: target_id.clone(),
            })
            .collect();
        let coverage = ScanCoverage::new(
            tasks,
            engines
                .iter()
                .cloned()
                .zip(states)
                .map(|(engine, state)| EngineCoverage {
                    engine,
                    target_id: target_id.clone(),
                    state,
                    evidence_obtained: u32::from(state == EngineRunState::Passed),
                })
                .collect(),
        )
        .unwrap();
        let kind = if complete {
            VerdictKind::NoKnownIndicators
        } else {
            VerdictKind::InsufficientCoverage
        };
        ScanResult {
            request_id: ScanId::new("018f4c2a-1d3b-7abc-8def-0123456789ab").unwrap(),
            findings: vec![],
            coverage,
            verdict: Verdict {
                kind,
                risk: RiskAssessment {
                    score: RiskScore::new(0).unwrap(),
                    band: Severity::Info,
                    reasons: vec!["fixture risk".into()],
                },
                confidence: ConfidenceAssessment {
                    score: ConfidenceScore::new(if complete { 80 } else { 35 }).unwrap(),
                    band: if complete {
                        Confidence::High
                    } else {
                        Confidence::Low
                    },
                    reasons: vec!["fixture confidence".into()],
                    unavailable_checks: vec![],
                },
                reasons: vec!["fixture verdict".into()],
                evidence_ids: vec![],
                unavailable_checks: vec![],
            },
        }
    }

    #[test]
    fn sensitive_evidence_is_redacted_before_serialization() {
        let evidence =
            ReportEvidence::from_preclassified("e-1", "FAKE_SECRET_VALUE", "fixture", true);
        let json = ReportDocument::build(
            ReportKind::Technical,
            &fixture(true),
            vec![evidence],
            vec![],
        )
        .to_json_pretty()
        .unwrap();
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("FAKE_SECRET_VALUE"));

        let malformed = ReportEvidence {
            id: "e-2".into(),
            summary: "FAKE_SECRET_BYPASS".into(),
            provenance: "fixture".into(),
            redacted: true,
        };
        let json = ReportDocument::build(
            ReportKind::Technical,
            &fixture(true),
            vec![malformed],
            vec![],
        )
        .to_json_pretty()
        .unwrap();
        assert!(!json.contains("FAKE_SECRET_BYPASS"));
    }

    #[test]
    fn json_is_deterministic_and_escapes_untrusted_text() {
        let input = fixture(true);
        let evidence = vec![ReportEvidence::from_preclassified(
            "b",
            "quote: \" <script>",
            "fixture",
            false,
        )];
        let first = ReportDocument::build(
            ReportKind::Developer,
            &input,
            evidence.clone(),
            vec!["z".into(), "a".into()],
        )
        .to_json_pretty()
        .unwrap();
        let second = ReportDocument::build(
            ReportKind::Developer,
            &input,
            evidence,
            vec!["a".into(), "z".into()],
        )
        .to_json_pretty()
        .unwrap();
        assert_eq!(first, second);
        assert!(first.contains("\\\""));
        assert!(!first.to_ascii_lowercase().contains("safe guaranteed"));
    }

    #[test]
    fn insufficient_coverage_is_explicit() {
        let report = ReportDocument::build(ReportKind::Executive, &fixture(false), vec![], vec![]);
        assert_eq!(report.verdict, VerdictKind::InsufficientCoverage);
        assert!(!report.coverage.complete);
        assert!(report.headline.contains("insufficient"));
        assert!(
            report
                .limitations
                .iter()
                .any(|item| item.contains("incomplete"))
        );
    }

    #[test]
    fn all_three_report_contracts_are_versioned() {
        let executive =
            ReportDocument::build(ReportKind::Executive, &fixture(true), vec![], vec![]);
        let technical =
            ReportDocument::build(ReportKind::Technical, &fixture(true), vec![], vec![]);
        let developer =
            ReportDocument::build(ReportKind::Developer, &fixture(true), vec![], vec![]);
        assert_eq!(executive.schema, REPORT_SCHEMA);
        assert_eq!(technical.schema, REPORT_SCHEMA);
        assert_eq!(developer.schema, REPORT_SCHEMA);
        assert!(matches!(
            executive.contract,
            ReportContract::Executive { .. }
        ));
        assert!(matches!(
            technical.contract,
            ReportContract::Technical { .. }
        ));
        assert!(matches!(
            developer.contract,
            ReportContract::Developer { .. }
        ));
        assert_ne!(
            executive.to_json_pretty().unwrap(),
            technical.to_json_pretty().unwrap()
        );
        assert_eq!(HTML_RENDERER_STATUS, "DEFERRED");
    }

    #[test]
    fn resolved_findings_are_history_not_active_priorities() {
        let mut input = fixture(true);
        let mut finding = Finding::new(FindingDraft {
            id: FindingId::new("018f4c2a-1d3b-7abc-8def-0123456789ad").unwrap(),
            scan_id: input.request_id.clone(),
            target_id: TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789ac").unwrap(),
            source_engine: EngineId::new("a").unwrap(),
            rule_id: "fixture-rule".into(),
            title: "Resolved fixture".into(),
            description: "Synthetic resolved finding".into(),
            category: "fixture".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            fingerprint: FindingFingerprint::parse("ffp1-0123456789abcdef0123456789abcdef")
                .unwrap(),
            observed_at: Timestamp::new("2026-09-02T03:00:00Z").unwrap(),
            evidence_id: EvidenceId::new("018f4c2a-1d3b-7abc-8def-0123456789ae").unwrap(),
        })
        .unwrap();
        for status in [
            FindingStatus::Investigating,
            FindingStatus::Remediating,
            FindingStatus::VerificationPending,
            FindingStatus::Resolved,
        ] {
            finding.change_status(status).unwrap();
        }
        input.findings.push(finding);

        let report = ReportDocument::build(ReportKind::Developer, &input, vec![], vec![]);
        assert!(report.recommended_priorities.is_empty());
        assert!(matches!(
            &report.contract,
            ReportContract::Developer { rescan_status, .. }
                if rescan_status.iter().any(|status| status.ends_with(":Resolved"))
        ));
    }
}
