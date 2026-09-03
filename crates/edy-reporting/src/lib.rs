#![forbid(unsafe_code)]
//! Deterministic, local-only Level 0 report contracts.
//!
//! Rendering is separated from persistence: callers capture an immutable [`ReportSnapshot`]
//! before producing one or more projections. A renderer therefore has no database or clock.

pub const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

use edy_core::{
    Availability, Confidence, EngineRunState, FindingStatus, ScanResult, Severity, VerdictKind,
};
use serde::{Deserialize, Serialize};

pub mod file;
pub mod installed_apps;
pub mod investigation;
pub mod remediation;
pub mod repository;
pub mod web;

pub const REPORT_SCHEMA: &str = "REPORT_SCHEMA_V2";
pub const REPORT_SNAPSHOT_SCHEMA: &str = "REPORT_SNAPSHOT_V1";
pub const HTML_RENDERER_STATUS: &str = "READY";

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotScanStatus {
    Completed,
    Partial,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanMetadata {
    pub scan_id: String,
    pub target_ids: Vec<String>,
    pub status: SnapshotScanStatus,
    pub expected_engine_runs: u32,
    pub completed_engine_runs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineRunSummary {
    pub engine: String,
    pub target_id: String,
    pub state: EngineRunState,
    pub evidence_obtained: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageSummary {
    pub expected: u32,
    pub completed: u32,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub cancelled: u32,
    pub unavailable: u32,
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
#[serde(deny_unknown_fields)]
pub struct ExecutiveFinding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: FindingStatus,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeveloperFinding {
    pub finding_id: String,
    pub component_or_file: String,
    pub rules: Vec<String>,
    pub category: String,
    pub remediation: Vec<String>,
    pub verification: String,
    pub status: FindingStatus,
}

/// A self-contained reporting input with private, normalized fields and no mutation API.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportSnapshot {
    schema: String,
    metadata: ScanMetadata,
    verdict: VerdictKind,
    risk_score: u8,
    risk: Severity,
    confidence_score: u8,
    confidence: Confidence,
    coverage: CoverageSummary,
    engine_runs: Vec<EngineRunSummary>,
    findings: Vec<FindingSummary>,
    evidence: Vec<ReportEvidence>,
    correlation_reasons: Vec<String>,
    limitations: Vec<String>,
    priorities: Vec<String>,
    errors: Vec<String>,
    unavailable_checks: Vec<String>,
}

impl ReportSnapshot {
    pub fn capture(
        result: &ScanResult,
        mut evidence: Vec<ReportEvidence>,
        mut limitations: Vec<String>,
    ) -> Self {
        let mut engine_runs = result
            .coverage
            .engine_results()
            .iter()
            .map(|run| EngineRunSummary {
                engine: run.engine.to_string(),
                target_id: run.target_id.to_string(),
                state: run.state,
                evidence_obtained: run.evidence_obtained,
            })
            .collect::<Vec<_>>();
        engine_runs.sort_by(|left, right| {
            (&left.engine, &left.target_id).cmp(&(&right.engine, &right.target_id))
        });

        let count = |state| engine_runs.iter().filter(|run| run.state == state).count() as u32;
        let passed = count(EngineRunState::Passed);
        let failed = count(EngineRunState::Failed);
        let skipped = count(EngineRunState::Skipped);
        let cancelled = count(EngineRunState::Cancelled);

        let mut unavailable_checks = result.verdict.unavailable_checks.clone();
        unavailable_checks.extend(result.verdict.confidence.unavailable_checks.iter().cloned());
        unavailable_checks.extend(
            engine_runs
                .iter()
                .filter(|run| run.state == EngineRunState::Skipped)
                .map(|run| format!("engine:{}:target:{}:skipped", run.engine, run.target_id)),
        );
        unavailable_checks.extend(
            result
                .coverage
                .provider_results()
                .iter()
                .filter(|provider| provider.availability != Availability::Available)
                .map(|provider| {
                    format!(
                        "provider:{}:{}",
                        provider.id,
                        enum_label(provider.availability)
                    )
                }),
        );
        normalize_strings(&mut unavailable_checks);

        let coverage = CoverageSummary {
            expected: result.coverage.expected_tasks().len() as u32,
            completed: passed,
            passed,
            failed,
            skipped,
            cancelled,
            unavailable: unavailable_checks.len() as u32,
            evidence_obtained: result.coverage.evidence_count(),
            complete: result.coverage.is_complete() && unavailable_checks.is_empty(),
        };

        if !coverage.complete {
            limitations.push(
                "Coverage was incomplete; unavailable checks may change the conclusion.".into(),
            );
        }
        limitations.extend(
            unavailable_checks
                .iter()
                .map(|check| format!("Unavailable check: {check}")),
        );
        normalize_strings(&mut limitations);

        evidence = evidence
            .into_iter()
            .map(ReportEvidence::enforce_redaction)
            .collect();
        evidence.sort_by(|left, right| {
            (&left.id, &left.provenance, &left.summary, left.redacted).cmp(&(
                &right.id,
                &right.provenance,
                &right.summary,
                right.redacted,
            ))
        });
        evidence = merge_evidence_fail_closed(evidence);

        let mut findings = result
            .findings
            .iter()
            .map(|finding| {
                let mut source_engines = finding
                    .source_engines()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                let mut rule_ids = finding.rule_ids().to_vec();
                let mut evidence_ids = finding
                    .evidence_ids()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                let mut remediation_ids = finding
                    .remediation_ids()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                normalize_strings(&mut source_engines);
                normalize_strings(&mut rule_ids);
                normalize_strings(&mut evidence_ids);
                normalize_strings(&mut remediation_ids);
                FindingSummary {
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
                    source_engines,
                    rule_ids,
                    evidence_ids,
                    remediation_ids,
                    first_seen: finding.first_seen().to_string(),
                    last_seen: finding.last_seen().to_string(),
                }
            })
            .collect::<Vec<_>>();
        findings.sort_by(|left, right| {
            (&left.fingerprint, &left.id).cmp(&(&right.fingerprint, &right.id))
        });

        let mut priorities = findings
            .iter()
            .filter(|finding| finding.status != FindingStatus::Resolved)
            .map(|finding| {
                format!(
                    "Review {} finding {}",
                    enum_label(finding.severity),
                    finding.id
                )
            })
            .collect::<Vec<_>>();
        if priorities.is_empty() && !coverage.complete {
            priorities.push("Restore unavailable checks and run verification again.".into());
        }
        normalize_strings(&mut priorities);

        let mut correlation_reasons = result.verdict.reasons.clone();
        correlation_reasons.extend(result.verdict.risk.reasons.iter().cloned());
        correlation_reasons.extend(result.verdict.confidence.reasons.iter().cloned());
        normalize_strings(&mut correlation_reasons);

        let mut errors = engine_runs
            .iter()
            .filter(|run| {
                matches!(
                    run.state,
                    EngineRunState::Failed | EngineRunState::Cancelled
                )
            })
            .map(|run| {
                format!(
                    "engine:{}:target:{}:{}",
                    run.engine,
                    run.target_id,
                    enum_label(run.state)
                )
            })
            .collect::<Vec<_>>();
        normalize_strings(&mut errors);

        let mut target_ids = result
            .coverage
            .expected_tasks()
            .iter()
            .map(|task| task.target_id.to_string())
            .collect::<Vec<_>>();
        normalize_strings(&mut target_ids);

        let metadata = ScanMetadata {
            scan_id: result.request_id.to_string(),
            target_ids,
            status: scan_status(&coverage),
            expected_engine_runs: coverage.expected,
            completed_engine_runs: coverage.completed,
        };

        Self {
            schema: REPORT_SNAPSHOT_SCHEMA.into(),
            metadata,
            verdict: result.verdict.kind,
            risk_score: result.verdict.risk.score.value(),
            risk: result.verdict.risk.band,
            confidence_score: result.verdict.confidence.score.value(),
            confidence: result.verdict.confidence.band,
            coverage,
            engine_runs,
            findings,
            evidence,
            correlation_reasons,
            limitations,
            priorities,
            errors,
            unavailable_checks,
        }
    }

    pub fn metadata(&self) -> &ScanMetadata {
        &self.metadata
    }

    pub fn findings(&self) -> &[FindingSummary] {
        &self.findings
    }

    pub fn coverage(&self) -> &CoverageSummary {
        &self.coverage
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "contract", content = "details", rename_all = "snake_case")]
pub enum ReportContract {
    Executive {
        top_findings: Vec<ExecutiveFinding>,
        business_impact: Vec<String>,
    },
    Technical {
        scan_metadata: ScanMetadata,
        engine_runs: Vec<EngineRunSummary>,
        evidence_references: Vec<String>,
        correlation_reasons: Vec<String>,
        errors: Vec<String>,
        unavailable_checks: Vec<String>,
    },
    Developer {
        findings: Vec<DeveloperFinding>,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportDocument {
    pub schema: String,
    pub product_version: String,
    pub snapshot_schema: String,
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
    /// Compatibility constructor. New integrations should capture once and call
    /// [`Self::from_snapshot`] for every desired report kind.
    pub fn build(
        kind: ReportKind,
        result: &ScanResult,
        evidence: Vec<ReportEvidence>,
        limitations: Vec<String>,
    ) -> Self {
        let snapshot = ReportSnapshot::capture(result, evidence, limitations);
        Self::from_snapshot(kind, &snapshot)
    }

    pub fn from_snapshot(kind: ReportKind, snapshot: &ReportSnapshot) -> Self {
        Self {
            schema: REPORT_SCHEMA.into(),
            product_version: PRODUCT_VERSION.into(),
            snapshot_schema: snapshot.schema.clone(),
            kind,
            scan_id: snapshot.metadata.scan_id.clone(),
            verdict: snapshot.verdict,
            risk_score: snapshot.risk_score,
            risk: snapshot.risk,
            confidence_score: snapshot.confidence_score,
            confidence: snapshot.confidence,
            coverage: snapshot.coverage.clone(),
            headline: headline(snapshot.verdict).into(),
            limitations: snapshot.limitations.clone(),
            recommended_priorities: snapshot.priorities.clone(),
            findings: snapshot.findings.clone(),
            evidence: snapshot.evidence.clone(),
            explanation: snapshot.correlation_reasons.clone(),
            contract: build_contract(kind, snapshot),
        }
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Produces standalone HTML with static inline CSS and no executable content.
    pub fn to_html(&self) -> String {
        render_html(self)
    }
}

fn scan_status(coverage: &CoverageSummary) -> SnapshotScanStatus {
    if coverage.complete {
        SnapshotScanStatus::Completed
    } else if coverage.passed > 0 {
        SnapshotScanStatus::Partial
    } else if coverage.failed > 0 {
        SnapshotScanStatus::Failed
    } else if coverage.cancelled > 0 {
        SnapshotScanStatus::Cancelled
    } else {
        SnapshotScanStatus::Partial
    }
}

fn headline(verdict: VerdictKind) -> &'static str {
    match verdict {
        VerdictKind::Malicious => "Strong malicious indicators require immediate review.",
        VerdictKind::Suspicious => "Suspicious indicators require investigation.",
        VerdictKind::Vulnerable => "Known vulnerability indicators require prioritization.",
        VerdictKind::NeedsReview => "Available evidence requires analyst review.",
        VerdictKind::NoKnownIndicators => {
            "No known indicators were observed by the completed planned checks."
        }
        VerdictKind::InsufficientCoverage => "Coverage is insufficient for a broader conclusion.",
    }
}

fn build_contract(kind: ReportKind, snapshot: &ReportSnapshot) -> ReportContract {
    match kind {
        ReportKind::Executive => {
            let mut candidates = snapshot
                .findings
                .iter()
                .filter(|finding| finding.status != FindingStatus::Resolved)
                .collect::<Vec<_>>();
            candidates.sort_by(|left, right| {
                right
                    .severity
                    .cmp(&left.severity)
                    .then_with(|| right.confidence.cmp(&left.confidence))
                    .then_with(|| left.id.cmp(&right.id))
            });
            let top_findings = candidates
                .into_iter()
                .take(5)
                .map(|finding| ExecutiveFinding {
                    id: finding.id.clone(),
                    title: finding.title.clone(),
                    severity: finding.severity,
                    confidence: finding.confidence,
                    status: finding.status,
                })
                .collect();
            let mut business_impact = Vec::new();
            if snapshot.findings.iter().any(|finding| {
                finding.status != FindingStatus::Resolved && finding.severity >= Severity::Critical
            }) {
                business_impact.push(
                    "Critical technical exposure may materially affect operations or data; validate scope immediately."
                        .into(),
                );
            } else if snapshot.findings.iter().any(|finding| {
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
            if !snapshot.coverage.complete {
                business_impact.push(
                    "Incomplete coverage limits business-impact assessment and requires additional checks."
                        .into(),
                );
            }
            ReportContract::Executive {
                top_findings,
                business_impact,
            }
        }
        ReportKind::Technical => {
            let mut evidence_references = snapshot
                .findings
                .iter()
                .flat_map(|finding| finding.evidence_ids.iter().cloned())
                .chain(snapshot.evidence.iter().map(|evidence| evidence.id.clone()))
                .collect::<Vec<_>>();
            normalize_strings(&mut evidence_references);
            ReportContract::Technical {
                scan_metadata: snapshot.metadata.clone(),
                engine_runs: snapshot.engine_runs.clone(),
                evidence_references,
                correlation_reasons: snapshot.correlation_reasons.clone(),
                errors: snapshot.errors.clone(),
                unavailable_checks: snapshot.unavailable_checks.clone(),
            }
        }
        ReportKind::Developer => {
            let findings = snapshot
                .findings
                .iter()
                .map(|finding| DeveloperFinding {
                    finding_id: finding.id.clone(),
                    component_or_file: finding.target_id.clone(),
                    rules: finding.rule_ids.clone(),
                    category: finding.category.clone(),
                    remediation: if finding.remediation_ids.is_empty() {
                        vec!["Manual review required before a remediation plan is selected.".into()]
                    } else {
                        finding
                            .remediation_ids
                            .iter()
                            .map(|id| format!("Follow remediation plan {id}."))
                            .collect()
                    },
                    verification: "Verify recorded evidence, then rescan the same approved target."
                        .into(),
                    status: finding.status,
                })
                .collect();
            ReportContract::Developer { findings }
        }
    }
}

fn normalize_strings(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn merge_evidence_fail_closed(evidence: Vec<ReportEvidence>) -> Vec<ReportEvidence> {
    let mut normalized: Vec<ReportEvidence> = Vec::with_capacity(evidence.len());
    for candidate in evidence {
        if let Some(existing) = normalized.last_mut()
            && existing.id == candidate.id
        {
            // A duplicate identifier is treated conservatively: one sensitive classification
            // makes every representation of that evidence redacted.
            if candidate.redacted {
                existing.redacted = true;
                existing.summary = "[REDACTED]".into();
            }
            continue;
        }
        normalized.push(candidate);
    }
    normalized
}

fn enum_label<T: Serialize>(value: T) -> String {
    serde_json::to_string(&value)
        .unwrap_or_else(|_| "unknown".into())
        .trim_matches('"')
        .to_owned()
}

fn render_html(report: &ReportDocument) -> String {
    const PREFIX: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; frame-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'\"><title>EDY VERDICT report</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b1020;color:#e8edf7;font:15px/1.5 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:32px}.panel{background:#131b2f;border:1px solid #2d3a59;border-radius:12px;padding:20px;margin:16px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.metric{background:#0e1628;border-radius:8px;padding:12px}h1,h2{margin-top:0}table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #2d3a59;padding:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080d18;padding:16px;border-radius:8px}code{font-family:ui-monospace,monospace}.muted{color:#aebbd3}</style></head><body><main>";
    let mut html = String::from(PREFIX);
    html.push_str("<h1>EDY VERDICT report</h1><p class=\"muted\">Deterministic local report · ");
    push_escaped(&mut html, &enum_label(report.kind));
    html.push_str("</p><section class=\"panel\"><h2>Conclusion</h2><p>");
    push_escaped(&mut html, &report.headline);
    html.push_str("</p><div class=\"grid\">");
    metric(&mut html, "Verdict", &enum_label(report.verdict));
    metric(
        &mut html,
        "Risk",
        &format!("{} / 100 ({})", report.risk_score, enum_label(report.risk)),
    );
    metric(
        &mut html,
        "Confidence",
        &format!(
            "{} / 100 ({})",
            report.confidence_score,
            enum_label(report.confidence)
        ),
    );
    metric(
        &mut html,
        "Coverage",
        &format!(
            "{} of {} completed; {} unavailable",
            report.coverage.completed, report.coverage.expected, report.coverage.unavailable
        ),
    );
    html.push_str("</div></section><section class=\"panel\"><h2>Findings</h2>");
    if report.findings.is_empty() {
        html.push_str("<p class=\"muted\">No findings are recorded in this snapshot.</p>");
    } else {
        html.push_str("<table><thead><tr><th>Finding</th><th>Severity</th><th>Confidence</th><th>Status</th></tr></thead><tbody>");
        for finding in &report.findings {
            html.push_str("<tr><td><strong>");
            push_escaped(&mut html, &finding.title);
            html.push_str("</strong><br><span class=\"muted\">");
            push_escaped(&mut html, &finding.description);
            html.push_str("</span></td><td>");
            push_escaped(&mut html, &enum_label(finding.severity));
            html.push_str("</td><td>");
            push_escaped(&mut html, &enum_label(finding.confidence));
            html.push_str("</td><td>");
            push_escaped(&mut html, &enum_label(finding.status));
            html.push_str("</td></tr>");
        }
        html.push_str("</tbody></table>");
    }
    html.push_str("</section>");
    html_list(&mut html, "Limitations", &report.limitations);
    html_list(
        &mut html,
        "Recommended priorities",
        &report.recommended_priorities,
    );
    html.push_str("<section class=\"panel\"><h2>Complete JSON contract</h2><pre><code>");
    let json = report
        .to_json_pretty()
        .unwrap_or_else(|_| "{\"error\":\"serialization_failed\"}".into());
    push_escaped(&mut html, &json);
    html.push_str("</code></pre></section></main></body></html>");
    html
}

fn metric(html: &mut String, label: &str, value: &str) {
    html.push_str("<div class=\"metric\"><strong>");
    push_escaped(html, label);
    html.push_str("</strong><br>");
    push_escaped(html, value);
    html.push_str("</div>");
}

fn html_list(html: &mut String, title: &str, items: &[String]) {
    html.push_str("<section class=\"panel\"><h2>");
    push_escaped(html, title);
    html.push_str("</h2>");
    if items.is_empty() {
        html.push_str("<p class=\"muted\">None recorded.</p>");
    } else {
        html.push_str("<ul>");
        for item in items {
            html.push_str("<li>");
            push_escaped(html, item);
            html.push_str("</li>");
        }
        html.push_str("</ul>");
    }
    html.push_str("</section>");
}

fn push_escaped(output: &mut String, input: &str) {
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#x27;"),
            _ => output.push(character),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edy_core::{
        ConfidenceAssessment, ConfidenceScore, CoverageTask, EngineCoverage, EngineId, EvidenceId,
        Finding, FindingDraft, FindingFingerprint, FindingId, ProviderCoverage, RiskAssessment,
        RiskScore, ScanCoverage, ScanId, TargetId, Timestamp, Verdict,
    };

    fn fixture(states: &[EngineRunState], unavailable_provider: bool) -> ScanResult {
        let target_id = TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789ac").unwrap();
        let engines = states
            .iter()
            .enumerate()
            .map(|(index, _)| EngineId::new(format!("engine-{index}")).unwrap())
            .collect::<Vec<_>>();
        let tasks = engines
            .iter()
            .cloned()
            .map(|engine| CoverageTask {
                engine,
                target_id: target_id.clone(),
            })
            .collect();
        let mut coverage = ScanCoverage::new(
            tasks,
            engines
                .iter()
                .cloned()
                .zip(states.iter().copied())
                .map(|(engine, state)| EngineCoverage {
                    engine,
                    target_id: target_id.clone(),
                    state,
                    evidence_obtained: u32::from(state == EngineRunState::Passed),
                })
                .collect(),
        )
        .unwrap();
        if unavailable_provider {
            coverage = coverage
                .with_provider_results(vec![
                    ProviderCoverage::new("fixture-provider", Availability::Offline).unwrap(),
                ])
                .unwrap();
        }
        let complete = coverage.is_complete();
        ScanResult {
            request_id: ScanId::new("018f4c2a-1d3b-7abc-8def-0123456789ab").unwrap(),
            findings: vec![],
            coverage,
            verdict: Verdict {
                kind: if complete {
                    VerdictKind::NoKnownIndicators
                } else {
                    VerdictKind::InsufficientCoverage
                },
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
                    unavailable_checks: if unavailable_provider {
                        vec!["fixture-provider".into()]
                    } else {
                        vec![]
                    },
                },
                reasons: vec!["fixture verdict".into()],
                evidence_ids: vec![],
                unavailable_checks: vec![],
            },
        }
    }

    fn add_finding(input: &mut ScanResult, resolved: bool, title: &str, description: &str) {
        let mut finding = Finding::new(FindingDraft {
            id: FindingId::new("018f4c2a-1d3b-7abc-8def-0123456789ad").unwrap(),
            scan_id: input.request_id.clone(),
            target_id: TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789ac").unwrap(),
            source_engine: EngineId::new("engine-0").unwrap(),
            rule_id: "fixture-rule".into(),
            title: title.into(),
            description: description.into(),
            category: "fixture".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            fingerprint: FindingFingerprint::parse("ffp1-0123456789abcdef0123456789abcdef")
                .unwrap(),
            observed_at: Timestamp::new("2026-09-02T03:00:00Z").unwrap(),
            evidence_id: EvidenceId::new("018f4c2a-1d3b-7abc-8def-0123456789ae").unwrap(),
        })
        .unwrap();
        if resolved {
            for next in [
                FindingStatus::Investigating,
                FindingStatus::Remediating,
                FindingStatus::VerificationPending,
                FindingStatus::Resolved,
            ] {
                finding.change_status(next).unwrap();
            }
        }
        input.findings.push(finding);
    }

    #[test]
    fn sensitive_evidence_is_redacted_before_snapshot_serialization() {
        let snapshot = ReportSnapshot::capture(
            &fixture(&[EngineRunState::Passed], false),
            vec![ReportEvidence::from_preclassified(
                "e-1",
                "FAKE_SECRET_VALUE",
                "fixture",
                true,
            )],
            vec![],
        );
        let json = ReportDocument::from_snapshot(ReportKind::Technical, &snapshot)
            .to_json_pretty()
            .unwrap();
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("FAKE_SECRET_VALUE"));
    }

    #[test]
    fn duplicate_evidence_id_cannot_bypass_redaction() {
        let snapshot = ReportSnapshot::capture(
            &fixture(&[EngineRunState::Passed], false),
            vec![
                ReportEvidence::from_preclassified(
                    "e-1",
                    "FAKE_SECRET_DUPLICATE",
                    "fixture",
                    false,
                ),
                ReportEvidence::from_preclassified("e-1", "classified", "fixture", true),
            ],
            vec![],
        );
        let json = ReportDocument::from_snapshot(ReportKind::Technical, &snapshot)
            .to_json_pretty()
            .unwrap();
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("FAKE_SECRET_DUPLICATE"));
    }

    #[test]
    fn same_snapshot_produces_identical_json_and_html() {
        let snapshot = ReportSnapshot::capture(
            &fixture(&[EngineRunState::Passed], false),
            vec![ReportEvidence::from_preclassified(
                "b",
                "quote: \"",
                "fixture",
                false,
            )],
            vec!["z".into(), "a".into()],
        );
        let first = ReportDocument::from_snapshot(ReportKind::Developer, &snapshot);
        let second = ReportDocument::from_snapshot(ReportKind::Developer, &snapshot);
        assert_eq!(
            first.to_json_pretty().unwrap(),
            second.to_json_pretty().unwrap()
        );
        assert_eq!(first.to_html(), second.to_html());
        assert!(!first.to_json_pretty().unwrap().contains("generated_at"));
    }

    #[test]
    fn reordered_inputs_produce_the_same_snapshot_output() {
        let input = fixture(&[EngineRunState::Passed], false);
        let first = ReportSnapshot::capture(
            &input,
            vec![
                ReportEvidence::from_preclassified("b", "second", "fixture", false),
                ReportEvidence::from_preclassified("a", "first", "fixture", false),
            ],
            vec!["z".into(), "a".into()],
        );
        let second = ReportSnapshot::capture(
            &input,
            vec![
                ReportEvidence::from_preclassified("a", "first", "fixture", false),
                ReportEvidence::from_preclassified("b", "second", "fixture", false),
            ],
            vec!["a".into(), "z".into()],
        );
        assert_eq!(first, second);
    }

    #[test]
    fn partial_and_unavailable_states_are_explicit() {
        let snapshot = ReportSnapshot::capture(
            &fixture(&[EngineRunState::Passed, EngineRunState::Failed], true),
            vec![],
            vec![],
        );
        let report = ReportDocument::from_snapshot(ReportKind::Technical, &snapshot);
        assert_eq!(snapshot.metadata().status, SnapshotScanStatus::Partial);
        assert_eq!(report.verdict, VerdictKind::InsufficientCoverage);
        assert!(!report.coverage.complete);
        assert_eq!(report.coverage.failed, 1);
        assert!(report.coverage.unavailable > 0);
        assert!(matches!(
            &report.contract,
            ReportContract::Technical {
                errors,
                unavailable_checks,
                engine_runs,
                ..
            } if !errors.is_empty() && !unavailable_checks.is_empty() && engine_runs.len() == 2
        ));
    }

    #[test]
    fn resolved_findings_are_history_not_executive_priorities() {
        let mut input = fixture(&[EngineRunState::Passed], false);
        add_finding(
            &mut input,
            true,
            "Resolved fixture",
            "Synthetic resolved finding",
        );
        let snapshot = ReportSnapshot::capture(&input, vec![], vec![]);
        let executive = ReportDocument::from_snapshot(ReportKind::Executive, &snapshot);
        let developer = ReportDocument::from_snapshot(ReportKind::Developer, &snapshot);
        assert!(executive.recommended_priorities.is_empty());
        assert!(matches!(
            executive.contract,
            ReportContract::Executive { top_findings, .. } if top_findings.is_empty()
        ));
        assert!(matches!(
            developer.contract,
            ReportContract::Developer { findings }
                if findings.iter().any(|finding| finding.status == FindingStatus::Resolved)
        ));
    }

    #[test]
    fn all_three_contracts_are_complete_and_versioned() {
        let snapshot =
            ReportSnapshot::capture(&fixture(&[EngineRunState::Passed], false), vec![], vec![]);
        let executive = ReportDocument::from_snapshot(ReportKind::Executive, &snapshot);
        let technical = ReportDocument::from_snapshot(ReportKind::Technical, &snapshot);
        let developer = ReportDocument::from_snapshot(ReportKind::Developer, &snapshot);
        for report in [&executive, &technical, &developer] {
            assert_eq!(report.schema, REPORT_SCHEMA);
            assert_eq!(report.snapshot_schema, REPORT_SNAPSHOT_SCHEMA);
        }
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
        assert_eq!(HTML_RENDERER_STATUS, "READY");
    }

    #[test]
    fn html_escapes_script_and_img_payloads_and_has_no_active_content() {
        let mut input = fixture(&[EngineRunState::Passed], false);
        add_finding(
            &mut input,
            false,
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(2)>",
        );
        let snapshot = ReportSnapshot::capture(
            &input,
            vec![ReportEvidence::from_preclassified(
                "e-xss",
                "<script>alert(3)</script><img src=x onerror=alert(4)>",
                "fixture",
                false,
            )],
            vec!["<script>alert(5)</script>".into()],
        );
        let html = ReportDocument::from_snapshot(ReportKind::Technical, &snapshot).to_html();
        assert!(!html.contains("<script"));
        assert!(!html.contains("<img"));
        assert!(!html.contains("<iframe"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&lt;img src=x onerror=alert(2)&gt;"));
        assert!(html.contains("script-src 'none'"));
        assert!(html.contains("img-src 'none'"));
    }

    #[test]
    fn conclusion_never_uses_prohibited_assurance_phrases() {
        let snapshot =
            ReportSnapshot::capture(&fixture(&[EngineRunState::Passed], false), vec![], vec![]);
        for kind in [
            ReportKind::Executive,
            ReportKind::Technical,
            ReportKind::Developer,
        ] {
            let report = ReportDocument::from_snapshot(kind, &snapshot);
            for output in [report.to_json_pretty().unwrap(), report.to_html()] {
                let normalized = output.to_ascii_lowercase();
                for prohibited in ["100% safe", "completely secure", "guaranteed clean"] {
                    assert!(!normalized.contains(prohibited));
                }
            }
        }
    }
}
