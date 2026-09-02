use crate::ReportKind;
use edy_engine_manager::file_security::{FileAnalysis, FileSecurityFinding};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileReport {
    pub schema: &'static str,
    pub kind: ReportKind,
    pub scan_id: String,
    pub file_name: String,
    pub disposition: String,
    pub risk: String,
    pub confidence: String,
    pub coverage: Vec<String>,
    pub unavailable_checks: Vec<String>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    pub file_identity: Option<String>,
    pub classification: Option<String>,
    pub pe_metadata: Option<String>,
    pub authenticode: String,
    pub yara_status: String,
    pub reputation_status: String,
    pub findings: Vec<FileReportFinding>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileReportFinding {
    pub category: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub source: String,
    pub rule: String,
    pub evidence: Vec<String>,
    pub remediation_guidance: String,
    pub verification: String,
}

impl FileReport {
    pub fn capture(kind: ReportKind, scan_id: &str, analysis: &FileAnalysis) -> Self {
        let technical = !matches!(kind, ReportKind::Executive);
        let developer = matches!(kind, ReportKind::Developer);
        let coverage = vec![
            format!("hashing={:?}", analysis.coverage.hashing),
            format!("classification={:?}", analysis.coverage.classification),
            format!("pe={:?}", analysis.coverage.pe_inspection),
            format!("authenticode={:?}", analysis.coverage.authenticode),
            format!("yara={:?}", analysis.coverage.yara),
            format!("reputation={:?}", analysis.coverage.reputation),
        ];
        Self {
            schema: "EDY_FILE_REPORT_V1",
            kind,
            scan_id: scan_id.into(),
            file_name: std::path::Path::new(&analysis.target.canonical_path)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("file")
                .into(),
            disposition: analysis.verdict.disposition.clone(),
            risk: format!("{:?} ({})", analysis.verdict.risk, analysis.verdict.risk_score),
            confidence: format!(
                "{:?} ({})",
                analysis.verdict.confidence, analysis.verdict.confidence_score
            ),
            coverage,
            unavailable_checks: analysis.coverage.unavailable_checks.clone(),
            sha256: technical.then(|| analysis.hashes.sha256.clone()),
            sha512: technical.then(|| analysis.hashes.sha512.clone()),
            file_identity: technical.then(|| {
                format!(
                    "volume={};file={};size={}",
                    analysis.target.identity.volume_id,
                    analysis.target.identity.file_id,
                    analysis.target.identity.size
                )
            }),
            classification: technical.then(|| format!("{:?}", analysis.classification)),
            pe_metadata: technical.then(|| {
                analysis.pe.as_ref().map_or_else(
                    || analysis.pe_error.map_or_else(|| "not_applicable".into(), |e| format!("rejected:{e:?}")),
                    |pe| format!("{pe:?}"),
                )
            }),
            authenticode: format!(
                "presence={};crypto={:?};trust={:?};offline_cache_only={};publisher={:?}",
                analysis.authenticode.signature_present,
                analysis.authenticode.cryptographic_status,
                analysis.authenticode.trust_chain_status,
                analysis.authenticode.offline_cache_only,
                technical.then_some(&analysis.authenticode.publisher)
            ),
            yara_status: "unavailable_by_execution_policy".into(),
            reputation_status: analysis.reputation.status.clone(),
            findings: analysis
                .findings
                .iter()
                .map(|finding| finding_view(finding, developer))
                .collect(),
            limitations: vec![
                "No report claims SAFE, guaranteed clean, or trusted merely because a file is signed."
                    .into(),
                "YARA-X real execution remains policy-blocked.".into(),
                "Hash reputation was not checked and no file bytes were uploaded.".into(),
                "Production file scanning readiness is not claimed.".into(),
            ],
        }
    }

    pub fn json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn html(&self) -> String {
        let json = self.json().unwrap_or_else(|_| "{}".into());
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>EDY VERDICT file report</title></head><body><main><h1>EDY VERDICT file report</h1><pre>{}</pre></main></body></html>",
            escape(&json)
        )
    }
}

fn finding_view(finding: &FileSecurityFinding, developer: bool) -> FileReportFinding {
    FileReportFinding {
        category: format!("{:?}", finding.category),
        title: finding.title.clone(),
        severity: format!("{:?}", finding.severity),
        confidence: format!("{:?}", finding.confidence),
        source: finding.source.clone(),
        rule: finding.rule_id.clone(),
        evidence: finding.evidence.clone(),
        remediation_guidance: if developer {
            "Review the bounded parser/engine evidence and verify using a newly authorized immutable target snapshot."
                .into()
        } else {
            "Review the evidence before taking action.".into()
        },
        verification:
            "Re-authorize the explicit file and repeat the same checks after remediation.".into(),
    }
}

fn escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use edy_engine_manager::file_security::*;

    fn analysis_with_injection(value: &str) -> FileAnalysis {
        FileAnalysis {
            target: AuthorizedFileTarget {
                authorization_id: "018f4c2a-1d3b-7abc-8def-0123456789d1".into(),
                requested_path: "D:/fixture.bin".into(),
                canonical_path: "D:/fixture.bin".into(),
                identity: FileIdentity {
                    volume_id: "1".into(),
                    file_id: "2".into(),
                    size: 3,
                    last_write_time: "4".into(),
                    attributes: 0,
                },
                authorized_at_utc: "2026-09-02T00:00:00Z".into(),
                snapshot_version: FILE_SNAPSHOT_VERSION.into(),
                max_file_size: DEFAULT_MAX_FILE_SIZE,
            },
            hashes: FileHashes {
                sha256: "a".repeat(64),
                sha512: "b".repeat(128),
                bytes_hashed: 3,
            },
            classification: FileClassification::UnknownBinary,
            pe: None,
            pe_error: None,
            authenticode: AuthenticodeInspection {
                signature_present: false,
                cryptographic_status: AuthenticodeStatus::Unsigned,
                trust_chain_status: AuthenticodeStatus::Unsigned,
                publisher: PublisherMetadata::default(),
                offline_cache_only: true,
            },
            yara_observations: Vec::new(),
            reputation: FileReputationSummary {
                privacy_mode: edy_core::FilePrivacyMode::LocalOnly,
                availability: edy_core::Availability::NotConfigured,
                provider: None,
                known: None,
                malicious_count: None,
                suspicious_count: None,
                status: "not_checked".into(),
            },
            findings: vec![FileSecurityFinding {
                fingerprint_version: PE_INDICATOR_V1.into(),
                fingerprint: "fixture".into(),
                category: FileFindingCategory::SuspiciousBinaryIndicator,
                rule_id: value.into(),
                title: value.into(),
                severity: edy_core::Severity::Medium,
                confidence: edy_core::Confidence::High,
                source: "fixture".into(),
                evidence: vec![value.into()],
            }],
            coverage: FileScanCoverage {
                hashing: CheckState::Completed,
                classification: CheckState::Completed,
                pe_inspection: CheckState::Failed,
                authenticode: CheckState::NotApplicable,
                yara: CheckState::PolicyBlocked,
                reputation: CheckState::NotChecked,
                target_stable: true,
                unavailable_checks: vec!["yara".into(), "reputation".into()],
            },
            verdict: FileVerdict {
                disposition: "needs_review".into(),
                risk_score: 40,
                risk: edy_core::Severity::Medium,
                confidence_score: 50,
                confidence: edy_core::Confidence::Medium,
                reasons: vec!["fixture".into()],
            },
        }
    }

    #[test]
    fn json_and_local_html_preserve_evidence_and_escape_active_content() {
        let payload = "<script><img onerror=alert(1)>";
        let report = FileReport::capture(
            ReportKind::Developer,
            "018f4c2a-1d3b-7abc-8def-0123456789d2",
            &analysis_with_injection(payload),
        );
        assert!(report.json().unwrap().contains(payload));
        let html = report.html();
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img onerror"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
    }

    #[test]
    fn executive_omits_hash_detail_but_keeps_coverage_limitations() {
        let report = FileReport::capture(
            ReportKind::Executive,
            "018f4c2a-1d3b-7abc-8def-0123456789d2",
            &analysis_with_injection("fixture"),
        );
        assert!(report.sha256.is_none());
        assert!(report.sha512.is_none());
        assert_eq!(report.yara_status, "unavailable_by_execution_policy");
        assert_eq!(report.reputation_status, "not_checked");
    }
}
