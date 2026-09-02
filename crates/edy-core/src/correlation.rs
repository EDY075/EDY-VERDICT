use crate::{
    Confidence, DomainError, EngineObservation, EvidenceId, EvidenceStrength, Finding,
    FindingDraft, FindingFingerprint, FindingFingerprintInput, FindingId, ObservationSignal,
    ScanCoverage, ScanId, Severity, Target, Timestamp, UnavailableCheck, ValidationErrorKind,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub trait FindingIdSource {
    fn next_id(&mut self) -> FindingId;
}

pub struct CorrelationEngine;

impl CorrelationEngine {
    pub fn correlate<I: FindingIdSource>(
        scan_id: &ScanId,
        target: &Target,
        observations: &[EngineObservation],
        observed_at: &Timestamp,
        ids: &mut I,
    ) -> Result<Vec<Finding>, DomainError> {
        let mut grouped: BTreeMap<FindingFingerprint, Vec<&EngineObservation>> = BTreeMap::new();
        for observation in observations {
            observation.validate()?;
            if &observation.target_id != target.id() {
                return Err(DomainError::new(
                    "observation_target",
                    ValidationErrorKind::Incoherent,
                ));
            }
            let target_kind = format!("{:?}", target.kind()).to_ascii_lowercase();
            let fingerprint = FindingFingerprint::from_input(&FindingFingerprintInput {
                target_kind: &target_kind,
                canonical_target: &target.locator().canonical(),
                category: &observation.category,
                semantic_key: &observation.semantic_key,
                canonical_location: &observation.location,
            })?;
            grouped.entry(fingerprint).or_default().push(observation);
        }
        grouped
            .into_iter()
            .map(|(fingerprint, group)| {
                let first = group[0];
                let severity = group
                    .iter()
                    .map(|item| item.severity)
                    .max()
                    .unwrap_or(Severity::Info);
                let confidence = group
                    .iter()
                    .map(|item| item.parser_confidence)
                    .max()
                    .unwrap_or(Confidence::Low);
                let mut finding = Finding::new(FindingDraft {
                    id: ids.next_id(),
                    scan_id: scan_id.clone(),
                    target_id: target.id().clone(),
                    source_engine: first.engine.clone(),
                    rule_id: first.rule_id.clone(),
                    title: first.message.clone(),
                    description: first.message.clone(),
                    category: first.category.clone(),
                    severity,
                    confidence,
                    fingerprint,
                    observed_at: observed_at.clone(),
                    evidence_id: first.evidence_id.clone(),
                })?;
                for observation in group.into_iter().skip(1) {
                    finding.merge_observation(observation, observed_at)?;
                }
                Ok(finding)
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RiskScore(u8);

impl RiskScore {
    pub fn new(value: u8) -> Result<Self, DomainError> {
        (value <= 100)
            .then_some(Self(value))
            .ok_or_else(|| DomainError::new("risk_score", ValidationErrorKind::OutOfRange))
    }
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for RiskScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u8::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ConfidenceScore(u8);

impl ConfidenceScore {
    pub fn new(value: u8) -> Result<Self, DomainError> {
        (value <= 100)
            .then_some(Self(value))
            .ok_or_else(|| DomainError::new("confidence_score", ValidationErrorKind::OutOfRange))
    }
    pub const fn value(self) -> u8 {
        self.0
    }
    pub const fn band(self) -> Confidence {
        match self.0 {
            0..=39 => Confidence::Low,
            40..=74 => Confidence::Medium,
            _ => Confidence::High,
        }
    }
}

impl<'de> Deserialize<'de> for ConfidenceScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u8::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RiskSignals {
    pub known_exploited: bool,
    pub exposed: bool,
    pub persistence: bool,
    pub broad_scope: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RiskAssessment {
    pub score: RiskScore,
    pub band: Severity,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfidenceAssessment {
    pub score: ConfidenceScore,
    pub band: Confidence,
    pub reasons: Vec<String>,
    pub unavailable_checks: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerdictKind {
    Malicious,
    Suspicious,
    Vulnerable,
    NeedsReview,
    NoKnownIndicators,
    InsufficientCoverage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub kind: VerdictKind,
    pub risk: RiskAssessment,
    pub confidence: ConfidenceAssessment,
    pub reasons: Vec<String>,
    pub evidence_ids: Vec<EvidenceId>,
    pub unavailable_checks: Vec<String>,
}

pub struct VerdictModel;

impl VerdictModel {
    pub fn evaluate(
        findings: &[Finding],
        observations: &[EngineObservation],
        coverage: &ScanCoverage,
        unavailable: &[UnavailableCheck],
        signals: &RiskSignals,
    ) -> Result<Verdict, DomainError> {
        let risk = assess_risk(findings, signals)?;
        let confidence = assess_confidence(observations, coverage, unavailable)?;
        let strong_malicious = observations.iter().any(|observation| {
            observation.signal == ObservationSignal::Malicious
                && observation.evidence_strength == EvidenceStrength::Strong
        });
        let kind = if strong_malicious {
            VerdictKind::Malicious
        } else if observations
            .iter()
            .any(|item| item.signal == ObservationSignal::Vulnerability)
        {
            VerdictKind::Vulnerable
        } else if observations
            .iter()
            .any(|item| item.signal == ObservationSignal::Suspicious)
            || findings
                .iter()
                .any(|finding| finding.severity() >= Severity::High)
        {
            VerdictKind::Suspicious
        } else if !findings.is_empty() {
            VerdictKind::NeedsReview
        } else if coverage.is_complete() && unavailable.is_empty() {
            VerdictKind::NoKnownIndicators
        } else {
            VerdictKind::InsufficientCoverage
        };
        let mut reasons = vec![
            match kind {
                VerdictKind::Malicious => "strong malicious evidence was observed",
                VerdictKind::Vulnerable => "vulnerability evidence was observed",
                VerdictKind::Suspicious => "suspicious or high-impact evidence requires review",
                VerdictKind::NeedsReview => "observations require analyst review",
                VerdictKind::NoKnownIndicators => "no indicators were found by all planned checks",
                VerdictKind::InsufficientCoverage => {
                    if coverage.is_complete() {
                        "required external checks were unavailable"
                    } else {
                        "planned checks did not achieve complete coverage"
                    }
                }
            }
            .to_owned(),
        ];
        if coverage.has_failures() {
            reasons
                .push("one or more engine checks failed, were skipped, or were cancelled".into());
        }
        let evidence_ids = observations
            .iter()
            .map(|item| item.evidence_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let unavailable_checks = unavailable.iter().map(|item| item.id.clone()).collect();
        Ok(Verdict {
            kind,
            risk,
            confidence,
            reasons,
            evidence_ids,
            unavailable_checks,
        })
    }
}

fn assess_risk(findings: &[Finding], signals: &RiskSignals) -> Result<RiskAssessment, DomainError> {
    let severity = findings
        .iter()
        .map(Finding::severity)
        .max()
        .unwrap_or(Severity::Info);
    let mut score = severity.base_risk_score();
    let mut reasons = vec![format!(
        "base score {} from maximum severity {severity:?}",
        score
    )];
    for (enabled, points, reason) in [
        (signals.known_exploited, 10, "known exploited status"),
        (signals.exposed, 10, "exposed attack surface"),
        (signals.persistence, 5, "persistence indicator"),
        (signals.broad_scope, 5, "broad affected scope"),
    ] {
        if enabled {
            score = score.saturating_add(points).min(100);
            reasons.push(format!("+{points} {reason}"));
        }
    }
    let independent_sources = findings
        .iter()
        .flat_map(Finding::source_engines)
        .collect::<BTreeSet<_>>()
        .len();
    if independent_sources > 1 {
        score = score.saturating_add(5).min(100);
        reasons.push("+5 multiple independent engine sources".into());
    }
    let band = match score {
        0..=9 => Severity::Info,
        10..=29 => Severity::Low,
        30..=59 => Severity::Medium,
        60..=84 => Severity::High,
        _ => Severity::Critical,
    };
    Ok(RiskAssessment {
        score: RiskScore::new(score)?,
        band,
        reasons,
    })
}

fn assess_confidence(
    observations: &[EngineObservation],
    coverage: &ScanCoverage,
    unavailable: &[UnavailableCheck],
) -> Result<ConfidenceAssessment, DomainError> {
    let expected = coverage.expected_tasks().len() as u32;
    let passed = coverage.passed_count() as u32;
    let mut score = (passed * 70).checked_div(expected).unwrap_or(0) as u8;
    let mut reasons = vec![format!(
        "{} of {} planned engine checks passed",
        passed, expected
    )];
    if coverage.is_complete() {
        score = score.saturating_add(10);
        reasons.push("+10 complete planned engine coverage".into());
    }
    let strongest = observations.iter().map(|item| item.evidence_strength).max();
    let evidence_points = match strongest {
        Some(EvidenceStrength::Weak) => 5,
        Some(EvidenceStrength::Moderate) => 10,
        Some(EvidenceStrength::Strong) => 15,
        None => 0,
    };
    if evidence_points > 0 {
        score = score.saturating_add(evidence_points);
        reasons.push(format!("+{evidence_points} evidence strength"));
    }
    let sources = observations
        .iter()
        .map(|item| &item.engine)
        .collect::<BTreeSet<_>>()
        .len();
    if sources > 1 {
        score = score.saturating_add(5);
        reasons.push("+5 independent source agreement".into());
    }
    let penalty = (unavailable.len() as u8).saturating_mul(5).min(20);
    if penalty > 0 {
        score = score.saturating_sub(penalty);
        reasons.push(format!("-{penalty} unavailable provider checks"));
    }
    score = score.min(100);
    let score = ConfidenceScore::new(score)?;
    Ok(ConfidenceAssessment {
        band: score.band(),
        score,
        reasons,
        unavailable_checks: unavailable
            .iter()
            .map(|item| format!("{}:{:?}", item.id, item.availability))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Availability, CoverageTask, EngineId, EngineRunState, TargetId};

    fn coverage(passed: usize) -> ScanCoverage {
        let target_id = TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789ad").unwrap();
        let engines = ["a", "b", "c", "d"]
            .map(|id| EngineId::new(id).unwrap())
            .to_vec();
        let expected = engines
            .iter()
            .map(|engine| CoverageTask {
                engine: engine.clone(),
                target_id: target_id.clone(),
            })
            .collect();
        let results = engines
            .iter()
            .enumerate()
            .map(|(index, engine)| crate::EngineCoverage {
                engine: engine.clone(),
                target_id: target_id.clone(),
                state: if index < passed {
                    EngineRunState::Passed
                } else {
                    EngineRunState::Failed
                },
                evidence_obtained: u32::from(index < passed),
            })
            .collect();
        ScanCoverage::new(expected, results).unwrap()
    }

    #[test]
    fn zero_findings_low_coverage_is_insufficient_not_clean() {
        let verdict =
            VerdictModel::evaluate(&[], &[], &coverage(1), &[], &RiskSignals::default()).unwrap();
        assert_eq!(verdict.kind, VerdictKind::InsufficientCoverage);
        assert_eq!(verdict.confidence.band, Confidence::Low);
    }

    #[test]
    fn full_coverage_without_findings_is_carefully_worded() {
        let verdict =
            VerdictModel::evaluate(&[], &[], &coverage(4), &[], &RiskSignals::default()).unwrap();
        assert_eq!(verdict.kind, VerdictKind::NoKnownIndicators);
        assert!(
            !serde_json::to_string(&verdict)
                .unwrap()
                .to_ascii_lowercase()
                .contains("safe")
        );
    }

    #[test]
    fn unavailable_provider_reduces_confidence_not_risk() {
        let baseline =
            VerdictModel::evaluate(&[], &[], &coverage(4), &[], &RiskSignals::default()).unwrap();
        let unavailable = VerdictModel::evaluate(
            &[],
            &[],
            &coverage(4),
            &[UnavailableCheck {
                id: "nvd".into(),
                availability: Availability::Unavailable,
            }],
            &RiskSignals::default(),
        )
        .unwrap();
        assert_eq!(baseline.risk, unavailable.risk);
        assert!(unavailable.confidence.score < baseline.confidence.score);
        assert_eq!(unavailable.kind, VerdictKind::InsufficientCoverage);
    }

    #[test]
    fn score_and_confidence_are_independently_range_checked() {
        assert!(RiskScore::new(101).is_err());
        assert!(ConfidenceScore::new(101).is_err());
        assert_eq!(RiskScore::new(90).unwrap().value(), 90);
        assert_eq!(ConfidenceScore::new(10).unwrap().band(), Confidence::Low);
    }

    #[test]
    fn correlation_keeps_sources_without_duplicate_findings() {
        struct Ids;
        impl FindingIdSource for Ids {
            fn next_id(&mut self) -> FindingId {
                FindingId::new("018f4c2a-1d3b-7abc-8def-0123456789ad").unwrap()
            }
        }
        let target_id = TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789ac").unwrap();
        let target = Target::new(
            target_id.clone(),
            crate::TargetKind::Repository,
            crate::TargetLocator::new_local_path("D:/fixture").unwrap(),
        )
        .unwrap();
        let observations = ["a", "b"].map(|engine| EngineObservation {
            engine: EngineId::new(engine).unwrap(),
            engine_version: "1.0.0".into(),
            target_id: target_id.clone(),
            rule_id: format!("{engine}-rule"),
            semantic_key: "cve-2099-0001".into(),
            category: "vulnerability".into(),
            severity: Severity::High,
            location: "Cargo.lock".into(),
            message: "synthetic vulnerable dependency".into(),
            evidence_id: EvidenceId::new(if engine == "a" {
                "018f4c2a-1d3b-7abc-8def-0123456789ae"
            } else {
                "018f4c2a-1d3b-7abc-8def-0123456789af"
            })
            .unwrap(),
            signal: ObservationSignal::Vulnerability,
            evidence_strength: EvidenceStrength::Strong,
            parser_confidence: Confidence::High,
        });
        let findings = CorrelationEngine::correlate(
            &ScanId::new("018f4c2a-1d3b-7abc-8def-0123456789ab").unwrap(),
            &target,
            &observations,
            &Timestamp::new("2026-09-02T03:00:00Z").unwrap(),
            &mut Ids,
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source_engines().len(), 2);
        assert_eq!(findings[0].evidence_ids().len(), 2);
    }
}
