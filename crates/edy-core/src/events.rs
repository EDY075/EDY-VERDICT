use crate::{
    Confidence, EngineId, EvidenceId, FindingFingerprint, FindingId, FindingStatus, RemediationId,
    ScanId, Severity, TargetId, Timestamp, VerificationId,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum DomainEvent {
    ScanCreated(ScanCreated),
    ScanStarted(ScanStarted),
    EngineStarted(EngineStarted),
    EngineProgress(EngineProgress),
    FindingObserved(FindingObserved),
    EngineCompleted(EngineCompleted),
    EngineFailed(EngineFailed),
    ScanCompleted(ScanFinished),
    ScanPartial(ScanFinished),
    ScanFailed(ScanFailed),
    FindingStatusChanged(FindingStatusChanged),
    RemediationRequested(RemediationRequested),
    VerificationCompleted(VerificationCompleted),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanCreated {
    pub scan_id: ScanId,
    pub target_ids: Vec<TargetId>,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanStarted {
    pub scan_id: ScanId,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineStarted {
    pub scan_id: ScanId,
    pub engine: EngineId,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineProgress {
    pub scan_id: ScanId,
    pub engine: EngineId,
    pub completed_units: u32,
    pub total_units: Option<u32>,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FindingObserved {
    pub scan_id: ScanId,
    pub finding_id: FindingId,
    pub fingerprint: FindingFingerprint,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence_id: EvidenceId,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineCompleted {
    pub scan_id: ScanId,
    pub engine: EngineId,
    pub observations: u32,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineFailed {
    pub scan_id: ScanId,
    pub engine: EngineId,
    pub failure: String,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanFinished {
    pub scan_id: ScanId,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanFailed {
    pub scan_id: ScanId,
    pub structural_failure: String,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FindingStatusChanged {
    pub scan_id: ScanId,
    pub finding_id: FindingId,
    pub previous: FindingStatus,
    pub current: FindingStatus,
    pub reason: String,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationRequested {
    pub scan_id: ScanId,
    pub finding_id: FindingId,
    pub remediation_id: RemediationId,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationCompleted {
    pub scan_id: ScanId,
    pub finding_id: FindingId,
    pub verification_id: VerificationId,
    pub still_present: bool,
    pub at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_round_trip_is_tagged_and_strict() {
        let event = DomainEvent::ScanStarted(ScanStarted {
            scan_id: ScanId::new("018f4c2a-1d3b-7abc-8def-0123456789ab").unwrap(),
            at: Timestamp::new("2026-09-02T03:00:00Z").unwrap(),
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("scan_started"));
        assert_eq!(serde_json::from_str::<DomainEvent>(&json).unwrap(), event);
    }
}
