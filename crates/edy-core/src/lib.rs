#![forbid(unsafe_code)]
//! Structural contracts only. No scanner or verdict implementation.
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    pub schema_version: u32,
    pub producer_version: String,
    pub generated_at_utc: String,
    pub data: T,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    NotConfigured,
    Offline,
    RateLimited,
    Unavailable,
    PolicyBlocked,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    NotAssessed,
    Complete,
    Incomplete,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationState {
    Proposed,
    Review,
    Approved,
    Execute,
    Verify,
    Resolved,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    pub id: String,
    pub target_reference: String,
    pub provider_ids: Vec<String>,
    pub engine_ids: Vec<String>,
    pub offline: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanResult {
    pub request_id: String,
    pub findings: Vec<Finding>,
    pub coverage: Coverage,
    pub provider_statuses: Vec<ProviderStatus>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub category: String,
    pub location_reference: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence_ids: Vec<String>,
    pub fingerprint: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub id: String,
    pub source: String,
    pub observed_at_utc: String,
    pub fact: String,
    pub integrity_sha256: String,
    pub redacted: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderStatus {
    pub id: String,
    pub availability: Availability,
    pub coverage: Coverage,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineStatus {
    pub id: String,
    pub version: String,
    pub integrity_verified: bool,
    pub availability: Availability,
    pub coverage: Coverage,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Risk {
    pub severity: Severity,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
    pub cvss: Option<String>,
    pub kev: Option<bool>,
    pub epss_probability: Option<f64>,
    pub exposed: Option<bool>,
    pub fix_available: Option<bool>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Remediation {
    pub id: String,
    pub state: RemediationState,
    pub proposal: String,
    pub requires_authorization: bool,
    pub verification_evidence: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub id: String,
    pub at_utc: String,
    pub operation_id: String,
    pub actor: String,
    pub action: String,
    pub object_reference: String,
    pub decision: String,
    pub result: String,
}

pub trait ProviderPort {
    fn status(&self) -> ProviderStatus;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confidence_is_not_severity() {
        let risk = Risk {
            severity: Severity::Critical,
            confidence: Confidence::Low,
            reasons: vec![],
            cvss: None,
            kev: None,
            epss_probability: None,
            exposed: None,
            fix_available: None,
        };
        let json = serde_json::to_value(risk).unwrap();
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["confidence"], "low");
    }
    #[test]
    fn unavailable_has_no_clean_representation() {
        let status = ProviderStatus {
            id: "fixture".into(),
            availability: Availability::Unavailable,
            coverage: Coverage::Incomplete,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("clean"));
        assert_eq!(
            serde_json::from_str::<ProviderStatus>(&json).unwrap(),
            status
        );
        assert!(
            serde_json::from_str::<ProviderStatus>(
                r#"{"id":"fixture","availability":"clean","coverage":"complete"}"#
            )
            .is_err()
        );
    }
}
