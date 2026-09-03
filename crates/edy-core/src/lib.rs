#![forbid(unsafe_code)]
//! Pure EDY VERDICT domain contracts. No I/O, engine process, storage, UI or network code.

mod correlation;
mod domain;
mod events;
mod file_reputation;
mod fingerprint;
mod ids;
mod installed_apps;
mod investigation;
mod lifecycle;
mod orchestrator;
mod remediation;
mod validation;
mod web;

pub use correlation::*;
pub use domain::*;
pub use events::*;
pub use file_reputation::*;
pub use fingerprint::*;
pub use ids::*;
pub use installed_apps::*;
pub use investigation::*;
pub use lifecycle::*;
pub use orchestrator::*;
pub use remediation::*;
pub use validation::{DomainError, ValidationErrorKind};
pub use web::*;

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

pub trait ProviderPort {
    fn status(&self) -> ProviderStatus;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanResult {
    pub request_id: ScanId,
    pub findings: Vec<Finding>,
    pub coverage: ScanCoverage,
    pub verdict: Verdict,
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

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
