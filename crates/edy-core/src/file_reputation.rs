use crate::{Availability, Sha256Digest, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilePrivacyMode {
    LocalOnly,
    HashLookup,
    CloudAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileReputationQuery {
    pub sha256: Sha256Digest,
    pub privacy_mode: FilePrivacyMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileReputationResult {
    pub provider: String,
    pub hash_queried: Sha256Digest,
    pub availability: Availability,
    pub known: Option<bool>,
    pub malicious_count: Option<u32>,
    pub suspicious_count: Option<u32>,
    pub harmless_count: Option<u32>,
    pub undetected_count: Option<u32>,
    pub lookup_timestamp: Option<Timestamp>,
    pub freshness_seconds: Option<u64>,
    pub provider_error_safe: Option<String>,
}

pub trait FileReputationPort {
    fn status(&self) -> Availability;

    fn lookup_hash(
        &self,
        query: &FileReputationQuery,
    ) -> Result<FileReputationResult, &'static str>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_modes_are_explicit_and_cloud_is_not_an_implicit_default() {
        let query = FileReputationQuery {
            sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
            privacy_mode: FilePrivacyMode::LocalOnly,
        };
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("local_only"));
        assert!(!json.contains("cloud_analysis"));
    }
}
