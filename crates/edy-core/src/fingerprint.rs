use crate::{DomainError, ValidationErrorKind, validation};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

pub const FINDING_FINGERPRINT_VERSION: &str = "FINDING_FINGERPRINT_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingFingerprintInput<'a> {
    pub target_kind: &'a str,
    pub canonical_target: &'a str,
    pub category: &'a str,
    pub semantic_key: &'a str,
    pub canonical_location: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct FindingFingerprint(String);

impl FindingFingerprint {
    pub fn from_input(input: &FindingFingerprintInput<'_>) -> Result<Self, DomainError> {
        for (field, value) in [
            ("target_kind", input.target_kind),
            ("canonical_target", input.canonical_target),
            ("category", input.category),
            ("semantic_key", input.semantic_key),
            ("canonical_location", input.canonical_location),
        ] {
            validation::bounded_text(field, value, 4096)?;
        }
        let mut canonical = Vec::new();
        for value in [
            input.target_kind,
            input.canonical_target,
            input.category,
            input.semantic_key,
            input.canonical_location,
        ] {
            let normalized = normalize(value);
            canonical.extend_from_slice(&(normalized.len() as u32).to_be_bytes());
            canonical.extend_from_slice(normalized.as_bytes());
        }
        // Two domain-separated FNV-1a 64-bit passes. This is a stable deduplication
        // identifier, explicitly not a cryptographic integrity or security hash.
        let high = fnv1a(&canonical, 0xcbf29ce484222325);
        let low = fnv1a(&canonical, 0x84222325cbf29ce4);
        Ok(Self(format!("ffp1-{high:016x}{low:016x}")))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.len() != 37
            || !value.starts_with("ffp1-")
            || !value[5..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(DomainError::new(
                "fingerprint",
                ValidationErrorKind::InvalidFormat,
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FindingFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for FindingFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn normalize(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn fnv1a(bytes: &[u8], seed: u64) -> u64 {
    bytes.iter().fold(seed, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(semantic_key: &'a str) -> FindingFingerprintInput<'a> {
        FindingFingerprintInput {
            target_kind: "repository",
            canonical_target: "d:/synthetic/repo",
            category: "vulnerability",
            semantic_key,
            canonical_location: "cargo.lock",
        }
    }

    #[test]
    fn fingerprint_is_deterministic_and_excludes_source_and_time() {
        let first = FindingFingerprint::from_input(&input("CVE-2099-0001")).unwrap();
        let second = FindingFingerprint::from_input(&input("  cve-2099-0001 ")).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.as_str(), "ffp1-13cc8ebf448ce5e5c1ec259256108d7e");
    }

    #[test]
    fn semantic_identity_changes_fingerprint() {
        assert_ne!(
            FindingFingerprint::from_input(&input("CVE-2099-0001")).unwrap(),
            FindingFingerprint::from_input(&input("CVE-2099-0002")).unwrap()
        );
    }
}
