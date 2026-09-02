#![deny(unsafe_code)]
//! Provider adapters. Host inventory stays local; public-data clients accept no host inventory.
pub mod installed_apps;
use edy_core::{
    Availability, Coverage, FilePrivacyMode, FileReputationPort, FileReputationQuery,
    FileReputationResult, ProviderPort, ProviderStatus,
};

pub struct FakeProvider {
    pub id: String,
    pub availability: Availability,
}

/// Level 2 provider boundary. It never accepts file bytes or a file path.
pub struct DisabledHashReputationProvider {
    pub id: String,
    pub availability: Availability,
}

impl FileReputationPort for DisabledHashReputationProvider {
    fn status(&self) -> Availability {
        self.availability
    }

    fn lookup_hash(
        &self,
        query: &FileReputationQuery,
    ) -> Result<FileReputationResult, &'static str> {
        if query.privacy_mode != FilePrivacyMode::HashLookup {
            return Err("hash lookup requires explicit privacy mode");
        }
        Err("network reputation lookup is disabled")
    }
}
impl ProviderPort for FakeProvider {
    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            id: self.id.clone(),
            availability: self.availability,
            coverage: if self.availability == Availability::Available {
                Coverage::NotAssessed
            } else {
                Coverage::Incomplete
            },
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_availability_states_are_not_clean() {
        for availability in [
            Availability::Available,
            Availability::NotConfigured,
            Availability::Offline,
            Availability::RateLimited,
            Availability::Unavailable,
            Availability::PolicyBlocked,
        ] {
            let provider = FakeProvider {
                id: "fake".into(),
                availability,
            };
            assert_eq!(provider.status().availability, availability);
            assert_ne!(provider.status().coverage, Coverage::Complete);
        }
    }

    #[test]
    fn reputation_contract_never_accepts_or_uploads_file_bytes() {
        let provider = DisabledHashReputationProvider {
            id: "fixture".into(),
            availability: Availability::NotConfigured,
        };
        let query = FileReputationQuery {
            sha256: edy_core::Sha256Digest::new("b".repeat(64)).unwrap(),
            privacy_mode: FilePrivacyMode::HashLookup,
        };
        assert_eq!(provider.status(), Availability::NotConfigured);
        assert_eq!(
            provider.lookup_hash(&query),
            Err("network reputation lookup is disabled")
        );
    }
}
