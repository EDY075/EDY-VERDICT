#![forbid(unsafe_code)]
//! No real providers or networking. Infrastructure fakes only.
use edy_core::{Availability, Coverage, ProviderPort, ProviderStatus};

pub struct FakeProvider {
    pub id: String,
    pub availability: Availability,
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
}
