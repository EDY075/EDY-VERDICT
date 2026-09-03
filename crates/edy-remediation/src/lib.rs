//! Safe, bounded Level 6 remediation.
//!
//! This crate deliberately owns no shell adapter and accepts no frontend-authored patch.
//!
//! Production does not export the mutating entrypoint (L6-S01 regression):
//! ```compile_fail
//! use edy_remediation::apply_exact_edit;
//! ```
//! ```compile_fail
//! use edy_remediation::rollback_exact_edit;
//! ```

mod domain;
#[cfg(any(test, feature = "test-remediation-executor"))]
mod executor;
mod legacy_snapshot;
mod manual;
mod manual_target;
#[cfg(any(test, feature = "test-remediation-executor"))]
mod service;

pub use domain::*;
#[cfg(any(test, feature = "test-remediation-executor"))]
pub use executor::*;
pub use legacy_snapshot::*;
pub use manual::*;
pub use manual_target::*;
#[cfg(any(test, feature = "test-remediation-executor"))]
pub use service::*;

#[cfg(all(feature = "test-remediation-executor", not(debug_assertions)))]
compile_error!("test-remediation-executor is forbidden in production release builds");

pub const PRODUCTION_MUTATING_REMEDIATION: bool = false;

pub const REMEDIATION_ACTION_ID_VERSION: &str = "REMEDIATION_ACTION_ID_V1";
pub const EXACT_TEXT_CONFIG_RULE_ID: &str = "EXACT_TEXT_CONFIG_REMEDIATION_V1";
pub const EXACT_TEXT_CONFIG_RULE_VERSION: u32 = 1;
