//! Infrastructure only; no real engine or target analysis.
pub mod adapters;
pub mod manifest;
#[cfg(windows)]
pub mod process;
pub mod receipt;
