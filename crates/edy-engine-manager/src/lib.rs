//! Infrastructure only; no real engine or target analysis.
pub mod adapters;
#[cfg(windows)]
pub mod execution;
pub mod file_security;
pub mod manifest;
#[cfg(windows)]
pub mod process;
pub mod receipt;
pub mod repository;
