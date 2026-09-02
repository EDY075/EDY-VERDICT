#![forbid(unsafe_code)]
//! Backend application services. The Tauri host remains a thin, untrusted-UI boundary.

pub mod ipc;
pub mod level0;
