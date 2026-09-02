//! Fixture-only parsers for pinned external engine output.
//!
//! This module does not construct commands or execute engines. Production execution
//! remains behind the process, manifest, receipt and network-enforcement gates.

use crate::manifest::{EngineManifest, EngineTrustPolicy};
use crate::receipt::{EngineReceipt, EngineState, IntegrityObservation, verify_execution_ready};
use edy_core::{Confidence, Severity};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

const MAX_ENGINE_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureOutcome {
    Exited(u32),
    TimedOut,
    Cancelled,
    OutputLimit,
}

pub struct CapturedOutput<'a> {
    pub outcome: CaptureOutcome,
    pub stdout: &'a [u8],
    pub stderr: &'a [u8],
}

#[cfg(windows)]
impl<'a> From<&'a crate::process::ProcessResult> for CapturedOutput<'a> {
    fn from(value: &'a crate::process::ProcessResult) -> Self {
        use crate::process::Outcome;
        Self {
            outcome: match value.outcome {
                Outcome::Exited(code) => CaptureOutcome::Exited(code),
                Outcome::TimedOut => CaptureOutcome::TimedOut,
                Outcome::Cancelled => CaptureOutcome::Cancelled,
                Outcome::OutputLimit => CaptureOutcome::OutputLimit,
            },
            stdout: &value.stdout,
            stderr: &value.stderr,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdapterExit {
    Clean,
    Findings,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NormalizedObservation {
    pub engine_id: String,
    pub engine_version: String,
    pub category: String,
    pub identifier: String,
    pub location_reference: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub package: Option<String>,
    pub installed_version: Option<String>,
    pub fixed_version: Option<String>,
    pub summary: String,
    pub fingerprint: String,
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdapterReport {
    pub engine_id: String,
    pub engine_version: String,
    pub exit: AdapterExit,
    pub observations: Vec<NormalizedObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterError {
    EmptyOutput,
    OutputTooLarge,
    TruncatedOutput,
    TimedOut,
    Cancelled,
    ProcessFailed,
    InvalidOutput,
    UnsupportedSchema,
    ExitMismatch,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyOutput => "engine output is empty",
            Self::OutputTooLarge => "engine output exceeds the parser limit",
            Self::TruncatedOutput => "engine output was truncated",
            Self::TimedOut => "engine process timed out",
            Self::Cancelled => "engine process was cancelled",
            Self::ProcessFailed => "engine process failed",
            Self::InvalidOutput => "engine output is invalid",
            Self::UnsupportedSchema => "engine output schema or version is unsupported",
            Self::ExitMismatch => "engine exit code disagrees with parsed output",
        })
    }
}

impl std::error::Error for AdapterError {}

pub trait EngineAdapter {
    fn engine_id(&self) -> &'static str;
    fn engine_version(&self) -> &'static str;
    fn parse_value(&self, value: &Value) -> Result<Vec<NormalizedObservation>, AdapterError>;
    fn classify_exit(
        &self,
        exit_code: u32,
        finding_count: usize,
    ) -> Result<AdapterExit, AdapterError>;

    fn parse(&self, output: CapturedOutput<'_>) -> Result<AdapterReport, AdapterError> {
        let exit_code = checked_capture(&output)?;
        let value = parse_json(output.stdout)?;
        let observations = deduplicate(self.parse_value(&value)?);
        let exit = self.classify_exit(exit_code, observations.len())?;
        Ok(AdapterReport {
            engine_id: self.engine_id().to_owned(),
            engine_version: self.engine_version().to_owned(),
            exit,
            observations,
        })
    }

    fn trust_gate(
        &self,
        manifest: &EngineManifest,
        receipt: Option<&EngineReceipt>,
        policy: &EngineTrustPolicy,
        observation: &IntegrityObservation,
    ) -> Result<EngineState, EngineState> {
        if manifest.identity.id != self.engine_id()
            || manifest.identity.version != self.engine_version()
        {
            return Err(EngineState::InvalidManifest);
        }
        verify_execution_ready(manifest, receipt, policy, observation)
    }
}

pub struct YaraXAdapter;
pub struct GitleaksAdapter;
pub struct TrivyAdapter;
pub struct OsvScannerAdapter;

impl EngineAdapter for YaraXAdapter {
    fn engine_id(&self) -> &'static str {
        "yara-x"
    }

    fn engine_version(&self) -> &'static str {
        "1.20.0"
    }

    fn parse_value(&self, value: &Value) -> Result<Vec<NormalizedObservation>, AdapterError> {
        let root = object(value)?;
        if string(root.get("version"))? != self.engine_version() {
            return Err(AdapterError::UnsupportedSchema);
        }
        let matches = array(root.get("matches"))?;
        matches
            .iter()
            .map(|item| {
                let item = object(item)?;
                let rule = safe_field(string(item.get("rule"))?)?;
                let location = normalize_location(string(item.get("file"))?)?;
                Ok(observation(
                    self,
                    "suspicious_file",
                    rule,
                    &location,
                    Severity::Medium,
                    Confidence::Medium,
                    None,
                    None,
                    None,
                    None,
                    "YARA-X rule match",
                    false,
                ))
            })
            .collect()
    }

    fn classify_exit(
        &self,
        exit_code: u32,
        finding_count: usize,
    ) -> Result<AdapterExit, AdapterError> {
        zero_exit(exit_code, finding_count)
    }
}

impl EngineAdapter for GitleaksAdapter {
    fn engine_id(&self) -> &'static str {
        "gitleaks"
    }

    fn engine_version(&self) -> &'static str {
        "8.30.0"
    }

    fn parse_value(&self, value: &Value) -> Result<Vec<NormalizedObservation>, AdapterError> {
        array(Some(value))?
            .iter()
            .map(|item| {
                let item = object(item)?;
                let rule = safe_field(string(item.get("RuleID"))?)?;
                let file = normalize_location(string(item.get("File"))?)?;
                let line = integer(item.get("StartLine"))?;
                let upstream_fingerprint = safe_field(string(item.get("Fingerprint"))?)?;
                let location = format!("{file}:{line}");
                Ok(observation(
                    self,
                    "secret_exposure",
                    rule,
                    &location,
                    Severity::High,
                    Confidence::Medium,
                    None,
                    None,
                    None,
                    Some(upstream_fingerprint),
                    "Potential secret detected; raw match removed",
                    true,
                ))
            })
            .collect()
    }

    fn classify_exit(
        &self,
        exit_code: u32,
        finding_count: usize,
    ) -> Result<AdapterExit, AdapterError> {
        match (exit_code, finding_count) {
            (0, 0) => Ok(AdapterExit::Clean),
            (1, 1..) => Ok(AdapterExit::Findings),
            (0 | 1, _) => Err(AdapterError::ExitMismatch),
            _ => Err(AdapterError::ProcessFailed),
        }
    }
}

impl EngineAdapter for TrivyAdapter {
    fn engine_id(&self) -> &'static str {
        "trivy"
    }

    fn engine_version(&self) -> &'static str {
        "0.74.0"
    }

    fn parse_value(&self, value: &Value) -> Result<Vec<NormalizedObservation>, AdapterError> {
        let root = object(value)?;
        if root.get("SchemaVersion").and_then(Value::as_u64) != Some(2) {
            return Err(AdapterError::UnsupportedSchema);
        }
        let mut observations = Vec::new();
        for result in array(root.get("Results"))? {
            let result = object(result)?;
            let location = normalize_location(string(result.get("Target"))?)?;
            for vulnerability in optional_array(result.get("Vulnerabilities"))? {
                let vulnerability = object(vulnerability)?;
                let id = safe_field(string(vulnerability.get("VulnerabilityID"))?)?;
                let package = safe_field(string(vulnerability.get("PkgName"))?)?;
                let installed = safe_field(string(vulnerability.get("InstalledVersion"))?)?;
                let fixed = optional_safe_field(vulnerability.get("FixedVersion"))?;
                let severity = parse_severity(string(vulnerability.get("Severity"))?)?;
                observations.push(observation(
                    self,
                    "dependency_vulnerability",
                    id,
                    &location,
                    severity,
                    Confidence::High,
                    Some(package),
                    Some(installed),
                    fixed,
                    None,
                    "Trivy dependency vulnerability",
                    false,
                ));
            }
        }
        Ok(observations)
    }

    fn classify_exit(
        &self,
        exit_code: u32,
        finding_count: usize,
    ) -> Result<AdapterExit, AdapterError> {
        zero_exit(exit_code, finding_count)
    }
}

impl EngineAdapter for OsvScannerAdapter {
    fn engine_id(&self) -> &'static str {
        "osv-scanner"
    }

    fn engine_version(&self) -> &'static str {
        "2.5.1"
    }

    fn parse_value(&self, value: &Value) -> Result<Vec<NormalizedObservation>, AdapterError> {
        let root = object(value)?;
        let mut observations = Vec::new();
        for result in array(root.get("results"))? {
            let result = object(result)?;
            let source = object(result.get("source").ok_or(AdapterError::InvalidOutput)?)?;
            let location = normalize_location(string(source.get("path"))?)?;
            for package_result in array(result.get("packages"))? {
                let package_result = object(package_result)?;
                let package = object(
                    package_result
                        .get("package")
                        .ok_or(AdapterError::InvalidOutput)?,
                )?;
                let package_name = safe_field(string(package.get("name"))?)?;
                let installed = safe_field(string(package.get("version"))?)?;
                for vulnerability in array(package_result.get("vulnerabilities"))? {
                    let vulnerability = object(vulnerability)?;
                    let id = safe_field(string(vulnerability.get("id"))?)?;
                    let fixed = osv_fixed_version(vulnerability)?;
                    let severity = vulnerability
                        .get("database_specific")
                        .and_then(Value::as_object)
                        .and_then(|database| database.get("severity"))
                        .and_then(Value::as_str)
                        .map(parse_severity)
                        .transpose()?
                        .unwrap_or(Severity::Medium);
                    observations.push(observation(
                        self,
                        "dependency_vulnerability",
                        id,
                        &location,
                        severity,
                        Confidence::High,
                        Some(package_name),
                        Some(installed),
                        fixed.as_deref(),
                        None,
                        "OSV dependency vulnerability",
                        false,
                    ));
                }
            }
        }
        Ok(observations)
    }

    fn classify_exit(
        &self,
        exit_code: u32,
        finding_count: usize,
    ) -> Result<AdapterExit, AdapterError> {
        match (exit_code, finding_count) {
            (0, 0) => Ok(AdapterExit::Clean),
            (1, 1..) => Ok(AdapterExit::Findings),
            (0 | 1, _) => Err(AdapterError::ExitMismatch),
            _ => Err(AdapterError::ProcessFailed),
        }
    }
}

fn checked_capture(output: &CapturedOutput<'_>) -> Result<u32, AdapterError> {
    match output.outcome {
        CaptureOutcome::TimedOut => Err(AdapterError::TimedOut),
        CaptureOutcome::Cancelled => Err(AdapterError::Cancelled),
        CaptureOutcome::OutputLimit => Err(AdapterError::TruncatedOutput),
        CaptureOutcome::Exited(code) => {
            if output.stdout.is_empty() {
                Err(AdapterError::EmptyOutput)
            } else if output.stdout.len() > MAX_ENGINE_OUTPUT_BYTES
                || output.stderr.len() > MAX_ENGINE_OUTPUT_BYTES
            {
                Err(AdapterError::OutputTooLarge)
            } else {
                Ok(code)
            }
        }
    }
}

fn parse_json(bytes: &[u8]) -> Result<Value, AdapterError> {
    serde_json::from_slice(bytes).map_err(|_| AdapterError::InvalidOutput)
}

fn object(value: &Value) -> Result<&serde_json::Map<String, Value>, AdapterError> {
    value.as_object().ok_or(AdapterError::InvalidOutput)
}

fn array(value: Option<&Value>) -> Result<&[Value], AdapterError> {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(AdapterError::InvalidOutput)
}

fn optional_array(value: Option<&Value>) -> Result<&[Value], AdapterError> {
    match value {
        None | Some(Value::Null) => Ok(&[]),
        Some(value) => value
            .as_array()
            .map(Vec::as_slice)
            .ok_or(AdapterError::InvalidOutput),
    }
}

fn string(value: Option<&Value>) -> Result<&str, AdapterError> {
    value
        .and_then(Value::as_str)
        .ok_or(AdapterError::InvalidOutput)
}

fn integer(value: Option<&Value>) -> Result<u64, AdapterError> {
    value
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(AdapterError::InvalidOutput)
}

fn safe_field(value: &str) -> Result<&str, AdapterError> {
    if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control) {
        return Err(AdapterError::InvalidOutput);
    }
    Ok(value)
}

fn optional_safe_field(value: Option<&Value>) -> Result<Option<&str>, AdapterError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => safe_field(value).map(Some),
        _ => Err(AdapterError::InvalidOutput),
    }
}

fn normalize_location(value: &str) -> Result<String, AdapterError> {
    let value = safe_field(value)?.replace('\\', "/");
    let components: Vec<_> = value
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    if components.is_empty() || components.contains(&"..") {
        return Err(AdapterError::InvalidOutput);
    }
    let absolute = value.starts_with('/')
        || value.starts_with("//")
        || components
            .first()
            .is_some_and(|component| component.ends_with(':'));
    let normalized = if absolute {
        format!("<target>/{}", components.last().unwrap())
    } else {
        components.join("/")
    };
    if normalized.len() > MAX_FIELD_BYTES {
        return Err(AdapterError::InvalidOutput);
    }
    Ok(normalized)
}

#[allow(clippy::too_many_arguments)]
fn observation<A: EngineAdapter + ?Sized>(
    adapter: &A,
    category: &str,
    identifier: &str,
    location: &str,
    severity: Severity,
    confidence: Confidence,
    package: Option<&str>,
    installed_version: Option<&str>,
    fixed_version: Option<&str>,
    identity_discriminator: Option<&str>,
    summary: &str,
    redacted: bool,
) -> NormalizedObservation {
    let fingerprint_input = format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}",
        adapter.engine_id(),
        category,
        identifier,
        location,
        package.unwrap_or(""),
        installed_version.unwrap_or(""),
        identity_discriminator.unwrap_or("")
    );
    NormalizedObservation {
        engine_id: adapter.engine_id().to_owned(),
        engine_version: adapter.engine_version().to_owned(),
        category: category.to_owned(),
        identifier: identifier.to_owned(),
        location_reference: location.to_owned(),
        severity,
        confidence,
        package: package.map(str::to_owned),
        installed_version: installed_version.map(str::to_owned),
        fixed_version: fixed_version.map(str::to_owned),
        summary: summary.to_owned(),
        fingerprint: format!("{:x}", Sha256::digest(fingerprint_input.as_bytes())),
        redacted,
    }
}

fn deduplicate(observations: Vec<NormalizedObservation>) -> Vec<NormalizedObservation> {
    let mut fingerprints = BTreeSet::new();
    observations
        .into_iter()
        .filter(|observation| fingerprints.insert(observation.fingerprint.clone()))
        .collect()
}

fn zero_exit(exit_code: u32, finding_count: usize) -> Result<AdapterExit, AdapterError> {
    if exit_code != 0 {
        return Err(AdapterError::ProcessFailed);
    }
    Ok(if finding_count == 0 {
        AdapterExit::Clean
    } else {
        AdapterExit::Findings
    })
}

fn parse_severity(value: &str) -> Result<Severity, AdapterError> {
    match value.to_ascii_uppercase().as_str() {
        "UNKNOWN" | "INFORMATIONAL" | "INFO" => Ok(Severity::Info),
        "LOW" => Ok(Severity::Low),
        "MEDIUM" | "MODERATE" => Ok(Severity::Medium),
        "HIGH" => Ok(Severity::High),
        "CRITICAL" => Ok(Severity::Critical),
        _ => Err(AdapterError::UnsupportedSchema),
    }
}

fn osv_fixed_version(
    vulnerability: &serde_json::Map<String, Value>,
) -> Result<Option<String>, AdapterError> {
    let Some(affected) = vulnerability.get("affected") else {
        return Ok(None);
    };
    for affected in array(Some(affected))? {
        let affected = object(affected)?;
        for range in optional_array(affected.get("ranges"))? {
            let range = object(range)?;
            for event in optional_array(range.get("events"))? {
                let event = object(event)?;
                if let Some(fixed) = optional_safe_field(event.get("fixed"))? {
                    return Ok(Some(fixed.to_owned()));
                }
            }
        }
    }
    Ok(None)
}
