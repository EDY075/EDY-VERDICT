//! Production-shaped Level 1 repository adapters.
//!
//! They accept only an authorized target, parse bounded captured output, and return
//! normalized observations. Process execution remains policy-blocked.

use edy_repository::{
    AuthorizedRepositoryTarget, RepositoryDocumentKind, RepositoryFindingCategory,
    RepositoryInventory, RepositoryObservation, finding_fingerprint, normalize_reported_path,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAX_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_FIELD: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryAdapterError {
    EmptyOutput,
    OutputTooLarge,
    InvalidJson,
    InvalidSchema,
    MissingField,
    FieldTooLarge,
    PathEscape,
}

impl fmt::Display for RepositoryAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyOutput => "engine output is empty",
            Self::OutputTooLarge => "engine output exceeds the parser limit",
            Self::InvalidJson => "engine output is not valid JSON",
            Self::InvalidSchema => "engine output schema is unsupported",
            Self::MissingField => "required engine field is missing",
            Self::FieldTooLarge => "engine field exceeds the parser limit",
            Self::PathEscape => "engine output path escapes the authorized target",
        })
    }
}
impl std::error::Error for RepositoryAdapterError {}

pub struct GitleaksRepositoryAdapter;

impl GitleaksRepositoryAdapter {
    pub fn parse(
        &self,
        target: &AuthorizedRepositoryTarget,
        bytes: &[u8],
    ) -> Result<Vec<RepositoryObservation>, RepositoryAdapterError> {
        let value = parse_json(bytes)?;
        let items = value
            .as_array()
            .ok_or(RepositoryAdapterError::InvalidSchema)?;
        let mut findings = Vec::with_capacity(items.len());
        for value in items {
            let item = object(value)?;
            let rule = field(item, "RuleID")?;
            let description = field(item, "Description")?;
            let reported = field(item, "File")?;
            let location = normalize_reported_path(target, reported)
                .map_err(|_| RepositoryAdapterError::PathEscape)?;
            let line = positive_u64(item, "StartLine")?;
            let upstream_fingerprint = field(item, "Fingerprint")?;
            let secret = field(item, "Secret")?;
            let digest = secret_digest(secret, upstream_fingerprint);
            let preview = redacted_preview(secret);
            let fingerprint = finding_fingerprint(
                "SECRET_FINDING_V1",
                target,
                &[rule, &location, &line.to_string(), &digest],
            );
            let mut metadata = BTreeMap::new();
            if let Some(entropy) = item.get("Entropy").and_then(Value::as_f64) {
                metadata.insert("entropy".into(), format!("{entropy:.4}"));
            }
            findings.push(RepositoryObservation {
                engine_id: "gitleaks".into(),
                engine_version: "8.30.0".into(),
                category: RepositoryFindingCategory::Secret,
                rule_id: rule.into(),
                description: description.into(),
                location,
                line: Some(line),
                severity: "high".into(),
                confidence: "high".into(),
                fingerprint_version: "SECRET_FINDING_V1".into(),
                fingerprint,
                package: None,
                installed_version: None,
                vulnerability_id: None,
                aliases: vec![],
                affected_range: None,
                fixed_version: None,
                source: Some("gitleaks".into()),
                secret_class: Some(rule.into()),
                secret_preview: Some(preview),
                secret_digest: Some(digest),
                license: None,
                metadata,
            });
        }
        Ok(deduplicate(findings))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsvScanPlan {
    pub lockfiles: Vec<String>,
    pub execution_policy: &'static str,
}

pub struct OsvRepositoryAdapter;

impl OsvRepositoryAdapter {
    pub fn plan(&self, inventory: &RepositoryInventory) -> OsvScanPlan {
        OsvScanPlan {
            lockfiles: inventory
                .documents
                .iter()
                .filter(|doc| doc.kind == RepositoryDocumentKind::Lockfile)
                .map(|doc| doc.relative_path.clone())
                .collect(),
            execution_policy: "skipped_by_policy_offline_data_unavailable",
        }
    }

    pub fn parse(
        &self,
        target: &AuthorizedRepositoryTarget,
        bytes: &[u8],
    ) -> Result<Vec<RepositoryObservation>, RepositoryAdapterError> {
        let root = object(&parse_json(bytes)?)?.clone();
        let results = array(root.get("results"))?;
        let mut findings = Vec::new();
        for result in results {
            let result = object(result)?;
            let source = object(required(result, "source")?)?;
            let path = normalize_reported_path(target, field(source, "path")?)
                .map_err(|_| RepositoryAdapterError::PathEscape)?;
            let source_type = optional_field(source, "type")?.unwrap_or("lockfile");
            for package_result in array(result.get("packages"))? {
                let package_result = object(package_result)?;
                let package = object(required(package_result, "package")?)?;
                let name = field(package, "name")?;
                let version = field(package, "version")?;
                let ecosystem = field(package, "ecosystem")?;
                for vulnerability in array(package_result.get("vulnerabilities"))? {
                    let vulnerability = object(vulnerability)?;
                    let id = field(vulnerability, "id")?;
                    let aliases = optional_string_array(vulnerability.get("aliases"))?;
                    let affected_range =
                        optional_field(vulnerability, "affected_range")?.map(str::to_owned);
                    let fixed_version = fixed_version(vulnerability)?;
                    let severity = vulnerability
                        .get("database_specific")
                        .and_then(Value::as_object)
                        .and_then(|v| v.get("severity"))
                        .and_then(Value::as_str)
                        .map(normalize_severity)
                        .transpose()?
                        .unwrap_or("medium");
                    let fingerprint = finding_fingerprint(
                        "VULNERABILITY_FINDING_V1",
                        target,
                        &[ecosystem, name, version, id, &path],
                    );
                    findings.push(RepositoryObservation {
                        engine_id: "osv-scanner".into(),
                        engine_version: "2.5.1".into(),
                        category: RepositoryFindingCategory::VulnerableDependency,
                        rule_id: id.into(),
                        description: "Dependency vulnerability reported by OSV".into(),
                        location: path.clone(),
                        line: None,
                        severity: severity.into(),
                        confidence: "high".into(),
                        fingerprint_version: "VULNERABILITY_FINDING_V1".into(),
                        fingerprint,
                        package: Some(format!("{ecosystem}:{name}")),
                        installed_version: Some(version.into()),
                        vulnerability_id: Some(id.into()),
                        aliases,
                        affected_range,
                        fixed_version,
                        source: Some(source_type.into()),
                        secret_class: None,
                        secret_preview: None,
                        secret_digest: None,
                        license: None,
                        metadata: BTreeMap::new(),
                    });
                }
            }
        }
        Ok(deduplicate(findings))
    }
}

pub struct TrivyRepositoryAdapter;

impl TrivyRepositoryAdapter {
    pub fn parse(
        &self,
        target: &AuthorizedRepositoryTarget,
        bytes: &[u8],
    ) -> Result<Vec<RepositoryObservation>, RepositoryAdapterError> {
        let root = object(&parse_json(bytes)?)?.clone();
        if root.get("SchemaVersion").and_then(Value::as_u64) != Some(2) {
            return Err(RepositoryAdapterError::InvalidSchema);
        }
        let mut findings = Vec::new();
        for result in array(root.get("Results"))? {
            let result = object(result)?;
            let location = normalize_reported_path(target, field(result, "Target")?)
                .map_err(|_| RepositoryAdapterError::PathEscape)?;
            for vulnerability in optional_array(result.get("Vulnerabilities"))? {
                let item = object(vulnerability)?;
                let id = field(item, "VulnerabilityID")?;
                let package = field(item, "PkgName")?;
                let installed = field(item, "InstalledVersion")?;
                let fixed = optional_field(item, "FixedVersion")?.map(str::to_owned);
                let severity = normalize_severity(field(item, "Severity")?)?;
                findings.push(vulnerability_observation(
                    target, "trivy", "0.74.0", id, package, installed, fixed, &location, severity,
                ));
            }
            for misconfiguration in optional_array(result.get("Misconfigurations"))? {
                let item = object(misconfiguration)?;
                let id = field(item, "ID")?;
                let title = field(item, "Title")?;
                let severity = normalize_severity(field(item, "Severity")?)?;
                let fingerprint =
                    finding_fingerprint("MISCONFIG_FINDING_V1", target, &[id, &location]);
                findings.push(base_observation(
                    "trivy",
                    "0.74.0",
                    RepositoryFindingCategory::Misconfiguration,
                    id,
                    title,
                    &location,
                    severity,
                    "MISCONFIG_FINDING_V1",
                    fingerprint,
                ));
            }
            for license in optional_array(result.get("Licenses"))? {
                let item = object(license)?;
                let name = field(item, "Name")?;
                let package = optional_field(item, "PkgName")?.map(str::to_owned);
                let category = optional_field(item, "Category")?.unwrap_or("unknown");
                let fingerprint = finding_fingerprint(
                    "LICENSE_FINDING_V1",
                    target,
                    &[name, package.as_deref().unwrap_or(""), &location],
                );
                let mut observation = base_observation(
                    "trivy",
                    "0.74.0",
                    RepositoryFindingCategory::License,
                    name,
                    "License observation; legal review is separate",
                    &location,
                    "info",
                    "LICENSE_FINDING_V1",
                    fingerprint,
                );
                observation.package = package;
                observation.license = Some(name.into());
                observation
                    .metadata
                    .insert("license_status".into(), category.to_ascii_lowercase());
                findings.push(observation);
            }
            for secret in optional_array(result.get("Secrets"))? {
                let item = object(secret)?;
                let rule = field(item, "RuleID")?;
                let fingerprint =
                    finding_fingerprint("SECRET_FINDING_V1", target, &[rule, &location]);
                let digest = format!("{:x}", Sha256::digest(fingerprint.as_bytes()));
                let mut observation = base_observation(
                    "trivy",
                    "0.74.0",
                    RepositoryFindingCategory::Secret,
                    rule,
                    "Potential secret detected; raw match removed",
                    &location,
                    "high",
                    "SECRET_FINDING_V1",
                    fingerprint,
                );
                observation.secret_class = Some(rule.into());
                observation.secret_preview = Some("[REDACTED]".into());
                observation.secret_digest = Some(digest);
                findings.push(observation);
            }
        }
        Ok(deduplicate(findings))
    }
}

#[allow(clippy::too_many_arguments)]
fn vulnerability_observation(
    target: &AuthorizedRepositoryTarget,
    engine: &str,
    version: &str,
    id: &str,
    package: &str,
    installed: &str,
    fixed: Option<String>,
    location: &str,
    severity: &str,
) -> RepositoryObservation {
    let fingerprint = finding_fingerprint(
        "VULNERABILITY_FINDING_V1",
        target,
        &[package, installed, id, location],
    );
    let mut observation = base_observation(
        engine,
        version,
        RepositoryFindingCategory::VulnerableDependency,
        id,
        "Dependency vulnerability reported by Trivy",
        location,
        severity,
        "VULNERABILITY_FINDING_V1",
        fingerprint,
    );
    observation.package = Some(package.into());
    observation.installed_version = Some(installed.into());
    observation.vulnerability_id = Some(id.into());
    observation.fixed_version = fixed;
    observation.source = Some("trivy-db".into());
    observation
}

#[allow(clippy::too_many_arguments)]
fn base_observation(
    engine: &str,
    version: &str,
    category: RepositoryFindingCategory,
    rule: &str,
    description: &str,
    location: &str,
    severity: &str,
    fingerprint_version: &str,
    fingerprint: String,
) -> RepositoryObservation {
    RepositoryObservation {
        engine_id: engine.into(),
        engine_version: version.into(),
        category,
        rule_id: rule.into(),
        description: description.into(),
        location: location.into(),
        line: None,
        severity: severity.into(),
        confidence: "high".into(),
        fingerprint_version: fingerprint_version.into(),
        fingerprint,
        package: None,
        installed_version: None,
        vulnerability_id: None,
        aliases: vec![],
        affected_range: None,
        fixed_version: None,
        source: None,
        secret_class: None,
        secret_preview: None,
        secret_digest: None,
        license: None,
        metadata: BTreeMap::new(),
    }
}

fn parse_json(bytes: &[u8]) -> Result<Value, RepositoryAdapterError> {
    if bytes.is_empty() {
        return Err(RepositoryAdapterError::EmptyOutput);
    }
    if bytes.len() > MAX_OUTPUT {
        return Err(RepositoryAdapterError::OutputTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| RepositoryAdapterError::InvalidJson)
}
fn object(value: &Value) -> Result<&Map<String, Value>, RepositoryAdapterError> {
    value
        .as_object()
        .ok_or(RepositoryAdapterError::InvalidSchema)
}
fn required<'a>(
    map: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Value, RepositoryAdapterError> {
    map.get(key).ok_or(RepositoryAdapterError::MissingField)
}
fn field<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, RepositoryAdapterError> {
    let value = required(map, key)?
        .as_str()
        .ok_or(RepositoryAdapterError::InvalidSchema)?;
    if value.is_empty() {
        return Err(RepositoryAdapterError::MissingField);
    }
    if value.len() > MAX_FIELD || value.chars().any(char::is_control) {
        return Err(RepositoryAdapterError::FieldTooLarge);
    }
    Ok(value)
}
fn optional_field<'a>(
    map: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, RepositoryAdapterError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value))
            if value.len() <= MAX_FIELD && !value.chars().any(char::is_control) =>
        {
            Ok(Some(value))
        }
        Some(Value::String(_)) => Err(RepositoryAdapterError::FieldTooLarge),
        _ => Err(RepositoryAdapterError::InvalidSchema),
    }
}
fn positive_u64(map: &Map<String, Value>, key: &str) -> Result<u64, RepositoryAdapterError> {
    required(map, key)?
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or(RepositoryAdapterError::InvalidSchema)
}
fn array(value: Option<&Value>) -> Result<&[Value], RepositoryAdapterError> {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(RepositoryAdapterError::MissingField)
}
fn optional_array(value: Option<&Value>) -> Result<&[Value], RepositoryAdapterError> {
    match value {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(v)) => Ok(v),
        _ => Err(RepositoryAdapterError::InvalidSchema),
    }
}
fn optional_string_array(value: Option<&Value>) -> Result<Vec<String>, RepositoryAdapterError> {
    let mut values = optional_array(value)?
        .iter()
        .map(|v| v.as_str().ok_or(RepositoryAdapterError::InvalidSchema))
        .collect::<Result<Vec<_>, _>>()?;
    if values.iter().any(|v| v.is_empty() || v.len() > MAX_FIELD) {
        return Err(RepositoryAdapterError::FieldTooLarge);
    }
    values.sort_unstable();
    values.dedup();
    Ok(values.into_iter().map(str::to_owned).collect())
}
fn normalize_severity(value: &str) -> Result<&'static str, RepositoryAdapterError> {
    match value.to_ascii_lowercase().as_str() {
        "unknown" | "info" | "informational" => Ok("info"),
        "low" => Ok("low"),
        "medium" | "moderate" => Ok("medium"),
        "high" => Ok("high"),
        "critical" => Ok("critical"),
        _ => Err(RepositoryAdapterError::InvalidSchema),
    }
}
fn fixed_version(map: &Map<String, Value>) -> Result<Option<String>, RepositoryAdapterError> {
    for affected in optional_array(map.get("affected"))? {
        for range in optional_array(object(affected)?.get("ranges"))? {
            for event in optional_array(object(range)?.get("events"))? {
                if let Some(value) = optional_field(object(event)?, "fixed")? {
                    return Ok(Some(value.into()));
                }
            }
        }
    }
    Ok(None)
}
fn secret_digest(secret: &str, upstream_fingerprint: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"EDY_SECRET_DIGEST_V1\0");
    hash.update(secret.as_bytes());
    hash.update([0]);
    hash.update(upstream_fingerprint.as_bytes());
    format!("{:x}", hash.finalize())
}
fn redacted_preview(secret: &str) -> String {
    if secret.eq_ignore_ascii_case("redacted") {
        return "[REDACTED]".into();
    }
    let prefix = secret
        .find('_')
        .map_or(secret.chars().take(4).collect::<String>(), |i| {
            secret[..=i].to_owned()
        });
    format!(
        "{}************",
        prefix.chars().take(12).collect::<String>()
    )
}
fn deduplicate(findings: Vec<RepositoryObservation>) -> Vec<RepositoryObservation> {
    let mut seen = BTreeSet::new();
    findings
        .into_iter()
        .filter(|item| seen.insert(item.fingerprint.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use edy_core::TargetId;
    use edy_repository::{RepositoryLimits, inspect};
    use std::fs;
    use std::path::{Path, PathBuf};

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/synthetic-repository-a")
    }
    fn target() -> AuthorizedRepositoryTarget {
        AuthorizedRepositoryTarget::authorize(
            fixture_root().to_str().unwrap(),
            TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789b1").unwrap(),
            "018f4c2a-1d3b-7abc-8def-0123456789b2",
            "2026-09-02T13:00:00Z",
            RepositoryLimits::default(),
        )
        .unwrap()
    }
    fn fake_secret() -> String {
        fs::read_to_string(fixture_root().join("config/test-secret.env"))
            .unwrap()
            .trim()
            .split_once('=')
            .unwrap()
            .1
            .into()
    }

    #[test]
    fn gitleaks_redacts_deduplicates_and_never_serializes_plaintext() {
        let secret = fake_secret();
        let item = serde_json::json!({
            "RuleID":"generic-api-key", "Description":"Synthetic credential",
            "File":"config/test-secret.env", "StartLine":1, "Fingerprint":"fixture:1", "Secret":secret, "Entropy":4.2
        });
        let bytes = serde_json::to_vec(&serde_json::json!([item.clone(), item])).unwrap();
        let observations = GitleaksRepositoryAdapter.parse(&target(), &bytes).unwrap();
        assert_eq!(observations.len(), 1);
        let serialized = serde_json::to_string(&observations).unwrap();
        assert!(!serialized.contains(&secret));
        assert!(serialized.contains("************"));
    }

    #[test]
    fn gitleaks_rejects_malformed_missing_huge_and_escape() {
        let adapter = GitleaksRepositoryAdapter;
        let target = target();
        assert_eq!(
            adapter.parse(&target, b"{").unwrap_err(),
            RepositoryAdapterError::InvalidJson
        );
        assert_eq!(
            adapter.parse(&target, br#"[{"RuleID":"x"}]"#).unwrap_err(),
            RepositoryAdapterError::MissingField
        );
        let huge = "x".repeat(MAX_FIELD + 1);
        let invalid = serde_json::to_vec(&serde_json::json!([{"RuleID": huge,"Description":"x","File":"safe.txt","StartLine":1,"Fingerprint":"x","Secret":"x"}])).unwrap();
        assert_eq!(
            adapter.parse(&target, &invalid).unwrap_err(),
            RepositoryAdapterError::FieldTooLarge
        );
        let escape = serde_json::to_vec(&serde_json::json!([{"RuleID":"x","Description":"x","File":"../outside","StartLine":1,"Fingerprint":"x","Secret":"x"}])).unwrap();
        assert_eq!(
            adapter.parse(&target, &escape).unwrap_err(),
            RepositoryAdapterError::PathEscape
        );
    }

    #[test]
    fn osv_routes_only_lockfiles_and_does_not_invent_fix() {
        let target = target();
        let plan = OsvRepositoryAdapter.plan(&inspect(&target).unwrap());
        assert!(plan.lockfiles.iter().all(|path| path.ends_with("lock")
            || path.ends_with("lock.yaml")
            || path.ends_with("lock.json")));
        let json = br#"{"results":[{"source":{"path":"Cargo.lock","type":"lockfile"},"packages":[{"package":{"name":"synthetic-vulnerable","version":"0.1.0","ecosystem":"crates.io"},"vulnerabilities":[{"id":"GHSA-TEST-0001","aliases":["CVE-2099-0001"],"affected_range":"<1.0.0","database_specific":{"severity":"HIGH"}}]}]}]}"#;
        let observations = OsvRepositoryAdapter.parse(&target, json).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].fixed_version, None);
        assert_eq!(
            observations[0].category,
            RepositoryFindingCategory::VulnerableDependency
        );
    }

    #[test]
    fn trivy_keeps_output_categories_separate() {
        let json = br#"{"SchemaVersion":2,"Results":[{"Target":"Cargo.lock","Vulnerabilities":[{"VulnerabilityID":"CVE-2099-0001","PkgName":"synthetic-vulnerable","InstalledVersion":"0.1.0","FixedVersion":"1.0.0","Severity":"HIGH"}],"Misconfigurations":[{"ID":"CFG-001","Title":"Unsafe synthetic configuration","Severity":"MEDIUM"}],"Licenses":[{"Name":"MIT","PkgName":"safe","Category":"detected"}],"Secrets":[{"RuleID":"synthetic-secret"}]}]}"#;
        let observations = TrivyRepositoryAdapter.parse(&target(), json).unwrap();
        let categories: BTreeSet<_> = observations.iter().map(|item| item.category).collect();
        assert_eq!(categories.len(), 4);
        assert!(categories.contains(&RepositoryFindingCategory::Secret));
        assert!(categories.contains(&RepositoryFindingCategory::License));
        assert!(categories.contains(&RepositoryFindingCategory::Misconfiguration));
        assert!(categories.contains(&RepositoryFindingCategory::VulnerableDependency));
    }
}
