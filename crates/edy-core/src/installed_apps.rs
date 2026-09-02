//! Pure Level 3 installed-application inventory and vulnerability contracts.
//! No registry, filesystem, clock, HTTP or provider implementation belongs here.

use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeMap};

pub const INSTALLED_APPLICATION_SNAPSHOT_V1: &str = "INSTALLED_APPLICATION_SNAPSHOT_V1";
pub const INSTALLED_APP_VULNERABILITY_V1: &str = "INSTALLED_APP_VULNERABILITY_V1";
pub const IDENTITY_ALIAS_DATA_V1: &str = "IDENTITY_ALIAS_DATA_V1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum InventoryScope {
    Machine,
    CurrentUser,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RegistryView {
    Registry64,
    Registry32,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum InventorySourceKind {
    Registry,
    Msix,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct InventorySource {
    pub kind: InventorySourceKind,
    pub scope: InventoryScope,
    pub view: RegistryView,
    /// Registry subkey or MSIX package full name. Never an uninstall command.
    pub source_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawInstalledApplication {
    pub source: InventorySource,
    pub display_name: Option<String>,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    pub display_icon: Option<String>,
    pub install_date: Option<String>,
    pub windows_installer: Option<bool>,
    pub system_component: Option<bool>,
    pub release_type: Option<String>,
    pub product_code: Option<String>,
    pub package_family_name: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VersionKind {
    SemVer,
    DottedNumeric,
    VendorSpecific,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NormalizedVersion {
    pub raw: Option<String>,
    pub kind: VersionKind,
    pub canonical: Option<String>,
    /// Numeric components are present only when ordering is defined.
    pub numeric: Vec<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMatchState {
    Exact,
    Curated,
    Strong,
    Heuristic,
    Unmapped,
    Conflicting,
}

impl IdentityMatchState {
    pub const fn permits_automatic_cve(self) -> bool {
        matches!(self, Self::Exact | Self::Curated | Self::Strong)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SoftwareIdentity {
    pub state: IdentityMatchState,
    pub cpe: Option<String>,
    pub purl: Option<String>,
    pub reason: String,
    pub alias_dataset: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledApplication {
    pub application_id: String,
    pub name: String,
    pub normalized_name: String,
    pub publisher: Option<String>,
    pub normalized_publisher: Option<String>,
    pub version: NormalizedVersion,
    pub sources: Vec<InventorySource>,
    pub product_code: Option<String>,
    pub package_family_name: Option<String>,
    pub install_location: Option<String>,
    pub display_icon: Option<String>,
    pub display_icon_signature: Option<InstalledApplicationSignature>,
    pub install_date_reported: Option<String>,
    pub system_component: bool,
    pub release_type: Option<String>,
    pub identity: SoftwareIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledApplicationSignature {
    pub cryptographic_status: String,
    pub trust_chain_status: String,
    pub publisher_subject: Option<String>,
    pub offline_cache_only: bool,
    pub limitation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InventoryCoverage {
    pub registry_machine_64: bool,
    pub registry_machine_32: bool,
    pub registry_current_user_64: bool,
    pub registry_current_user_32: bool,
    pub msix_current_user: bool,
    pub other_users: bool,
    pub portable_applications: bool,
    pub filesystem_crawl: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledApplicationSnapshot {
    pub schema: String,
    pub applications: Vec<InstalledApplication>,
    pub coverage: InventoryCoverage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityAlias {
    pub normalized_name: String,
    pub normalized_publisher: Option<String>,
    pub cpe: String,
    pub purl: Option<String>,
}

pub fn normalize_inventory(
    raw: Vec<RawInstalledApplication>,
    aliases: &[IdentityAlias],
    mut coverage: InventoryCoverage,
) -> InstalledApplicationSnapshot {
    coverage.limitations.sort();
    coverage.limitations.dedup();
    let mut groups: BTreeMap<String, InstalledApplication> = BTreeMap::new();
    for item in raw {
        let Some(name) = clean_optional(item.display_name.as_deref(), 512) else {
            continue;
        };
        let normalized_name = normalize_text(&name);
        let publisher = clean_optional(item.publisher.as_deref(), 512);
        let normalized_publisher = publisher.as_deref().map(normalize_publisher);
        let version = normalize_version(item.display_version.as_deref());
        let product_code = clean_optional(item.product_code.as_deref(), 256);
        let package_family_name = clean_optional(item.package_family_name.as_deref(), 512);
        let strong_key = product_code
            .as_deref()
            .filter(|value| looks_like_guid(value))
            .map(|value| format!("product:{}", value.to_ascii_lowercase()))
            .or_else(|| {
                package_family_name
                    .as_deref()
                    .map(|value| format!("msix:{}", value.to_ascii_lowercase()))
            });
        let exact_key = strong_key.unwrap_or_else(|| {
            format!(
                "exact:{}|{}|{}",
                normalized_publisher.as_deref().unwrap_or(""),
                normalized_name,
                version.canonical.as_deref().unwrap_or("")
            )
        });
        if let Some(existing) = groups.get_mut(&exact_key) {
            if !existing.sources.contains(&item.source) {
                existing.sources.push(item.source);
                existing.sources.sort();
            }
            continue;
        }
        let identity = resolve_identity(
            &normalized_name,
            normalized_publisher.as_deref(),
            product_code.as_deref(),
            package_family_name.as_deref(),
            aliases,
        );
        let application_id = stable_id(&exact_key);
        groups.insert(
            exact_key,
            InstalledApplication {
                application_id,
                name,
                normalized_name,
                publisher,
                normalized_publisher,
                version,
                sources: vec![item.source],
                product_code,
                package_family_name,
                install_location: clean_optional(item.install_location.as_deref(), 4096),
                display_icon: clean_optional(item.display_icon.as_deref(), 4096),
                display_icon_signature: None,
                install_date_reported: clean_optional(item.install_date.as_deref(), 64),
                system_component: item.system_component.unwrap_or(false),
                release_type: clean_optional(item.release_type.as_deref(), 128),
                identity,
            },
        );
    }
    let mut applications = groups.into_values().collect::<Vec<_>>();
    applications.sort_by(|left, right| {
        left.normalized_name
            .cmp(&right.normalized_name)
            .then(left.normalized_publisher.cmp(&right.normalized_publisher))
            .then(left.version.canonical.cmp(&right.version.canonical))
            .then(left.application_id.cmp(&right.application_id))
    });
    InstalledApplicationSnapshot {
        schema: INSTALLED_APPLICATION_SNAPSHOT_V1.into(),
        applications,
        coverage,
    }
}

fn resolve_identity(
    name: &str,
    publisher: Option<&str>,
    product_code: Option<&str>,
    package_family: Option<&str>,
    aliases: &[IdentityAlias],
) -> SoftwareIdentity {
    let matches = aliases
        .iter()
        .filter(|alias| {
            alias.normalized_name == name
                && alias
                    .normalized_publisher
                    .as_deref()
                    .is_none_or(|expected| Some(expected) == publisher)
        })
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return SoftwareIdentity {
            state: IdentityMatchState::Conflicting,
            cpe: None,
            purl: None,
            reason: "multiple curated identities matched".into(),
            alias_dataset: IDENTITY_ALIAS_DATA_V1.into(),
        };
    }
    if let Some(alias) = matches.first() {
        let valid_cpe = Cpe23::parse(&alias.cpe).is_ok();
        return SoftwareIdentity {
            state: if valid_cpe {
                IdentityMatchState::Curated
            } else {
                IdentityMatchState::Conflicting
            },
            cpe: valid_cpe.then(|| alias.cpe.clone()),
            purl: alias.purl.clone(),
            reason: if valid_cpe {
                "versioned curated alias matched"
            } else {
                "curated CPE was invalid"
            }
            .into(),
            alias_dataset: IDENTITY_ALIAS_DATA_V1.into(),
        };
    }
    if package_family.is_some() || product_code.is_some_and(looks_like_guid) {
        return SoftwareIdentity {
            state: IdentityMatchState::Strong,
            cpe: None,
            purl: package_family.map(|value| format!("pkg:msix/{value}")),
            reason: "strong local package identifier present; CVE mapping still requires provider identity".into(),
            alias_dataset: IDENTITY_ALIAS_DATA_V1.into(),
        };
    }
    SoftwareIdentity {
        state: if publisher.is_some() {
            IdentityMatchState::Heuristic
        } else {
            IdentityMatchState::Unmapped
        },
        cpe: None,
        purl: None,
        reason: "no exact or curated vulnerability identity".into(),
        alias_dataset: IDENTITY_ALIAS_DATA_V1.into(),
    }
}

pub fn normalize_version(raw: Option<&str>) -> NormalizedVersion {
    let raw = clean_optional(raw, 128);
    let Some(value) = raw.clone() else {
        return NormalizedVersion {
            raw: None,
            kind: VersionKind::Unknown,
            canonical: None,
            numeric: vec![],
        };
    };
    let value = value.as_str();
    let base = value.split_once('+').map_or(value, |(base, _)| base);
    let (numeric_part, suffix) = base
        .split_once('-')
        .map_or((base, None), |(left, right)| (left, Some(right)));
    let components = numeric_part.split('.').collect::<Vec<_>>();
    let valid_numeric = !components.is_empty()
        && components.len() <= 8
        && components
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    if valid_numeric {
        let leading_zero = components
            .iter()
            .any(|part| part.len() > 1 && part.starts_with('0'));
        let parsed = components
            .iter()
            .map(|part| part.parse::<u64>())
            .collect::<Result<Vec<_>, _>>();
        if let Ok(numeric) = parsed {
            let semver_suffix = suffix.is_none_or(|part| {
                !part.is_empty() && part.split('.').all(valid_semver_identifier)
            });
            let kind = if components.len() == 3 && !leading_zero && semver_suffix {
                VersionKind::SemVer
            } else {
                VersionKind::DottedNumeric
            };
            return NormalizedVersion {
                raw,
                kind,
                canonical: Some(value.to_ascii_lowercase()),
                numeric,
            };
        }
    }
    NormalizedVersion {
        raw,
        kind: VersionKind::VendorSpecific,
        canonical: Some(value.to_ascii_lowercase()),
        numeric: vec![],
    }
}

fn valid_semver_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn clean_optional(value: Option<&str>, max: usize) -> Option<String> {
    let value =
        value?.trim_matches(|character: char| character.is_whitespace() || character.is_control());
    (!value.is_empty() && value.chars().count() <= max).then(|| value.to_string())
}

pub fn normalize_text(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

pub fn normalize_publisher(value: &str) -> String {
    let normalized = normalize_text(value).trim_end_matches('.').to_string();
    match normalized.as_str() {
        "microsoft corp" | "microsoft corporation" => "microsoft corporation".into(),
        "the document foundation" => "the document foundation".into(),
        _ => normalized,
    }
}

fn looks_like_guid(value: &str) -> bool {
    let value = value.trim_matches(['{', '}']);
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn stable_id(value: &str) -> String {
    let high = fnv1a(value.as_bytes(), 0xcbf29ce484222325);
    let low = fnv1a(value.as_bytes(), 0x84222325cbf29ce4);
    format!("appv1-{high:016x}{low:016x}")
}

fn fnv1a(bytes: &[u8], seed: u64) -> u64 {
    bytes.iter().fold(seed, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Cpe23 {
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub update: String,
    pub edition: String,
    pub language: String,
    pub sw_edition: String,
    pub target_sw: String,
    pub target_hw: String,
    pub other: String,
}

impl Cpe23 {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if value.len() > 2048 || !value.is_ascii() {
            return Err("invalid CPE length or encoding");
        }
        let fields = split_cpe(value)?;
        if fields.len() != 13 || fields[0] != "cpe" || fields[1] != "2.3" {
            return Err("invalid CPE 2.3 structure");
        }
        if !matches!(fields[2].as_str(), "a" | "h" | "o") {
            return Err("invalid CPE part");
        }
        Ok(Self {
            part: fields[2].clone(),
            vendor: fields[3].clone(),
            product: fields[4].clone(),
            version: fields[5].clone(),
            update: fields[6].clone(),
            edition: fields[7].clone(),
            language: fields[8].clone(),
            sw_edition: fields[9].clone(),
            target_sw: fields[10].clone(),
            target_hw: fields[11].clone(),
            other: fields[12].clone(),
        })
    }
}

fn split_cpe(value: &str) -> Result<Vec<String>, &'static str> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ':' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
    }
    if escaped {
        return Err("trailing CPE escape");
    }
    fields.push(current);
    Ok(fields)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AffectedRange {
    pub start_including: Option<String>,
    pub start_excluding: Option<String>,
    pub end_including: Option<String>,
    pub end_excluding: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AffectedState {
    Affected,
    NotAffected,
    Unknown,
    VersionUnparsable,
    IdentityUncertain,
    DataUnavailable,
}

pub fn evaluate_affected(
    application: &InstalledApplication,
    expected_cpe: &str,
    ranges: &[AffectedRange],
) -> AffectedState {
    if !application.identity.state.permits_automatic_cve() {
        return AffectedState::IdentityUncertain;
    }
    if application.identity.cpe.as_deref() != Some(expected_cpe) {
        return AffectedState::NotAffected;
    }
    if application.version.numeric.is_empty() {
        return AffectedState::VersionUnparsable;
    }
    if ranges.is_empty() {
        return AffectedState::Unknown;
    }
    let mut comparable = false;
    for range in ranges {
        match range_contains(&application.version, range) {
            Some(true) => return AffectedState::Affected,
            Some(false) => comparable = true,
            None => {}
        }
    }
    if comparable {
        AffectedState::NotAffected
    } else {
        AffectedState::Unknown
    }
}

fn range_contains(version: &NormalizedVersion, range: &AffectedRange) -> Option<bool> {
    let mut ok = true;
    for (bound, inclusive, start) in [
        (range.start_including.as_deref(), true, true),
        (range.start_excluding.as_deref(), false, true),
        (range.end_including.as_deref(), true, false),
        (range.end_excluding.as_deref(), false, false),
    ] {
        let Some(bound) = bound else {
            continue;
        };
        let parsed = normalize_version(Some(bound));
        if parsed.numeric.is_empty() {
            return None;
        }
        let ordering = compare_numeric(&version.numeric, &parsed.numeric);
        ok &= if start {
            ordering == Ordering::Greater || (inclusive && ordering == Ordering::Equal)
        } else {
            ordering == Ordering::Less || (inclusive && ordering == Ordering::Equal)
        };
    }
    Some(ok)
}

fn compare_numeric(left: &[u64], right: &[u64]) -> Ordering {
    let length = left.len().max(right.len());
    (0..length)
        .map(|index| {
            (
                *left.get(index).unwrap_or(&0),
                *right.get(index).unwrap_or(&0),
            )
        })
        .find_map(|(left, right)| (left != right).then(|| left.cmp(&right)))
        .unwrap_or(Ordering::Equal)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VulnerabilityRecord {
    pub cve: String,
    pub cpe: String,
    pub ranges: Vec<AffectedRange>,
    pub cvss_score: Option<f64>,
    pub cvss_severity: Option<String>,
    pub fixed_version: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KevRecord {
    pub cve: String,
    pub date_added: String,
    pub due_date: Option<String>,
    pub required_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EpssRecord {
    pub cve: String,
    pub probability: f64,
    pub percentile: f64,
    pub score_date: String,
    pub model_version: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PriorityBand {
    Low,
    Normal,
    High,
    Immediate,
    Review,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstalledAppFinding {
    pub fingerprint_version: String,
    pub fingerprint: String,
    pub application_id: String,
    pub application_name: String,
    pub installed_version: String,
    pub cve: String,
    pub affected: AffectedState,
    pub identity_state: IdentityMatchState,
    pub priority: PriorityBand,
    pub priority_reasons: Vec<String>,
    pub cvss_score: Option<f64>,
    pub cvss_severity: Option<String>,
    pub kev: Option<KevRecord>,
    pub epss: Option<EpssRecord>,
    pub fixed_version: Option<String>,
    pub sources: Vec<String>,
    pub limitations: Vec<String>,
}

pub fn correlate_installed_vulnerabilities(
    snapshot: &InstalledApplicationSnapshot,
    vulnerabilities: &[VulnerabilityRecord],
    kev: &[KevRecord],
    epss: &[EpssRecord],
) -> Vec<InstalledAppFinding> {
    let kev = kev
        .iter()
        .map(|record| (record.cve.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    let epss = epss
        .iter()
        .map(|record| (record.cve.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    let mut findings = BTreeMap::<String, InstalledAppFinding>::new();
    for application in &snapshot.applications {
        for vulnerability in vulnerabilities {
            let affected =
                evaluate_affected(application, &vulnerability.cpe, &vulnerability.ranges);
            if affected != AffectedState::Affected {
                continue;
            }
            let kev_record = kev.get(vulnerability.cve.as_str()).copied().cloned();
            let epss_record = epss.get(vulnerability.cve.as_str()).copied().cloned();
            let (priority, priority_reasons) = priority(
                vulnerability.cvss_score,
                kev_record.is_some(),
                epss_record.as_ref(),
            );
            let fingerprint_key = format!(
                "{}|{}|{}|{}",
                application.application_id,
                application
                    .version
                    .canonical
                    .as_deref()
                    .unwrap_or("unknown"),
                vulnerability.cve.to_ascii_uppercase(),
                "current_user_or_machine"
            );
            let fingerprint = format!(
                "iav1-{:016x}{:016x}",
                fnv1a(fingerprint_key.as_bytes(), 0xcbf29ce484222325),
                fnv1a(fingerprint_key.as_bytes(), 0x84222325cbf29ce4)
            );
            let candidate = findings.entry(fingerprint.clone()).or_insert_with(|| InstalledAppFinding {
                fingerprint_version: INSTALLED_APP_VULNERABILITY_V1.into(),
                fingerprint,
                application_id: application.application_id.clone(),
                application_name: application.name.clone(),
                installed_version: application.version.raw.clone().unwrap_or_else(|| "unknown".into()),
                cve: vulnerability.cve.to_ascii_uppercase(), affected,
                identity_state: application.identity.state, priority, priority_reasons,
                cvss_score: vulnerability.cvss_score, cvss_severity: vulnerability.cvss_severity.clone(),
                kev: kev_record, epss: epss_record, fixed_version: vulnerability.fixed_version.clone(),
                sources: vec![vulnerability.source.clone()],
                limitations: vec!["A documented fixed version does not prove an update is available on this host.".into()],
            });
            if !candidate.sources.contains(&vulnerability.source) {
                candidate.sources.push(vulnerability.source.clone());
                candidate.sources.sort();
            }
        }
    }
    findings.into_values().collect()
}

fn priority(
    cvss: Option<f64>,
    kev: bool,
    epss: Option<&EpssRecord>,
) -> (PriorityBand, Vec<String>) {
    let mut reasons = Vec::new();
    let band = if kev {
        reasons.push(
            "CISA KEV lists this validated CVE; this does not prove host exploitation.".into(),
        );
        PriorityBand::Immediate
    } else if epss.is_some_and(|score| score.probability >= 0.5 || score.percentile >= 0.95) {
        reasons.push(
            "EPSS indicates elevated exploitation likelihood and is used only for priority.".into(),
        );
        PriorityBand::High
    } else if cvss.is_some_and(|score| score >= 7.0) {
        reasons.push("CVSS base severity is high or critical.".into());
        PriorityBand::High
    } else if cvss.is_some() {
        reasons.push("Validated affected range with moderate or lower base severity.".into());
        PriorityBand::Normal
    } else {
        reasons.push("Affected range validated, but severity data is unavailable.".into());
        PriorityBand::Review
    };
    (band, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coverage() -> InventoryCoverage {
        InventoryCoverage {
            registry_machine_64: true,
            registry_machine_32: true,
            registry_current_user_64: true,
            registry_current_user_32: true,
            msix_current_user: true,
            other_users: false,
            portable_applications: false,
            filesystem_crawl: false,
            limitations: vec!["portable applications are outside coverage".into()],
        }
    }
    fn raw(source: &str, version: Option<&str>) -> RawInstalledApplication {
        RawInstalledApplication {
            source: InventorySource {
                kind: InventorySourceKind::Registry,
                scope: InventoryScope::Machine,
                view: RegistryView::Registry64,
                source_id: source.into(),
            },
            display_name: Some("Fixture App".into()),
            display_version: version.map(str::to_string),
            publisher: Some("Fixture Corp.".into()),
            install_location: None,
            display_icon: None,
            install_date: Some("20260902".into()),
            windows_installer: Some(true),
            system_component: Some(false),
            release_type: None,
            product_code: Some("{12345678-1234-1234-1234-1234567890AB}".into()),
            package_family_name: None,
        }
    }
    fn aliases() -> Vec<IdentityAlias> {
        vec![IdentityAlias {
            normalized_name: "fixture app".into(),
            normalized_publisher: Some("fixture corp".into()),
            cpe: "cpe:2.3:a:fixture:app:*:*:*:*:*:*:*:*".into(),
            purl: Some("pkg:generic/fixture-app".into()),
        }]
    }

    #[test]
    fn deterministic_normalization_deduplicates_only_strong_identity() {
        let mut second = raw("second", Some("1.2.3"));
        second.source.view = RegistryView::Registry32;
        let first = normalize_inventory(
            vec![second.clone(), raw("first", Some("1.2.3"))],
            &aliases(),
            coverage(),
        );
        let reversed = normalize_inventory(
            vec![raw("first", Some("1.2.3")), second],
            &aliases(),
            coverage(),
        );
        assert_eq!(first, reversed);
        assert_eq!(first.applications.len(), 1);
        assert_eq!(first.applications[0].sources.len(), 2);
        assert_eq!(
            first.applications[0].identity.state,
            IdentityMatchState::Curated
        );
    }

    #[test]
    fn versions_are_never_invented_and_vendor_versions_are_not_ordered() {
        assert_eq!(normalize_version(Some("1.2.3")).kind, VersionKind::SemVer);
        assert_eq!(
            normalize_version(Some("01.2.3.4")).kind,
            VersionKind::DottedNumeric
        );
        assert_eq!(
            normalize_version(Some("Release Blue")).kind,
            VersionKind::VendorSpecific
        );
        assert_eq!(normalize_version(None).kind, VersionKind::Unknown);
    }

    #[test]
    fn cpe_parser_honors_escaping_and_rejects_naive_shapes() {
        assert!(Cpe23::parse("cpe:2.3:a:fixture:app:*:*:*:*:*:*:*:*").is_ok());
        assert!(Cpe23::parse("cpe:2.3:a:fixture:app\\:suite:*:*:*:*:*:*:*:*").is_ok());
        assert!(Cpe23::parse("fixture:app").is_err());
        assert!(Cpe23::parse("cpe:2.3:x:fixture:app:*:*:*:*:*:*:*:*").is_err());
    }

    #[test]
    fn inclusive_exclusive_boundaries_are_exact_not_lexicographic() {
        let snapshot =
            normalize_inventory(vec![raw("one", Some("1.10.0"))], &aliases(), coverage());
        let app = &snapshot.applications[0];
        let affected = AffectedRange {
            start_including: Some("1.2.0".into()),
            end_excluding: Some("1.10.1".into()),
            ..Default::default()
        };
        assert_eq!(
            evaluate_affected(app, "cpe:2.3:a:fixture:app:*:*:*:*:*:*:*:*", &[affected]),
            AffectedState::Affected
        );
        let excluded = AffectedRange {
            end_excluding: Some("1.10.0".into()),
            ..Default::default()
        };
        assert_eq!(
            evaluate_affected(app, "cpe:2.3:a:fixture:app:*:*:*:*:*:*:*:*", &[excluded]),
            AffectedState::NotAffected
        );
    }

    #[test]
    fn uncertain_identity_and_unparsable_version_never_create_findings() {
        let unknown = normalize_inventory(
            vec![RawInstalledApplication {
                publisher: None,
                product_code: None,
                ..raw("x", Some("1.0.0"))
            }],
            &[],
            coverage(),
        );
        let vendor = normalize_inventory(vec![raw("x", Some("Blue"))], &aliases(), coverage());
        let vulnerability = VulnerabilityRecord {
            cve: "CVE-2099-0001".into(),
            cpe: "cpe:2.3:a:fixture:app:*:*:*:*:*:*:*:*".into(),
            ranges: vec![AffectedRange {
                end_excluding: Some("2.0.0".into()),
                ..Default::default()
            }],
            cvss_score: Some(9.8),
            cvss_severity: Some("CRITICAL".into()),
            fixed_version: Some("2.0.0".into()),
            source: "NVD".into(),
        };
        assert!(
            correlate_installed_vulnerabilities(
                &unknown,
                std::slice::from_ref(&vulnerability),
                &[],
                &[]
            )
            .is_empty()
        );
        assert!(
            correlate_installed_vulnerabilities(&vendor, &[vulnerability], &[], &[]).is_empty()
        );
    }

    #[test]
    fn kev_and_epss_enrich_one_deduplicated_finding() {
        let snapshot = normalize_inventory(vec![raw("x", Some("1.0.0"))], &aliases(), coverage());
        let vulnerability = VulnerabilityRecord {
            cve: "CVE-2099-0001".into(),
            cpe: "cpe:2.3:a:fixture:app:*:*:*:*:*:*:*:*".into(),
            ranges: vec![AffectedRange {
                end_excluding: Some("2.0.0".into()),
                ..Default::default()
            }],
            cvss_score: Some(5.0),
            cvss_severity: Some("MEDIUM".into()),
            fixed_version: Some("2.0.0".into()),
            source: "NVD".into(),
        };
        let kev = KevRecord {
            cve: "CVE-2099-0001".into(),
            date_added: "2099-01-01".into(),
            due_date: None,
            required_action: None,
        };
        let epss = EpssRecord {
            cve: "CVE-2099-0001".into(),
            probability: 0.9,
            percentile: 0.99,
            score_date: "2099-01-01".into(),
            model_version: Some("fixture".into()),
        };
        let findings = correlate_installed_vulnerabilities(
            &snapshot,
            &[
                vulnerability.clone(),
                VulnerabilityRecord {
                    source: "SECONDARY".into(),
                    ..vulnerability
                },
            ],
            &[kev],
            &[epss],
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].priority, PriorityBand::Immediate);
        assert_eq!(findings[0].sources.len(), 2);
    }
}
