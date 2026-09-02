//! Level 3 read-only Windows inventory plus bounded public vulnerability-data adapters.

use edy_core::{
    AffectedRange, EpssRecord, InventoryCoverage, InventoryScope, InventorySource,
    InventorySourceKind, KevRecord, RawInstalledApplication, RegistryView, VulnerabilityRecord,
};
use flate2::read::GzDecoder;
use reqwest::{StatusCode, Url, blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub const NVD_FIXED_SMOKE_CVE: &str = "CVE-2021-44228";
pub const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const EPSS_DAILY_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

const REGISTRY_MAX_ITEMS: usize = 16_384;
const REGISTRY_MAX_VALUE_BYTES: u32 = 64 * 1024;
const NVD_MAX_BYTES: usize = 4 * 1024 * 1024;
const CISA_MAX_BYTES: usize = 32 * 1024 * 1024;
const EPSS_GZIP_MAX_BYTES: usize = 64 * 1024 * 1024;
const EPSS_DECOMPRESSED_MAX_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug)]
pub enum ProviderError {
    Unavailable(&'static str),
    InvalidData(&'static str),
    Policy(&'static str),
    Io(std::io::Error),
    Json(serde_json::Error),
    Http(reqwest::Error),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable(message) | Self::InvalidData(message) | Self::Policy(message) => {
                message
            }
            Self::Io(_) => "provider cache I/O failed",
            Self::Json(_) => "public provider response was invalid",
            Self::Http(_) => "public provider request failed",
        })
    }
}
impl std::error::Error for ProviderError {}
impl From<std::io::Error> for ProviderError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for ProviderError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<reqwest::Error> for ProviderError {
    fn from(value: reqwest::Error) -> Self {
        Self::Http(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InventoryCollection {
    pub raw: Vec<RawInstalledApplication>,
    pub coverage: InventoryCoverage,
}

pub fn collect_installed_applications() -> Result<InventoryCollection, ProviderError> {
    #[cfg(windows)]
    {
        windows_inventory::collect()
    }
    #[cfg(not(windows))]
    {
        Err(ProviderError::Unavailable(
            "Windows inventory is unavailable on this platform",
        ))
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_inventory {
    use super::*;
    use std::ptr;
    use windows::{Management::Deployment::PackageManager, core::HSTRING};
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS},
        System::Registry::{
            HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY,
            KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ, REG_SZ, RegCloseKey, RegEnumKeyExW,
            RegOpenKeyExW, RegQueryValueExW,
        },
    };

    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    pub(super) fn collect() -> Result<InventoryCollection, ProviderError> {
        let mut raw = Vec::new();
        let mut limitations = vec![
            "Only standard uninstall registry keys and current-user MSIX packages are inventoried."
                .into(),
            "Other users, portable applications and filesystem crawling are outside coverage."
                .into(),
            "InstallDate is publisher-reported metadata, not an observed installation timestamp."
                .into(),
        ];
        let roots = [
            (
                HKEY_LOCAL_MACHINE,
                InventoryScope::Machine,
                RegistryView::Registry64,
                KEY_WOW64_64KEY,
            ),
            (
                HKEY_LOCAL_MACHINE,
                InventoryScope::Machine,
                RegistryView::Registry32,
                KEY_WOW64_32KEY,
            ),
            (
                HKEY_CURRENT_USER,
                InventoryScope::CurrentUser,
                RegistryView::Registry64,
                KEY_WOW64_64KEY,
            ),
            (
                HKEY_CURRENT_USER,
                InventoryScope::CurrentUser,
                RegistryView::Registry32,
                KEY_WOW64_32KEY,
            ),
        ];
        for (root, scope, view, flag) in roots {
            raw.extend(read_uninstall_root(root, scope, view, flag)?);
        }
        let msix_current_user = match read_current_user_msix() {
            Ok(packages) => {
                raw.extend(packages);
                true
            }
            Err(_) => {
                limitations.push("Current-user MSIX enumeration was unavailable.".into());
                false
            }
        };
        Ok(InventoryCollection {
            raw,
            coverage: InventoryCoverage {
                registry_machine_64: true,
                registry_machine_32: true,
                registry_current_user_64: true,
                registry_current_user_32: true,
                msix_current_user,
                other_users: false,
                portable_applications: false,
                filesystem_crawl: false,
                limitations,
            },
        })
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn open(root: HKEY, path: &str, flags: u32) -> Result<Key, ProviderError> {
        let mut handle = ptr::null_mut();
        let status =
            unsafe { RegOpenKeyExW(root, wide(path).as_ptr(), 0, KEY_READ | flags, &mut handle) };
        if status != ERROR_SUCCESS {
            return Err(ProviderError::Unavailable(
                "read-only uninstall registry view unavailable",
            ));
        }
        Ok(Key(handle))
    }

    fn read_uninstall_root(
        root: HKEY,
        scope: InventoryScope,
        view: RegistryView,
        flags: u32,
    ) -> Result<Vec<RawInstalledApplication>, ProviderError> {
        let parent = open(root, UNINSTALL, flags)?;
        let mut output = Vec::new();
        for index in 0..REGISTRY_MAX_ITEMS as u32 {
            let mut name = vec![0u16; 512];
            let mut length = name.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    parent.0,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status == ERROR_MORE_DATA {
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(ProviderError::Unavailable(
                    "read-only uninstall registry enumeration failed",
                ));
            }
            let subkey = String::from_utf16_lossy(&name[..length as usize]);
            let child_path = format!(r"{UNINSTALL}\{subkey}");
            let child = match open(root, &child_path, flags) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let display_name = query_string(&child, "DisplayName")?;
            if display_name
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            {
                continue;
            }
            output.push(RawInstalledApplication {
                source: InventorySource {
                    kind: InventorySourceKind::Registry,
                    scope,
                    view,
                    source_id: subkey.clone(),
                },
                display_name,
                display_version: query_string(&child, "DisplayVersion")?,
                publisher: query_string(&child, "Publisher")?,
                install_location: query_string(&child, "InstallLocation")?,
                display_icon: query_string(&child, "DisplayIcon")?,
                install_date: query_string(&child, "InstallDate")?,
                windows_installer: query_dword(&child, "WindowsInstaller")?.map(|value| value != 0),
                system_component: query_dword(&child, "SystemComponent")?.map(|value| value != 0),
                release_type: query_string(&child, "ReleaseType")?,
                product_code: looks_like_product_code(&subkey).then_some(subkey),
                package_family_name: None,
            });
        }
        Ok(output)
    }

    fn query_raw(key: &Key, name: &str) -> Result<Option<(u32, Vec<u8>)>, ProviderError> {
        let name = wide(name);
        let mut data_type = 0u32;
        let mut bytes = 0u32;
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                ptr::null(),
                &mut data_type,
                ptr::null_mut(),
                &mut bytes,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(ProviderError::Unavailable("registry value query failed"));
        }
        if bytes == 0 || bytes > REGISTRY_MAX_VALUE_BYTES {
            return Ok(None);
        }
        let mut data = vec![0u8; bytes as usize];
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                ptr::null(),
                &mut data_type,
                data.as_mut_ptr(),
                &mut bytes,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(ProviderError::Unavailable("registry value read failed"));
        }
        data.truncate(bytes as usize);
        Ok(Some((data_type, data)))
    }

    fn query_string(key: &Key, name: &str) -> Result<Option<String>, ProviderError> {
        let Some((data_type, data)) = query_raw(key, name)? else {
            return Ok(None);
        };
        if !matches!(data_type, REG_SZ | REG_EXPAND_SZ) || data.len() % 2 != 0 {
            return Ok(None);
        }
        let words =
            unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u16>(), data.len() / 2) };
        let end = words
            .iter()
            .position(|word| *word == 0)
            .unwrap_or(words.len());
        Ok(String::from_utf16(&words[..end]).ok())
    }
    fn query_dword(key: &Key, name: &str) -> Result<Option<u32>, ProviderError> {
        let Some((data_type, data)) = query_raw(key, name)? else {
            return Ok(None);
        };
        if data_type != REG_DWORD || data.len() != 4 {
            return Ok(None);
        }
        Ok(Some(u32::from_le_bytes(data.try_into().map_err(|_| {
            ProviderError::InvalidData("invalid registry DWORD")
        })?)))
    }
    fn looks_like_product_code(value: &str) -> bool {
        let value = value.trim_matches(['{', '}']);
        let bytes = value.as_bytes();
        bytes.len() == 36
            && [8, 13, 18, 23].into_iter().all(|i| bytes[i] == b'-')
            && bytes
                .iter()
                .enumerate()
                .all(|(i, b)| [8, 13, 18, 23].contains(&i) || b.is_ascii_hexdigit())
    }

    fn read_current_user_msix() -> Result<Vec<RawInstalledApplication>, ProviderError> {
        let manager = PackageManager::new()
            .map_err(|_| ProviderError::Unavailable("MSIX PackageManager unavailable"))?;
        let packages = manager
            .FindPackagesByUserSecurityId(&HSTRING::new())
            .map_err(|_| ProviderError::Unavailable("current-user MSIX enumeration unavailable"))?;
        let mut output = Vec::new();
        for package in packages.into_iter().take(REGISTRY_MAX_ITEMS) {
            let id = package
                .Id()
                .map_err(|_| ProviderError::InvalidData("MSIX identity unavailable"))?;
            let version = id
                .Version()
                .map_err(|_| ProviderError::InvalidData("MSIX version unavailable"))?;
            let full_name = id
                .FullName()
                .map_err(|_| ProviderError::InvalidData("MSIX full name unavailable"))?
                .to_string();
            let family = id
                .FamilyName()
                .map_err(|_| ProviderError::InvalidData("MSIX family unavailable"))?
                .to_string();
            let id_name = id
                .Name()
                .map_err(|_| ProviderError::InvalidData("MSIX name unavailable"))?
                .to_string();
            let display = package
                .DisplayName()
                .map(|value| value.to_string())
                .ok()
                .filter(|value| !value.trim().is_empty())
                .or(Some(id_name));
            let publisher = package
                .PublisherDisplayName()
                .map(|value| value.to_string())
                .ok()
                .filter(|value| !value.trim().is_empty());
            let system = package.IsFramework().unwrap_or(false)
                || package.IsResourcePackage().unwrap_or(false);
            output.push(RawInstalledApplication {
                source: InventorySource {
                    kind: InventorySourceKind::Msix,
                    scope: InventoryScope::CurrentUser,
                    view: RegistryView::NotApplicable,
                    source_id: full_name,
                },
                display_name: display,
                display_version: Some(format!(
                    "{}.{}.{}.{}",
                    version.Major, version.Minor, version.Build, version.Revision
                )),
                publisher,
                install_location: None,
                display_icon: None,
                install_date: None,
                windows_installer: Some(false),
                system_component: Some(system),
                release_type: Some("msix".into()),
                product_code: None,
                package_family_name: Some(family),
            });
        }
        Ok(output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CacheMetadata {
    pub source_url: String,
    pub fetched_at_utc: String,
    pub dataset_version: Option<String>,
    pub sha256: String,
    pub bytes: u64,
    pub freshness: String,
}

pub struct FixedPublicDataClient {
    client: Client,
}
impl FixedPublicDataClient {
    pub fn new() -> Result<Self, ProviderError> {
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent("EDY-VERDICT/0.1 public-vulnerability-data")
            .build()?;
        Ok(Self { client })
    }
    pub fn nvd_fixed_smoke(&self, api_key: Option<&str>) -> Result<Vec<u8>, ProviderError> {
        let url = format!("{NVD_API_BASE}?cveId={NVD_FIXED_SMOKE_CVE}");
        self.fetch(&url, &["services.nvd.nist.gov"], NVD_MAX_BYTES, api_key)
    }
    pub fn cisa_kev(&self) -> Result<Vec<u8>, ProviderError> {
        self.fetch(CISA_KEV_URL, &["www.cisa.gov"], CISA_MAX_BYTES, None)
    }
    pub fn epss_daily(&self) -> Result<Vec<u8>, ProviderError> {
        self.fetch(
            EPSS_DAILY_URL,
            &["epss.empiricalsecurity.com"],
            EPSS_GZIP_MAX_BYTES,
            None,
        )
    }
    fn fetch(
        &self,
        url: &str,
        allowed_hosts: &[&str],
        max_bytes: usize,
        api_key: Option<&str>,
    ) -> Result<Vec<u8>, ProviderError> {
        let mut current =
            Url::parse(url).map_err(|_| ProviderError::Policy("invalid fixed provider URL"))?;
        for _ in 0..=2 {
            validate_url(&current, allowed_hosts)?;
            let mut request = self
                .client
                .get(current.clone())
                .header("Accept", "application/json, text/csv, application/gzip");
            if let Some(key) = api_key.filter(|key| !key.trim().is_empty()) {
                request = request.header("apiKey", key);
            }
            let response = request.send()?;
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(ProviderError::Policy(
                        "provider redirect lacked a valid location",
                    ))?;
                current = current
                    .join(location)
                    .map_err(|_| ProviderError::Policy("provider redirect was invalid"))?;
                continue;
            }
            if response.status() != StatusCode::OK {
                return Err(ProviderError::Unavailable(
                    "public provider returned a non-success status",
                ));
            }
            if response
                .content_length()
                .is_some_and(|length| length > max_bytes as u64)
            {
                return Err(ProviderError::Policy(
                    "public provider response exceeded the size limit",
                ));
            }
            let mut output = Vec::new();
            response
                .take(max_bytes as u64 + 1)
                .read_to_end(&mut output)?;
            if output.len() > max_bytes {
                return Err(ProviderError::Policy(
                    "public provider response exceeded the size limit",
                ));
            }
            return Ok(output);
        }
        Err(ProviderError::Policy(
            "public provider redirect limit exceeded",
        ))
    }
}

fn validate_url(url: &Url, allowed_hosts: &[&str]) -> Result<(), ProviderError> {
    if url.scheme() != "https"
        || url.port().is_some()
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderError::Policy(
            "provider URL policy refused the request",
        ));
    }
    let host = url
        .host_str()
        .ok_or(ProviderError::Policy("provider URL has no host"))?;
    if !allowed_hosts.contains(&host) {
        return Err(ProviderError::Policy(
            "provider redirect origin was not approved",
        ));
    }
    Ok(())
}

/// Resolves only one explicit DisplayIcon PE candidate. It never searches directories or executes
/// the value. Quoted paths, an optional numeric icon index and bounded `%VAR%` expansion are
/// accepted; commands, relative/UNC/device paths and non-PE extensions are refused.
pub fn resolve_display_icon_candidate(raw: &str) -> Option<PathBuf> {
    if raw.is_empty() || raw.len() > 4096 || raw.chars().any(char::is_control) {
        return None;
    }
    let trimmed = raw.trim();
    let candidate = if let Some(rest) = trimmed.strip_prefix('"') {
        let end = rest.find('"')?;
        let path = &rest[..end];
        let suffix = rest[end + 1..].trim();
        if !suffix.is_empty() && !valid_icon_index(suffix) {
            return None;
        }
        path.to_string()
    } else if let Some((path, index)) = trimmed.rsplit_once(',') {
        if valid_icon_index(index.trim()) {
            path.trim().to_string()
        } else {
            trimmed.to_string()
        }
    } else {
        trimmed.to_string()
    };
    let expanded = expand_percent_variables(&candidate)?;
    let lower = expanded.to_ascii_lowercase();
    if lower.starts_with(r"\\") || lower.starts_with(r"\\?\") || lower.starts_with(r"\\.\") {
        return None;
    }
    let path = PathBuf::from(expanded);
    if !path.is_absolute()
        || !matches!(
            path.extension()
                .and_then(|value| value.to_str())
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("exe" | "dll")
        )
    {
        return None;
    }
    Some(path)
}
fn valid_icon_index(value: &str) -> bool {
    value
        .strip_prefix(',')
        .unwrap_or(value)
        .trim()
        .parse::<i32>()
        .is_ok()
}
fn expand_percent_variables(value: &str) -> Option<String> {
    let mut output = String::new();
    let mut rest = value;
    let mut expansions = 0;
    while let Some(start) = rest.find('%') {
        output.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        let end = tail.find('%')?;
        let name = &tail[..end];
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'(' | b')'))
            || expansions >= 8
        {
            return None;
        }
        let replacement = std::env::var(name).ok()?;
        if replacement.len() > 2048 {
            return None;
        }
        output.push_str(&replacement);
        rest = &tail[end + 1..];
        expansions += 1;
    }
    output.push_str(rest);
    (output.len() <= 4096).then_some(output)
}

pub fn promote_validated_cache(
    cache: &Path,
    bytes: &[u8],
    metadata: &CacheMetadata,
) -> Result<(), ProviderError> {
    if !cache.is_absolute()
        || cache.parent().is_none_or(|parent| !parent.is_dir())
        || bytes.is_empty()
    {
        return Err(ProviderError::Policy("cache path or payload was refused"));
    }
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != metadata.sha256 || metadata.bytes != bytes.len() as u64 {
        return Err(ProviderError::InvalidData(
            "cache metadata integrity mismatch",
        ));
    }
    let next = with_suffix(cache, "next");
    let previous = with_suffix(cache, "previous");
    let metadata_path = with_suffix(cache, "metadata.json");
    let metadata_next = with_suffix(cache, "metadata.next");
    let metadata_previous = with_suffix(cache, "metadata.previous.json");
    let metadata_bytes = serde_json::to_vec_pretty(metadata)?;
    write_new(&next, bytes)?;
    if let Err(error) = write_new(&metadata_next, &metadata_bytes) {
        let _ = fs::remove_file(&next);
        return Err(error);
    }
    if cache.exists() {
        if previous.exists() {
            fs::remove_file(&previous)?;
        }
        fs::rename(cache, &previous)?;
    }
    if metadata_path.exists() {
        if metadata_previous.exists() {
            fs::remove_file(&metadata_previous)?;
        }
        fs::rename(&metadata_path, &metadata_previous)?;
    }
    if let Err(error) = fs::rename(&next, cache) {
        if previous.exists() {
            let _ = fs::rename(&previous, cache);
        }
        if metadata_previous.exists() {
            let _ = fs::rename(&metadata_previous, &metadata_path);
        }
        let _ = fs::remove_file(&metadata_next);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&metadata_next, &metadata_path) {
        let _ = fs::remove_file(cache);
        if previous.exists() {
            let _ = fs::rename(&previous, cache);
        }
        if metadata_previous.exists() {
            let _ = fs::rename(&metadata_previous, &metadata_path);
        }
        return Err(error.into());
    }
    Ok(())
}
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.display(), suffix))
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), ProviderError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn read_validated_cache_metadata(
    cache: &Path,
    expected_source_url: &str,
) -> Result<CacheMetadata, ProviderError> {
    if !cache.is_absolute() || cache.parent().is_none_or(|parent| !parent.is_dir()) {
        return Err(ProviderError::Policy("cache path was refused"));
    }
    validate_cache_pair(
        cache,
        &with_suffix(cache, "metadata.json"),
        expected_source_url,
    )
}

pub fn read_validated_cache_metadata_with_fallback(
    cache: &Path,
    expected_source_url: &str,
) -> Result<(CacheMetadata, bool), ProviderError> {
    match read_validated_cache_metadata(cache, expected_source_url) {
        Ok(metadata) => Ok((metadata, false)),
        Err(current_error) => validate_cache_pair(
            &with_suffix(cache, "previous"),
            &with_suffix(cache, "metadata.previous.json"),
            expected_source_url,
        )
        .map(|metadata| (metadata, true))
        .map_err(|_| current_error),
    }
}

fn validate_cache_pair(
    cache: &Path,
    metadata_path: &Path,
    expected_source_url: &str,
) -> Result<CacheMetadata, ProviderError> {
    if !cache.is_absolute() || cache.parent().is_none_or(|parent| !parent.is_dir()) {
        return Err(ProviderError::Policy("cache path was refused"));
    }
    for path in [cache, metadata_path] {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ProviderError::Policy("cache link or non-file was refused"));
        }
    }
    let metadata_bytes = fs::read(metadata_path)?;
    if metadata_bytes.len() > 16 * 1024 {
        return Err(ProviderError::Policy(
            "cache metadata exceeded the size limit",
        ));
    }
    let metadata: CacheMetadata = serde_json::from_slice(&metadata_bytes)?;
    if metadata.source_url != expected_source_url {
        return Err(ProviderError::InvalidData("cache source URL mismatch"));
    }
    let payload = fs::read(cache)?;
    if payload.is_empty()
        || payload.len() as u64 != metadata.bytes
        || sha256(&payload) != metadata.sha256
    {
        return Err(ProviderError::InvalidData(
            "cache payload integrity mismatch",
        ));
    }
    Ok(metadata)
}

pub fn cache_is_stale(metadata: &CacheMetadata, maximum_age_hours: i64) -> bool {
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    if maximum_age_hours <= 0 {
        return true;
    }
    let Ok(fetched) = OffsetDateTime::parse(&metadata.fetched_at_utc, &Rfc3339) else {
        return true;
    };
    let age = OffsetDateTime::now_utc() - fetched;
    age.is_negative() || age.whole_hours() > maximum_age_hours
}

#[derive(Deserialize)]
struct NvdRoot {
    vulnerabilities: Vec<NvdItem>,
}
#[derive(Deserialize)]
struct NvdItem {
    cve: NvdCve,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCve {
    id: String,
    configurations: Option<Vec<NvdConfiguration>>,
    metrics: Option<NvdMetrics>,
}
#[derive(Deserialize)]
struct NvdConfiguration {
    nodes: Vec<NvdNode>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdNode {
    cpe_match: Vec<NvdCpeMatch>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCpeMatch {
    vulnerable: bool,
    criteria: String,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetrics {
    cvss_metric_v40: Option<Vec<NvdMetric>>,
    cvss_metric_v31: Option<Vec<NvdMetric>>,
    cvss_metric_v30: Option<Vec<NvdMetric>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetric {
    cvss_data: NvdCvss,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvss {
    base_score: f64,
    base_severity: Option<String>,
}

pub fn parse_nvd(bytes: &[u8]) -> Result<Vec<VulnerabilityRecord>, ProviderError> {
    if bytes.len() > NVD_MAX_BYTES {
        return Err(ProviderError::Policy(
            "NVD response exceeded the parser limit",
        ));
    }
    let root: NvdRoot = serde_json::from_slice(bytes)?;
    let mut output = Vec::new();
    for item in root.vulnerabilities {
        if !valid_cve(&item.cve.id) {
            continue;
        }
        let score = item
            .cve
            .metrics
            .as_ref()
            .and_then(|metrics| {
                metrics
                    .cvss_metric_v40
                    .as_ref()
                    .or(metrics.cvss_metric_v31.as_ref())
                    .or(metrics.cvss_metric_v30.as_ref())
            })
            .and_then(|metrics| metrics.first());
        if let Some(configurations) = item.cve.configurations {
            for matched in configurations
                .into_iter()
                .flat_map(|configuration| configuration.nodes)
                .flat_map(|node| node.cpe_match)
                .filter(|matched| matched.vulnerable)
            {
                if edy_core::Cpe23::parse(&matched.criteria).is_err() {
                    continue;
                }
                output.push(VulnerabilityRecord {
                    cve: item.cve.id.clone(),
                    cpe: matched.criteria,
                    ranges: vec![AffectedRange {
                        start_including: matched.version_start_including,
                        start_excluding: matched.version_start_excluding,
                        end_including: matched.version_end_including,
                        end_excluding: matched.version_end_excluding,
                    }],
                    cvss_score: score.map(|value| value.cvss_data.base_score),
                    cvss_severity: score.and_then(|value| value.cvss_data.base_severity.clone()),
                    fixed_version: None,
                    source: "NVD_API_2_0".into(),
                });
            }
        }
    }
    output.sort_by(|a, b| a.cve.cmp(&b.cve).then(a.cpe.cmp(&b.cpe)));
    Ok(output)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevRoot {
    catalog_version: String,
    vulnerabilities: Vec<KevItem>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevItem {
    #[serde(rename = "cveID")]
    cve_id: String,
    date_added: String,
    due_date: Option<String>,
    required_action: Option<String>,
}
pub fn parse_cisa_kev(bytes: &[u8]) -> Result<(String, Vec<KevRecord>), ProviderError> {
    if bytes.len() > CISA_MAX_BYTES {
        return Err(ProviderError::Policy(
            "CISA KEV response exceeded the parser limit",
        ));
    }
    let root: KevRoot = serde_json::from_slice(bytes)?;
    if root.catalog_version.trim().is_empty() {
        return Err(ProviderError::InvalidData(
            "CISA KEV catalog version missing",
        ));
    }
    let mut records = root
        .vulnerabilities
        .into_iter()
        .filter(|item| valid_cve(&item.cve_id))
        .map(|item| KevRecord {
            cve: item.cve_id,
            date_added: item.date_added,
            due_date: item.due_date,
            required_action: item.required_action,
        })
        .collect::<Vec<_>>();
    records.sort_by(|a, b| a.cve.cmp(&b.cve));
    records.dedup_by(|a, b| a.cve == b.cve);
    Ok((root.catalog_version, records))
}

pub fn parse_epss_gzip(bytes: &[u8]) -> Result<Vec<EpssRecord>, ProviderError> {
    if bytes.len() > EPSS_GZIP_MAX_BYTES {
        return Err(ProviderError::Policy("EPSS gzip exceeded the parser limit"));
    }
    let decoder = GzDecoder::new(bytes);
    let mut text = String::new();
    decoder
        .take(EPSS_DECOMPRESSED_MAX_BYTES as u64 + 1)
        .read_to_string(&mut text)?;
    if text.len() > EPSS_DECOMPRESSED_MAX_BYTES {
        return Err(ProviderError::Policy(
            "EPSS decompressed data exceeded the parser limit",
        ));
    }
    parse_epss_csv(&text)
}
pub fn parse_epss_csv(text: &str) -> Result<Vec<EpssRecord>, ProviderError> {
    let mut model = None;
    let mut date = None;
    let mut records = Vec::new();
    for line in text.lines() {
        if let Some(comment) = line.strip_prefix('#') {
            for part in comment.split(',') {
                let part = part.trim();
                if let Some(value) = part.strip_prefix("model_version:") {
                    model = Some(value.trim().into())
                }
                if let Some(value) = part.strip_prefix("score_date:") {
                    date = Some(value.trim().into())
                }
            }
            continue;
        }
        if line.trim().is_empty() || line.starts_with("cve,") {
            continue;
        }
        let columns = line.split(',').map(str::trim).collect::<Vec<_>>();
        if columns.len() != 3 || !valid_cve(columns[0]) {
            return Err(ProviderError::InvalidData("EPSS CSV row was invalid"));
        }
        let probability = columns[1]
            .parse::<f64>()
            .map_err(|_| ProviderError::InvalidData("EPSS probability was invalid"))?;
        let percentile = columns[2]
            .parse::<f64>()
            .map_err(|_| ProviderError::InvalidData("EPSS percentile was invalid"))?;
        if !(0.0..=1.0).contains(&probability) || !(0.0..=1.0).contains(&percentile) {
            return Err(ProviderError::InvalidData("EPSS score was outside 0..1"));
        }
        records.push(EpssRecord {
            cve: columns[0].into(),
            probability,
            percentile,
            score_date: date.clone().unwrap_or_else(|| "unknown".into()),
            model_version: model.clone(),
        });
    }
    if records.is_empty() {
        return Err(ProviderError::InvalidData("EPSS dataset was empty"));
    }
    records.sort_by(|a, b| a.cve.cmp(&b.cve));
    records.dedup_by(|a, b| a.cve == b.cve);
    Ok(records)
}
fn valid_cve(value: &str) -> bool {
    let mut parts = value.split('-');
    matches!(parts.next(), Some("CVE"))
        && parts
            .next()
            .is_some_and(|year| year.len() == 4 && year.bytes().all(|b| b.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|id| id.len() >= 4 && id.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_none()
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nvd_parser_preserves_exact_ranges() {
        let json=br#"{"vulnerabilities":[{"cve":{"id":"CVE-2099-0001","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:fixture:app:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0.0","versionEndExcluding":"2.0.0"}]}]}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}}]}"#;
        let parsed = parse_nvd(json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ranges[0].end_excluding.as_deref(), Some("2.0.0"));
    }
    #[test]
    fn kev_and_epss_parsers_are_bounded_and_validated() {
        let kev=br#"{"catalogVersion":"2026.09.02","vulnerabilities":[{"cveID":"CVE-2099-0001","dateAdded":"2099-01-01","dueDate":"2099-01-02","requiredAction":"Review"}]}"#;
        assert_eq!(parse_cisa_kev(kev).unwrap().1.len(), 1);
        let epss = "#model_version:v2099.1,score_date:2099-01-01\ncve,epss,percentile\nCVE-2099-0001,0.9,0.99\n";
        let parsed = parse_epss_csv(epss).unwrap();
        assert_eq!(parsed[0].probability, 0.9);
        assert_eq!(parsed[0].model_version.as_deref(), Some("v2099.1"));
        assert!(parse_epss_csv("cve,epss,percentile\nCVE-2099-0001,2,0.5").is_err());
    }
    #[test]
    fn fixed_url_policy_rejects_http_credentials_ports_and_foreign_hosts() {
        for value in [
            "http://www.cisa.gov/feed",
            "https://user@www.cisa.gov/feed",
            "https://www.cisa.gov:444/feed",
            "https://evil.invalid/feed",
        ] {
            assert!(validate_url(&Url::parse(value).unwrap(), &["www.cisa.gov"]).is_err());
        }
    }
    #[test]
    fn current_platform_inventory_is_read_only_and_has_explicit_coverage() {
        #[cfg(windows)]
        {
            let result = collect_installed_applications().unwrap();
            assert!(!result.raw.is_empty());
            assert!(!result.coverage.other_users);
            assert!(!result.coverage.filesystem_crawl);
            println!(
                "READ_ONLY_HOST_INVENTORY count={} registry64={} registry32={} current_user64={} current_user32={} msix_current_user={} raw_names_emitted=false",
                result.raw.len(),
                result.coverage.registry_machine_64,
                result.coverage.registry_machine_32,
                result.coverage.registry_current_user_64,
                result.coverage.registry_current_user_32,
                result.coverage.msix_current_user
            );
        }
    }
    #[test]
    fn cache_status_revalidates_source_size_and_hash_and_classifies_bad_time_stale() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("edy-level3-cache-test-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let cache = root.join("nvd.json");
        let bytes = b"validated fixture";
        let metadata = CacheMetadata {
            source_url: NVD_API_BASE.into(),
            fetched_at_utc: "invalid".into(),
            dataset_version: Some("fixture".into()),
            sha256: sha256(bytes),
            bytes: bytes.len() as u64,
            freshness: "fresh".into(),
        };
        promote_validated_cache(&cache, bytes, &metadata).unwrap();
        let loaded = read_validated_cache_metadata(&cache, NVD_API_BASE).unwrap();
        assert!(cache_is_stale(&loaded, 24));
        assert!(read_validated_cache_metadata(&cache, CISA_KEV_URL).is_err());
        let replacement = b"validated replacement fixture";
        let replacement_metadata = CacheMetadata {
            sha256: sha256(replacement),
            bytes: replacement.len() as u64,
            ..metadata
        };
        promote_validated_cache(&cache, replacement, &replacement_metadata).unwrap();
        fs::write(&cache, b"tampered fixture").unwrap();
        assert!(read_validated_cache_metadata(&cache, NVD_API_BASE).is_err());
        let (fallback, used_previous) =
            read_validated_cache_metadata_with_fallback(&cache, NVD_API_BASE).unwrap();
        assert!(used_previous);
        assert_eq!(fallback.sha256, sha256(bytes));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn display_icon_parser_accepts_one_pe_and_refuses_commands_or_searches() {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        assert_eq!(
            resolve_display_icon_candidate(&format!(
                r#""{drive}\Windows\System32\shell32.dll",-1"#
            )),
            Some(PathBuf::from(format!(
                r"{drive}\Windows\System32\shell32.dll"
            )))
        );
        assert!(resolve_display_icon_candidate("relative.exe,0").is_none());
        assert!(resolve_display_icon_candidate(r"\\server\share\icon.exe,0").is_none());
        assert!(resolve_display_icon_candidate(r"C:\Windows\System32\cmd.exe /c whoami").is_none());
        assert!(resolve_display_icon_candidate(r"C:\Windows\System32\icon.png,0").is_none());
        assert!(resolve_display_icon_candidate(r#""C:\Windows\x.exe" & calc.exe"#).is_none());
    }
    #[test]
    #[ignore = "explicit network smoke against fixed public endpoints"]
    fn live_public_feeds_smoke_uses_no_host_inventory_or_credentials() {
        let client = FixedPublicDataClient::new().unwrap();
        let nvd = client.nvd_fixed_smoke(None).unwrap();
        let nvd_records = parse_nvd(&nvd).unwrap();
        assert!(!nvd_records.is_empty());
        assert!(
            nvd_records
                .iter()
                .all(|record| record.cve == NVD_FIXED_SMOKE_CVE)
        );
        let kev = client.cisa_kev().unwrap();
        let (kev_version, kev_records) = parse_cisa_kev(&kev).unwrap();
        assert!(!kev_records.is_empty());
        let epss = client.epss_daily().unwrap();
        let epss_records = parse_epss_gzip(&epss).unwrap();
        assert!(!epss_records.is_empty());
        println!(
            "NVD_FIXED_QUERY count={} sha256={}",
            nvd_records.len(),
            sha256(&nvd)
        );
        println!(
            "CISA_KEV version={} count={} sha256={}",
            kev_version,
            kev_records.len(),
            sha256(&kev)
        );
        println!(
            "EPSS_DAILY count={} sha256={}",
            epss_records.len(),
            sha256(&epss)
        );
    }
}
