//! Pure Level 4 passive web-security contracts and conservative correlation.

use crate::{Confidence, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const WEB_ANALYSIS_SCHEMA: &str = "PASSIVE_WEB_ANALYSIS_V1";
pub const WEB_TRANSPORT_FINDING_V1: &str = "WEB_TRANSPORT_FINDING_V1";
pub const WEB_TLS_FINDING_V1: &str = "WEB_TLS_FINDING_V1";
pub const WEB_HEADER_FINDING_V1: &str = "WEB_HEADER_FINDING_V1";
pub const WEB_COOKIE_FINDING_V1: &str = "WEB_COOKIE_FINDING_V1";
pub const WEB_REPUTATION_FINDING_V1: &str = "WEB_REPUTATION_FINDING_V1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryPolicy {
    Send,
    Strip,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SanitizedUrlTarget {
    pub display_url: String,
    pub scheme: String,
    pub canonical_host: String,
    pub path: String,
    pub port: u16,
    pub query_present: bool,
    pub query_parameter_names: Vec<String>,
    pub fragment_present: bool,
    pub idna_ascii: bool,
    pub public_ip_literal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsObservation {
    pub canonical_host: String,
    pub public_addresses: Vec<String>,
    pub selected_address: Option<String>,
    pub address_families: Vec<String>,
    pub resolved_at_utc: String,
    pub state: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsCertificateState {
    Valid,
    ExpiringSoon,
    Expired,
    NotYetValid,
    Unknown,
    NotApplicable,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsObservation {
    pub attempted: bool,
    pub certificate_state: TlsCertificateState,
    pub validation_enabled: bool,
    pub hostname_validation_enabled: bool,
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub san_count: Option<u32>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedirectObservation {
    pub hop: u8,
    pub status: u16,
    pub source_scheme: String,
    pub source_host: String,
    pub destination_scheme: String,
    pub destination_host: String,
    pub destination_display_url: String,
    pub same_origin: bool,
    pub followed: bool,
    pub outcome: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebObservationClass {
    SecurityIssue,
    Hardening,
    Review,
    Informational,
    Coverage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeaderObservation {
    pub name: String,
    pub state: String,
    pub value_sanitized: Option<String>,
    pub interpretation: String,
    pub class: WebObservationClass,
    pub guidance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SameSiteState {
    Strict,
    Lax,
    None,
    Missing,
    Malformed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CookieObservation {
    pub safe_identifier: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSiteState,
    pub domain_present: bool,
    pub path: Option<String>,
    pub max_age_or_expires_present: bool,
    pub partitioned: bool,
    pub prefix: Option<String>,
    pub observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReputationObservation {
    pub provider: String,
    pub state: String,
    pub exact_match: Option<bool>,
    pub dataset_version: Option<String>,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebCoverage {
    pub dns: String,
    pub tls: String,
    pub http: String,
    pub redirects: String,
    pub headers: String,
    pub cookies: String,
    pub reputation: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebFinding {
    pub fingerprint_version: String,
    pub fingerprint: String,
    pub family: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub class: WebObservationClass,
    pub evidence: Vec<String>,
    pub guidance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PassiveWebAnalysis {
    pub schema: String,
    pub scan_id: String,
    pub state: String,
    pub query_policy: QueryPolicy,
    pub target: SanitizedUrlTarget,
    pub final_target: Option<SanitizedUrlTarget>,
    pub dns: Vec<DnsObservation>,
    pub tls: Vec<TlsObservation>,
    pub redirects: Vec<RedirectObservation>,
    pub final_http_status: Option<u16>,
    pub headers: Vec<HeaderObservation>,
    pub cookies: Vec<CookieObservation>,
    pub reputation: ReputationObservation,
    pub findings: Vec<WebFinding>,
    pub risk: Severity,
    pub confidence: Confidence,
    pub coverage: WebCoverage,
}

fn v4_in(ip: Ipv4Addr, base: [u8; 4], prefix: u8) -> bool {
    let value = u32::from(ip);
    let base = u32::from(Ipv4Addr::from(base));
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    value & mask == base & mask
}
fn v6_in(ip: Ipv6Addr, base: [u16; 8], prefix: u8) -> bool {
    let value = u128::from(ip);
    let base = u128::from(Ipv6Addr::from(base));
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    value & mask == base & mask
}

pub fn is_public_internet_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ![
            ([0, 0, 0, 0], 8),
            ([10, 0, 0, 0], 8),
            ([100, 64, 0, 0], 10),
            ([127, 0, 0, 0], 8),
            ([169, 254, 0, 0], 16),
            ([172, 16, 0, 0], 12),
            ([192, 0, 0, 0], 24),
            ([192, 0, 2, 0], 24),
            ([192, 88, 99, 0], 24),
            ([192, 168, 0, 0], 16),
            ([198, 18, 0, 0], 15),
            ([198, 51, 100, 0], 24),
            ([203, 0, 113, 0], 24),
            ([224, 0, 0, 0], 4),
            ([240, 0, 0, 0], 4),
        ]
        .into_iter()
        .any(|(base, prefix)| v4_in(ip, base, prefix)),
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4() {
                return is_public_internet_address(IpAddr::V4(v4));
            }
            ![
                ([0, 0, 0, 0, 0, 0, 0, 0], 128),
                ([0, 0, 0, 0, 0, 0, 0, 1], 128),
                ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
                ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
                ([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
                ([0x0100, 0, 0, 0, 0, 0, 0, 0], 64),
                ([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32),
                ([0x2001, 0x0002, 0, 0, 0, 0, 0, 0], 48),
            ]
            .into_iter()
            .any(|(base, prefix)| v6_in(ip, base, prefix))
        }
    }
}

pub fn validate_resolved_addresses(
    addresses: &[IpAddr],
    maximum: usize,
) -> Result<Vec<IpAddr>, &'static str> {
    if addresses.is_empty() {
        return Err("DNS_EMPTY");
    }
    if addresses.len() > maximum {
        return Err("DNS_ANSWER_LIMIT");
    }
    let mut normalized = addresses
        .iter()
        .map(|ip| match ip {
            IpAddr::V6(v6) => v6.to_ipv4().map(IpAddr::V4).unwrap_or(*ip),
            _ => *ip,
        })
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    if normalized.iter().any(|ip| !is_public_internet_address(*ip)) {
        return Err("TARGET_RESOLUTION_REJECTED");
    }
    Ok(normalized)
}

pub fn parse_hsts(values: &[String], https: bool) -> HeaderObservation {
    if values.is_empty() {
        return HeaderObservation {
            name: "strict-transport-security".into(),
            state: "missing".into(),
            value_sanitized: None,
            interpretation:
                "HSTS was not observed; this is a hardening gap, not proof of exploitability."
                    .into(),
            class: WebObservationClass::Hardening,
            guidance: "Consider an appropriate HSTS policy after compatibility review.".into(),
        };
    }
    if !https {
        return HeaderObservation {
            name: "strict-transport-security".into(),
            state: "non_effective_http".into(),
            value_sanitized: None,
            interpretation: "HSTS received over HTTP is not effective transport protection.".into(),
            class: WebObservationClass::Informational,
            guidance: "Deliver HSTS only over validated HTTPS.".into(),
        };
    }
    if values.len() != 1 {
        return HeaderObservation {
            name: "strict-transport-security".into(),
            state: "multiple_headers".into(),
            value_sanitized: None,
            interpretation: "Multiple HSTS fields require review.".into(),
            class: WebObservationClass::Review,
            guidance: "Emit one unambiguous HSTS policy.".into(),
        };
    }
    let mut max_age = None;
    let mut include = false;
    let mut preload = false;
    let mut malformed = false;
    let mut seen = BTreeSet::new();
    for part in values[0]
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let lower = part.to_ascii_lowercase();
        let key = lower.split('=').next().unwrap_or("");
        if !seen.insert(key.to_string()) {
            malformed = true;
        }
        match key {
            "max-age" => {
                max_age = lower
                    .split_once('=')
                    .and_then(|(_, v)| v.parse::<u64>().ok())
            }
            "includesubdomains" => include = true,
            "preload" => preload = true,
            _ => malformed = true,
        }
    }
    if max_age.is_none() {
        malformed = true
    }
    let state = if malformed {
        "malformed"
    } else if max_age == Some(0) {
        "disabled"
    } else {
        "present"
    };
    HeaderObservation {
        name: "strict-transport-security".into(),
        state: state.into(),
        value_sanitized: Some(format!(
            "max-age={}; includeSubDomains={include}; preload={preload}",
            max_age.map_or("invalid".into(), |v| v.to_string())
        )),
        interpretation: "HSTS syntax was evaluated only for this HTTPS response.".into(),
        class: if malformed || max_age == Some(0) {
            WebObservationClass::Hardening
        } else {
            WebObservationClass::Informational
        },
        guidance: "Review max-age and subdomain scope against deployment requirements.".into(),
    }
}

pub fn parse_csp(enforced: &[String], report_only: &[String]) -> Vec<HeaderObservation> {
    let mut out = Vec::new();
    if enforced.is_empty() {
        out.push(HeaderObservation {
            name: "content-security-policy".into(),
            state: if report_only.is_empty() {
                "missing"
            } else {
                "report_only_only"
            }
            .into(),
            value_sanitized: None,
            interpretation: "No enforced CSP was observed; this does not confirm XSS.".into(),
            class: WebObservationClass::Hardening,
            guidance: "Consider a tested enforced CSP.".into(),
        });
    }
    for (index, policy) in enforced.iter().take(8).enumerate() {
        if policy.len() > 8192 {
            out.push(HeaderObservation {
                name: "content-security-policy".into(),
                state: "oversized".into(),
                value_sanitized: None,
                interpretation: "CSP exceeded the analysis bound.".into(),
                class: WebObservationClass::Review,
                guidance: "Reduce and review the policy.".into(),
            });
            continue;
        }
        let directives = policy
            .split(';')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        let lower = policy.to_ascii_lowercase();
        let nonce_or_hash = lower.contains("'nonce-")
            || lower.contains("'sha256-")
            || lower.contains("'sha384-")
            || lower.contains("'sha512-");
        let strict_dynamic = lower.contains("'strict-dynamic'");
        let unsafe_inline = lower.contains("'unsafe-inline'");
        let state = if unsafe_inline && (nonce_or_hash || strict_dynamic) {
            "policy_review"
        } else if unsafe_inline
            || lower.contains("'unsafe-eval'")
            || directives
                .iter()
                .any(|d| d.split_whitespace().skip(1).any(|v| v == "*"))
        {
            "permissive"
        } else {
            "present"
        };
        out.push(HeaderObservation {
            name: format!("content-security-policy[{index}]"),
            state: state.into(),
            value_sanitized: Some(format!("{} directives", directives.len())),
            interpretation:
                "Policy directives were parsed independently; no exploitability claim is made."
                    .into(),
            class: if state == "present" {
                WebObservationClass::Informational
            } else {
                WebObservationClass::Review
            },
            guidance:
                "Review script, object, base, frame and form restrictions in application context."
                    .into(),
        });
    }
    if !report_only.is_empty() {
        out.push(HeaderObservation {
            name: "content-security-policy-report-only".into(),
            state: "observed".into(),
            value_sanitized: Some(format!("{} policy field(s)", report_only.len().min(8))),
            interpretation: "Report-only CSP does not enforce restrictions.".into(),
            class: WebObservationClass::Informational,
            guidance: "Validate reports before promotion to an enforced policy.".into(),
        });
    }
    out
}

pub fn parse_set_cookie(value: &str) -> CookieObservation {
    const MAX: usize = 4096;
    let bounded = &value[..value.floor_char_boundary(value.len().min(MAX))];
    let mut parts = bounded.split(';');
    let first = parts.next().unwrap_or("");
    let name = first.split_once('=').map_or("", |(n, _)| n).trim();
    let safe_identifier = if name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        name.to_string()
    } else {
        "[redacted-cookie-name]".into()
    };
    let mut secure = false;
    let mut http_only = false;
    let mut same_site = SameSiteState::Missing;
    let mut domain = false;
    let mut path = None;
    let mut expiry = false;
    let mut partitioned = false;
    let mut observations = Vec::new();
    let mut seen = BTreeSet::new();
    for attr in parts.take(32) {
        let (key, val) = attr
            .trim()
            .split_once('=')
            .map_or((attr.trim(), None), |(k, v)| (k.trim(), Some(v.trim())));
        let lower = key.to_ascii_lowercase();
        if !seen.insert(lower.clone()) {
            observations.push(format!("duplicate attribute: {lower}"));
        }
        match lower.as_str() {
            "secure" => secure = true,
            "httponly" => http_only = true,
            "samesite" => {
                same_site = match val.unwrap_or("").to_ascii_lowercase().as_str() {
                    "strict" => SameSiteState::Strict,
                    "lax" => SameSiteState::Lax,
                    "none" => SameSiteState::None,
                    _ => SameSiteState::Malformed,
                }
            }
            "domain" => domain = true,
            "path" => path = val.filter(|v| v.len() <= 256).map(|v| v.to_string()),
            "max-age" | "expires" => expiry = true,
            "partitioned" => partitioned = true,
            _ => {}
        }
    }
    if same_site == SameSiteState::None && !secure {
        observations.push("SameSite=None without Secure".into());
    }
    if !secure {
        observations.push("Secure not observed".into());
    }
    if !http_only {
        observations.push("HttpOnly not observed; cookie sensitivity is unknown".into());
    }
    let prefix = if name.starts_with("__Host-") {
        if !secure || domain || path.as_deref() != Some("/") {
            observations.push("__Host- prefix requirements are inconsistent".into());
        }
        Some("__Host-".into())
    } else if name.starts_with("__Secure-") {
        if !secure {
            observations.push("__Secure- prefix requires Secure".into());
        }
        Some("__Secure-".into())
    } else {
        None
    };
    CookieObservation {
        safe_identifier,
        secure,
        http_only,
        same_site,
        domain_present: domain,
        path,
        max_age_or_expires_present: expiry,
        partitioned,
        prefix,
        observations,
    }
}

pub fn web_fingerprint(
    version: &str,
    family: &str,
    target: &SanitizedUrlTarget,
    key: &str,
) -> String {
    // Stable FNV-1a expansion avoids a hashing dependency in the pure core; this is an identity,
    // not a cryptographic boundary. Query values never enter this input.
    let input = format!(
        "{version}|{family}|{}|{}|{}|{key}",
        target.scheme, target.canonical_host, target.path
    );
    let mut h = 0xcbf29ce484222325_u64;
    for b in input.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3)
    }
    format!("webv1-{h:016x}{:016x}", h.rotate_left(17))
}

pub fn correlate_web(
    target: &SanitizedUrlTarget,
    redirects: &[RedirectObservation],
    headers: &[HeaderObservation],
    cookies: &[CookieObservation],
    reputation: &ReputationObservation,
) -> Vec<WebFinding> {
    let mut findings = BTreeMap::<String, WebFinding>::new();
    let mut add = |version: &str,
                   family: &str,
                   key: &str,
                   title: &str,
                   severity: Severity,
                   class: WebObservationClass,
                   evidence: Vec<String>,
                   guidance: &str| {
        let fingerprint = web_fingerprint(version, family, target, key);
        findings.entry(fingerprint.clone()).or_insert(WebFinding {
            fingerprint_version: version.into(),
            fingerprint,
            family: family.into(),
            title: title.into(),
            severity,
            confidence: Confidence::High,
            class,
            evidence,
            guidance: guidance.into(),
        });
    };
    if target.scheme == "http"
        && redirects
            .last()
            .is_none_or(|hop| hop.destination_scheme != "https")
    {
        add(
            WEB_TRANSPORT_FINDING_V1,
            "TRANSPORT_SECURITY",
            "cleartext-final",
            "Final destination uses cleartext HTTP",
            Severity::Medium,
            WebObservationClass::SecurityIssue,
            vec!["HTTP transport is not encrypted.".into()],
            "Migrate the final destination to validated HTTPS.",
        );
    }
    if let Some(hop) = redirects
        .iter()
        .find(|hop| hop.outcome == "transport_downgrade")
    {
        add(
            WEB_TRANSPORT_FINDING_V1,
            "REDIRECT_SECURITY",
            "https-downgrade",
            "HTTPS redirect attempted a downgrade to HTTP",
            Severity::High,
            WebObservationClass::SecurityIssue,
            vec![format!("redirect hop {} was not followed", hop.hop)],
            "Remove the HTTPS-to-HTTP redirect.",
        );
    }
    for header in headers.iter().filter(|h| {
        matches!(
            h.class,
            WebObservationClass::Hardening
                | WebObservationClass::Review
                | WebObservationClass::SecurityIssue
        )
    }) {
        let severity = if header.class == WebObservationClass::SecurityIssue {
            Severity::Medium
        } else {
            Severity::Low
        };
        add(
            WEB_HEADER_FINDING_V1,
            "HTTP_SECURITY_HEADER",
            &format!("{}:{}", header.name, header.state),
            &format!("{}: {}", header.name, header.state),
            severity,
            header.class,
            vec![header.interpretation.clone()],
            &header.guidance,
        );
    }
    for cookie in cookies.iter().filter(|c| !c.observations.is_empty()) {
        add(
            WEB_COOKIE_FINDING_V1,
            "COOKIE_SECURITY",
            &cookie.safe_identifier,
            "Cookie attributes require review",
            Severity::Low,
            WebObservationClass::Review,
            cookie.observations.clone(),
            "Review cookie purpose and apply compatible Secure, HttpOnly, SameSite and prefix attributes.",
        );
    }
    if reputation.exact_match == Some(true) {
        add(
            WEB_REPUTATION_FINDING_V1,
            "URL_REPUTATION",
            "exact-match",
            "Exact canonical URL matched local reputation data",
            Severity::High,
            WebObservationClass::SecurityIssue,
            vec![reputation.explanation.clone()],
            "Investigate the exact URL and corroborate with independent evidence; do not submit automatically.",
        );
    }
    findings.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ssrf_matrix_blocks_special_ranges_and_allows_public() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "192.0.2.1",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public_internet_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_internet_address(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn mixed_dns_is_rejected() {
        assert_eq!(
            validate_resolved_addresses(
                &["1.1.1.1".parse().unwrap(), "127.0.0.1".parse().unwrap()],
                16
            ),
            Err("TARGET_RESOLUTION_REJECTED")
        );
        assert!(validate_resolved_addresses(&["1.1.1.1".parse().unwrap()], 16).is_ok());
        assert_eq!(validate_resolved_addresses(&[], 16), Err("DNS_EMPTY"));
        assert_eq!(
            validate_resolved_addresses(&vec!["1.1.1.1".parse().unwrap(); 17], 16),
            Err("DNS_ANSWER_LIMIT")
        );
    }
    #[test]
    fn cookie_value_is_never_retained() {
        let secret = "EDY_FAKE_COOKIE_SECRET_LEVEL4";
        let parsed = parse_set_cookie(&format!(
            "session={secret}; Secure; HttpOnly; SameSite=None; Path=/"
        ));
        let json = serde_json::to_string(&parsed).unwrap();
        assert!(!json.contains(secret));
        assert_eq!(parsed.same_site, SameSiteState::None);
        for (header, same_site, secure) in [
            ("a=x; SameSite=Strict; Secure", SameSiteState::Strict, true),
            ("a=x; SameSite=Lax", SameSiteState::Lax, false),
            ("a=x; SameSite=None; Secure", SameSiteState::None, true),
            ("a=x; SameSite=None", SameSiteState::None, false),
            ("a=x", SameSiteState::Missing, false),
            ("a=x; SameSite=bad", SameSiteState::Malformed, false),
        ] {
            let parsed = parse_set_cookie(header);
            assert_eq!(parsed.same_site, same_site);
            assert_eq!(parsed.secure, secure);
            assert!(!serde_json::to_string(&parsed).unwrap().contains("=x"));
        }
        assert!(
            parse_set_cookie("__Host-id=x; Secure; Path=/; HttpOnly")
                .observations
                .is_empty()
        );
        assert!(!parse_set_cookie("__Secure-id=x").observations.is_empty());
    }
    #[test]
    fn hsts_and_csp_are_bounded_and_nuanced() {
        assert_eq!(parse_hsts(&[], true).state, "missing");
        assert_eq!(
            parse_hsts(&["max-age=31536000; includeSubDomains".into()], true).state,
            "present"
        );
        assert_eq!(
            parse_hsts(&["max-age=1".into()], false).state,
            "non_effective_http"
        );
        let csp = parse_csp(
            &["script-src 'unsafe-inline' 'nonce-abc' 'strict-dynamic'; object-src 'none'".into()],
            &[],
        );
        assert_eq!(csp[0].state, "policy_review");
        assert_eq!(parse_hsts(&["max-age=0".into()], true).state, "disabled");
        assert_eq!(parse_hsts(&["max-age=abc".into()], true).state, "malformed");
        assert_eq!(
            parse_hsts(&["max-age=1".into(), "max-age=2".into()], true).state,
            "multiple_headers"
        );
        assert_eq!(parse_csp(&[], &[])[0].state, "missing");
        assert_eq!(
            parse_csp(&[], &["default-src 'self'".into()])[0].state,
            "report_only_only"
        );
        assert_eq!(
            parse_hsts(
                &["max-age=31536000; includeSubDomains; preload".into()],
                true
            )
            .state,
            "present"
        );
        assert_eq!(
            parse_hsts(&["max-age=1; max-age=2".into()], true).state,
            "malformed"
        );
        for policy in ["script-src 'unsafe-eval'", "script-src *"] {
            assert_eq!(parse_csp(&[policy.into()], &[])[0].state, "permissive");
        }
        assert_eq!(
            parse_csp(
                &["default-src 'self'; object-src 'none'; frame-ancestors 'none'".into()],
                &[],
            )[0]
            .state,
            "present"
        );
        assert_eq!(parse_csp(&["a".repeat(8193)], &[])[0].state, "oversized");
        assert_eq!(
            parse_csp(
                &["default-src 'self'".into(), "object-src 'none'".into()],
                &[]
            )
            .len(),
            2
        );
    }

    #[test]
    fn tls_result_model_preserves_failure_states_without_disabling_validation() {
        for state in [
            TlsCertificateState::Valid,
            TlsCertificateState::Expired,
            TlsCertificateState::NotYetValid,
            TlsCertificateState::Failed,
            TlsCertificateState::Unknown,
        ] {
            let observation = TlsObservation {
                attempted: true,
                certificate_state: state,
                validation_enabled: true,
                hostname_validation_enabled: true,
                protocol: None,
                cipher: None,
                subject: None,
                issuer: None,
                not_before: None,
                not_after: None,
                fingerprint_sha256: None,
                san_count: None,
                error: None,
            };
            assert!(observation.validation_enabled);
            assert!(observation.hostname_validation_enabled);
        }
    }
    #[test]
    fn fingerprints_ignore_query_values() {
        let target = SanitizedUrlTarget {
            display_url: "https://example.com/a?token=[REDACTED]".into(),
            scheme: "https".into(),
            canonical_host: "example.com".into(),
            path: "/a".into(),
            port: 443,
            query_present: true,
            query_parameter_names: vec!["token".into()],
            fragment_present: false,
            idna_ascii: false,
            public_ip_literal: false,
        };
        assert_eq!(
            web_fingerprint(WEB_HEADER_FINDING_V1, "h", &target, "csp"),
            web_fingerprint(WEB_HEADER_FINDING_V1, "h", &target, "csp")
        );
        assert!(!web_fingerprint(WEB_HEADER_FINDING_V1, "h", &target, "csp").contains("token"));
    }
}
