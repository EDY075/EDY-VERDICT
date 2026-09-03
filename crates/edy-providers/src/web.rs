//! Level 4 backend-only URL parsing, SSRF-safe resolution and passive HTTP transport.

use edy_core::{
    Confidence, DnsObservation, HeaderObservation, PassiveWebAnalysis, QueryPolicy,
    RedirectObservation, ReputationObservation, SanitizedUrlTarget, Severity, TlsCertificateState,
    TlsObservation, WEB_ANALYSIS_SCHEMA, WEB_TLS_FINDING_V1, WebCoverage, WebFinding,
    WebObservationClass, correlate_web, parse_csp, parse_hsts, parse_set_cookie,
    validate_resolved_addresses, web_fingerprint,
};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT_ENCODING, LOCATION, SET_COOKIE, USER_AGENT};
use reqwest::{Url, redirect::Policy};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::time::Duration;

pub const MAX_URL_BYTES: usize = 2048;
pub const MAX_DNS_ANSWERS: usize = 16;
pub const MAX_REDIRECTS: usize = 5;
pub const MAX_TOTAL_REQUESTS: usize = 6;
pub const MAX_STORED_HEADERS: usize = 64;
pub const MAX_HEADER_VALUE_BYTES: usize = 4096;
pub const MAX_STORED_HEADER_BYTES: usize = 32768;
pub const MAX_COOKIES: usize = 32;
pub const MAX_BODY_INSPECTION_BYTES: usize = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebProviderError {
    code: &'static str,
}
impl WebProviderError {
    pub const fn new(code: &'static str) -> Self {
        Self { code }
    }
    pub const fn code(&self) -> &'static str {
        self.code
    }
}
impl std::fmt::Display for WebProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for WebProviderError {}

#[derive(Clone)]
pub struct PreparedUrlTarget {
    url: Url,
    sanitized: SanitizedUrlTarget,
}
impl PreparedUrlTarget {
    pub fn sanitized(&self) -> &SanitizedUrlTarget {
        &self.sanitized
    }
    pub fn with_query_policy(mut self, policy: QueryPolicy) -> Self {
        if policy == QueryPolicy::Strip {
            self.url.set_query(None);
            self.sanitized.query_present = false;
            self.sanitized.query_parameter_names.clear();
            self.sanitized.display_url = display_url(&self.url, &[]);
        }
        self
    }
    fn network_url(&self) -> &Url {
        &self.url
    }
}

fn display_url(url: &Url, names: &[String]) -> String {
    let host = url.host_str().unwrap_or("invalid");
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.into()
    };
    let mut out = format!("{}://{}{}", url.scheme(), authority, url.path());
    if !names.is_empty() {
        out.push('?');
        out.push_str(
            &names
                .iter()
                .map(|name| format!("{name}=[REDACTED]"))
                .collect::<Vec<_>>()
                .join("&"),
        );
    }
    out
}

pub fn prepare_url(input: &str) -> Result<PreparedUrlTarget, WebProviderError> {
    let lower_input = input.to_ascii_lowercase();
    if input.is_empty()
        || input.len() > MAX_URL_BYTES
        || input
            .bytes()
            .any(|b| b == 0 || b == b'\r' || b == b'\n' || b == b'\t' || b == b' ')
        || input.contains('\\')
        || ["%00", "%0a", "%0d", "%5c"]
            .iter()
            .any(|token| lower_input.contains(token))
    {
        return Err(WebProviderError::new("URL_INPUT_REJECTED"));
    }
    let explicit = input.find("://").is_some_and(|index| index > 0);
    if !explicit {
        return Err(WebProviderError::new("URL_SCHEME_REQUIRED"));
    }
    let fragment_present = input.contains('#');
    let mut url = Url::parse(input).map_err(|_| WebProviderError::new("URL_PARSE_REJECTED"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(WebProviderError::new("URL_SCHEME_REJECTED"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(WebProviderError::new("URL_USERINFO_REJECTED"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| WebProviderError::new("URL_HOST_REJECTED"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() || host.eq_ignore_ascii_case("localhost") || host.contains('%') {
        return Err(WebProviderError::new("URL_HOST_REJECTED"));
    }
    let ip_literal = host.parse::<IpAddr>().ok();
    if ip_literal.is_none() && !host.contains('.') {
        return Err(WebProviderError::new("URL_SINGLE_LABEL_REJECTED"));
    }
    if let Some(ip) = ip_literal {
        validate_resolved_addresses(&[ip], 1)
            .map_err(|_| WebProviderError::new("URL_IP_LITERAL_REJECTED"))?;
    }
    let expected = if url.scheme() == "https" { 443 } else { 80 };
    if url.port().is_some_and(|port| port != expected) {
        return Err(WebProviderError::new("URL_PORT_REJECTED"));
    }
    url.set_host(Some(&host))
        .map_err(|_| WebProviderError::new("URL_HOST_REJECTED"))?;
    url.set_fragment(None);
    let mut names = Vec::new();
    if url.query().is_some() {
        for (name, _) in url.query_pairs() {
            if names.len() >= 32 {
                return Err(WebProviderError::new("URL_QUERY_LIMIT"));
            }
            let name = name.to_string();
            if name.is_empty() || name.len() > 128 {
                return Err(WebProviderError::new("URL_QUERY_REJECTED"));
            }
            names.push(name)
        }
        names.sort();
        names.dedup();
    }
    let sanitized = SanitizedUrlTarget {
        display_url: display_url(&url, &names),
        scheme: url.scheme().into(),
        canonical_host: host,
        path: if url.path().is_empty() {
            "/".into()
        } else {
            url.path().into()
        },
        port: expected,
        query_present: url.query().is_some(),
        query_parameter_names: names,
        fragment_present,
        idna_ascii: url
            .host_str()
            .is_some_and(|h| h.split('.').any(|label| label.starts_with("xn--"))),
        public_ip_literal: ip_literal.is_some(),
    };
    Ok(PreparedUrlTarget { url, sanitized })
}

pub trait DnsResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, WebProviderError>;
}
pub struct SystemDnsResolver;
impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, WebProviderError> {
        let host = host.to_string();
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = (host.as_str(), port)
                .to_socket_addrs()
                .map(|items| items.map(|item| item.ip()).collect::<Vec<_>>());
            let _ = tx.send(result);
        });
        let addresses = rx
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| WebProviderError::new("DNS_TIMEOUT"))?
            .map_err(|_| WebProviderError::new("DNS_FAILED"))?;
        validate_resolved_addresses(&addresses, MAX_DNS_ANSWERS).map_err(WebProviderError::new)
    }
}

pub struct TransportRequest<'a> {
    target: &'a PreparedUrlTarget,
    selected: IpAddr,
}
impl<'a> TransportRequest<'a> {
    pub fn target(&self) -> &PreparedUrlTarget {
        self.target
    }
    pub const fn selected(&self) -> IpAddr {
        self.selected
    }
}
pub struct TransportResponse {
    status: u16,
    headers: Vec<(String, String)>,
}
impl TransportResponse {
    pub fn new(status: u16, headers: Vec<(String, String)>) -> Result<Self, WebProviderError> {
        if !(100..=599).contains(&status) || headers.len() > 256 {
            return Err(WebProviderError::new("HTTP_RESPONSE_REJECTED"));
        }
        Ok(Self { status, headers })
    }
    pub const fn status(&self) -> u16 {
        self.status
    }
}
pub trait HttpTransport: Send + Sync {
    fn get(
        &self,
        request: &TransportRequest<'_>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<TransportResponse, WebProviderError>;
}

pub struct ProductionHttpTransport;
impl HttpTransport for ProductionHttpTransport {
    fn get(
        &self,
        request: &TransportRequest<'_>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<TransportResponse, WebProviderError> {
        if cancelled() {
            return Err(WebProviderError::new("CANCELLED"));
        }
        let target = request.target();
        let socket = SocketAddr::new(request.selected(), target.sanitized.port);
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(8))
            .resolve(&target.sanitized.canonical_host, socket)
            .build()
            .map_err(|_| WebProviderError::new("HTTP_CLIENT_FAILED"))?;
        let response = client
            .get(target.network_url().clone())
            .header(USER_AGENT, "EDY-VERDICT/0.1.0 passive-security-check")
            .header(ACCEPT_ENCODING, "identity")
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    WebProviderError::new("HTTP_TIMEOUT")
                } else if target.sanitized.scheme == "https" {
                    WebProviderError::new("TLS_OR_CONNECT_FAILED")
                } else {
                    WebProviderError::new("HTTP_CONNECT_FAILED")
                }
            })?;
        if cancelled() {
            return Err(WebProviderError::new("CANCELLED"));
        }
        let status = response.status().as_u16();
        let mut headers = Vec::new();
        for (name, value) in response.headers() {
            let value = value
                .to_str()
                .map_err(|_| WebProviderError::new("HTTP_HEADER_ENCODING"))?;
            headers.push((name.as_str().to_ascii_lowercase(), value.to_string()));
        }
        TransportResponse::new(status, headers)
    }
}

pub trait ReputationProvider: Send + Sync {
    fn lookup(&self, target: &PreparedUrlTarget) -> ReputationObservation;
}
pub struct UnavailableUrlhaus;
impl ReputationProvider for UnavailableUrlhaus {
    fn lookup(&self, _: &PreparedUrlTarget) -> ReputationObservation {
        ReputationObservation {
            provider: "URLhaus".into(),
            state: "unavailable_byok_not_configured".into(),
            exact_match: None,
            dataset_version: None,
            explanation: "Not checked — optional provider not configured.".into(),
        }
    }
}
pub struct LocalUrlhausDataset {
    hashes: HashSet<[u8; 32]>,
    version: String,
}
impl LocalUrlhausDataset {
    pub fn from_urls(version: &str, urls: &[&str]) -> Result<Self, WebProviderError> {
        if urls.len() > 100_000 || version.is_empty() || version.len() > 128 {
            return Err(WebProviderError::new("URLHAUS_DATASET_REJECTED"));
        }
        let mut hashes = HashSet::new();
        for url in urls {
            let prepared = prepare_url(url)?;
            hashes.insert(Sha256::digest(prepared.network_url().as_str().as_bytes()).into());
        }
        Ok(Self {
            hashes,
            version: version.into(),
        })
    }
}
impl ReputationProvider for LocalUrlhausDataset {
    fn lookup(&self, target: &PreparedUrlTarget) -> ReputationObservation {
        let digest: [u8; 32] = Sha256::digest(target.network_url().as_str().as_bytes()).into();
        let matched = self.hashes.contains(&digest);
        ReputationObservation{provider:"URLhaus".into(),state:"local_dataset".into(),exact_match:Some(matched),dataset_version:Some(self.version.clone()),explanation:if matched{"Exact canonical URL matched the local synthetic reputation dataset."}else{"Exact canonical URL was not present in the local dataset; coverage is not a safety guarantee."}.into()}
    }
}

fn values(headers: &[(String, String)], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter(|(key, value)| key == name && value.len() <= MAX_HEADER_VALUE_BYTES)
        .map(|(_, value)| value.clone())
        .take(8)
        .collect()
}
fn sanitize_header(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(512)
        .collect()
}
fn security_headers(headers: &[(String, String)], https: bool) -> Vec<HeaderObservation> {
    let mut out = vec![parse_hsts(
        &values(headers, "strict-transport-security"),
        https,
    )];
    out.extend(parse_csp(
        &values(headers, "content-security-policy"),
        &values(headers, "content-security-policy-report-only"),
    ));
    let specs = [
        ("x-content-type-options", Some("nosniff")),
        ("referrer-policy", None),
        ("permissions-policy", None),
        ("x-frame-options", None),
        ("cross-origin-opener-policy", None),
        ("cross-origin-resource-policy", None),
        ("cross-origin-embedder-policy", None),
        ("access-control-allow-origin", None),
        ("access-control-allow-credentials", None),
    ];
    for (name, exact) in specs {
        let found = values(headers, name);
        let (state, class, interpretation) = if found.is_empty() {
            (
                "missing",
                WebObservationClass::Hardening,
                "Header was not observed; absence alone does not prove exploitability.",
            )
        } else if exact
            .is_some_and(|expected| !found.iter().any(|v| v.eq_ignore_ascii_case(expected)))
        {
            (
                "malformed_or_unsupported",
                WebObservationClass::Review,
                "Observed value did not match the recognized token.",
            )
        } else if name.starts_with("access-control-") {
            (
                "observed",
                WebObservationClass::Review,
                "Passive CORS evidence requires contextual review; exploitability was not tested.",
            )
        } else {
            (
                "observed",
                WebObservationClass::Informational,
                "Header was observed in this point-in-time response.",
            )
        };
        out.push(HeaderObservation {
            name: name.into(),
            state: state.into(),
            value_sanitized: found.first().map(|v| sanitize_header(v)),
            interpretation: interpretation.into(),
            class,
            guidance: format!("Review {name} against application requirements."),
        });
    }
    for name in ["server", "x-powered-by"] {
        if let Some(value) = values(headers, name).first() {
            out.push(HeaderObservation {
                name: name.into(),
                state: "observed".into(),
                value_sanitized: Some(sanitize_header(value)),
                interpretation:
                    "Technology banner is informational and not a vulnerability by itself.".into(),
                class: WebObservationClass::Informational,
                guidance: "Minimize unnecessary disclosure where operationally appropriate.".into(),
            });
        }
    }
    let has_frame_ancestors = values(headers, "content-security-policy")
        .iter()
        .any(|value| value.to_ascii_lowercase().contains("frame-ancestors"));
    if has_frame_ancestors {
        out.retain(|item| !(item.name == "x-frame-options" && item.state == "missing"));
    }
    out
}

fn hop_target(
    base: &PreparedUrlTarget,
    location: &str,
) -> Result<PreparedUrlTarget, WebProviderError> {
    if location.len() > MAX_URL_BYTES
        || location.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n')
    {
        return Err(WebProviderError::new("REDIRECT_LOCATION_REJECTED"));
    }
    let joined = base
        .network_url()
        .join(location)
        .map_err(|_| WebProviderError::new("REDIRECT_LOCATION_REJECTED"))?;
    prepare_url(joined.as_str())
}

#[allow(
    clippy::too_many_arguments,
    reason = "security-sensitive resolver, transport, reputation, clock and cancellation capabilities stay explicit"
)]
pub fn execute_passive_scan(
    scan_id: &str,
    initial: PreparedUrlTarget,
    query_policy: QueryPolicy,
    resolver: &dyn DnsResolver,
    transport: &dyn HttpTransport,
    reputation: &dyn ReputationProvider,
    now_utc: &str,
    cancelled: &dyn Fn() -> bool,
) -> Result<PassiveWebAnalysis, WebProviderError> {
    let initial = initial.with_query_policy(query_policy);
    let mut current = initial.clone();
    let mut dns = Vec::new();
    let mut tls = Vec::new();
    let mut redirects = Vec::new();
    let mut headers_out = Vec::new();
    let mut cookies = Vec::new();
    let mut final_status = None;
    let mut final_target = None;
    let mut visited = BTreeSet::new();
    // A redirect target is resolved and validated exactly once before we mark the
    // hop as followed. The validated set is then consumed by the next request,
    // preventing a second DNS lookup from creating a rebinding window.
    let mut prevalidated_addresses = None;
    let mut coverage=WebCoverage{dns:"pending".into(),tls:"pending".into(),http:"pending".into(),redirects:"pending".into(),headers:"pending".into(),cookies:"pending".into(),reputation:"pending".into(),limitations:vec!["Passive point-in-time checks do not prove a website is safe, legitimate or vulnerability-free.".into(),"No page body or JavaScript is inspected or executed.".into()]};
    let mut tls_failure = None;
    for request_index in 0..MAX_TOTAL_REQUESTS {
        if cancelled() {
            return Err(WebProviderError::new("CANCELLED"));
        }
        let key = current.network_url().as_str().to_string();
        if !visited.insert(key) {
            coverage.redirects = "failed_loop".into();
            break;
        }
        let addresses = if let Some(addresses) = prevalidated_addresses.take() {
            addresses
        } else {
            let resolved = if let Ok(ip) = current.sanitized.canonical_host.parse::<IpAddr>() {
                vec![ip]
            } else {
                resolver.resolve(&current.sanitized.canonical_host, current.sanitized.port)?
            };
            validate_resolved_addresses(&resolved, MAX_DNS_ANSWERS)
                .map_err(WebProviderError::new)?
        };
        let selected = addresses[0];
        dns.push(DnsObservation {
            canonical_host: current.sanitized.canonical_host.clone(),
            public_addresses: addresses.iter().map(ToString::to_string).collect(),
            selected_address: Some(selected.to_string()),
            address_families: addresses
                .iter()
                .map(|ip| if ip.is_ipv4() { "ipv4" } else { "ipv6" }.into())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            resolved_at_utc: now_utc.into(),
            state: "resolved_public_and_pinned".into(),
        });
        coverage.dns = "executed".into();
        let response = match transport.get(
            &TransportRequest {
                target: &current,
                selected,
            },
            cancelled,
        ) {
            Ok(value) => value,
            Err(error) => {
                coverage.http = "failed".into();
                if current.sanitized.scheme == "https" {
                    coverage.tls = "failed".into();
                    tls_failure = Some(error.code().to_string());
                    tls.push(TlsObservation {
                        attempted: true,
                        certificate_state: TlsCertificateState::Failed,
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
                        error: Some(error.code().into()),
                    });
                }
                break;
            }
        };
        coverage.http = "executed".into();
        if current.sanitized.scheme == "https" {
            coverage.tls = "executed".into();
            tls.push(TlsObservation {
                attempted: true,
                certificate_state: TlsCertificateState::Valid,
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
            });
        } else {
            coverage.tls = "not_applicable".into();
        }
        let total: usize = response
            .headers
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum();
        if response.headers.len() > MAX_STORED_HEADERS
            || total > MAX_STORED_HEADER_BYTES
            || response
                .headers
                .iter()
                .any(|(_, v)| v.len() > MAX_HEADER_VALUE_BYTES)
        {
            coverage.headers = "failed_bounds".into();
            coverage.cookies = "failed_bounds".into();
            break;
        }
        if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            let location = response
                .headers
                .iter()
                .find(|(k, _)| k == LOCATION.as_str())
                .map(|(_, v)| v.as_str())
                .ok_or_else(|| WebProviderError::new("REDIRECT_LOCATION_MISSING"))?;
            let next = hop_target(&current, location)?;
            let same = current.sanitized.scheme == next.sanitized.scheme
                && current.sanitized.canonical_host == next.sanitized.canonical_host
                && current.sanitized.port == next.sanitized.port;
            let downgrade = current.sanitized.scheme == "https" && next.sanitized.scheme == "http";
            redirects.push(RedirectObservation {
                hop: request_index as u8,
                status: response.status,
                source_scheme: current.sanitized.scheme.clone(),
                source_host: current.sanitized.canonical_host.clone(),
                destination_scheme: next.sanitized.scheme.clone(),
                destination_host: next.sanitized.canonical_host.clone(),
                destination_display_url: next.sanitized.display_url.clone(),
                same_origin: same,
                followed: !downgrade,
                outcome: if downgrade {
                    "transport_downgrade"
                } else if current.sanitized.scheme == "http" && next.sanitized.scheme == "https" {
                    "http_upgraded_to_https"
                } else {
                    "redirect_validated"
                }
                .into(),
            });
            if downgrade {
                coverage.redirects = "executed_downgrade_blocked".into();
                final_target = Some(current.sanitized.clone());
                final_status = Some(response.status);
                break;
            }
            if redirects.len() > MAX_REDIRECTS {
                coverage.redirects = "failed_limit".into();
                break;
            }
            let next_addresses = if let Ok(ip) = next.sanitized.canonical_host.parse::<IpAddr>() {
                vec![ip]
            } else {
                resolver.resolve(&next.sanitized.canonical_host, next.sanitized.port)?
            };
            prevalidated_addresses = Some(
                validate_resolved_addresses(&next_addresses, MAX_DNS_ANSWERS)
                    .map_err(WebProviderError::new)?,
            );
            current = next;
            continue;
        }
        coverage.redirects = "executed".into();
        headers_out = security_headers(&response.headers, current.sanitized.scheme == "https");
        coverage.headers = "executed".into();
        for (_, cookie) in response
            .headers
            .iter()
            .filter(|(name, _)| name == SET_COOKIE.as_str())
            .take(MAX_COOKIES)
        {
            cookies.push(parse_set_cookie(cookie));
        }
        coverage.cookies = "executed".into();
        final_status = Some(response.status);
        final_target = Some(current.sanitized.clone());
        break;
    }
    let reputation = reputation.lookup(final_target.as_ref().map_or(&initial, |_| &current));
    coverage.reputation = if reputation.state == "unavailable_byok_not_configured" {
        "unavailable"
    } else {
        "executed"
    }
    .into();
    let mut findings = correlate_web(
        final_target.as_ref().unwrap_or(&initial.sanitized),
        &redirects,
        &headers_out,
        &cookies,
        &reputation,
    );
    if let Some(error) = tls_failure {
        let target = final_target.as_ref().unwrap_or(&initial.sanitized);
        findings.push(WebFinding {
            fingerprint_version: WEB_TLS_FINDING_V1.into(),
            fingerprint: web_fingerprint(WEB_TLS_FINDING_V1, "TLS_CERTIFICATE", target, &error),
            family: "TLS_CERTIFICATE".into(),
            title: "TLS or validated connection failed".into(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            class: WebObservationClass::Coverage,
            evidence: vec![error],
            guidance:
                "Review the structured connection failure without disabling certificate validation."
                    .into(),
        });
    }
    findings.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    let risk = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    let complete = coverage.dns == "executed"
        && coverage.http == "executed"
        && coverage.headers == "executed"
        && coverage.cookies == "executed";
    Ok(PassiveWebAnalysis {
        schema: WEB_ANALYSIS_SCHEMA.into(),
        scan_id: scan_id.into(),
        state: if complete { "partial" } else { "failed" }.into(),
        query_policy,
        target: initial.sanitized,
        final_target,
        dns,
        tls,
        redirects,
        final_http_status: final_status,
        headers: headers_out,
        cookies,
        reputation,
        findings,
        risk,
        confidence: if complete {
            Confidence::High
        } else {
            Confidence::Low
        },
        coverage,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionSmokeResult {
    pub host: String,
    pub selected_ip: String,
    pub status: u16,
    pub tls_validated: bool,
    pub request_count: u8,
    pub body_bytes_read: usize,
}
pub fn production_transport_smoke() -> Result<ProductionSmokeResult, WebProviderError> {
    let prepared = prepare_url("https://example.com/")?;
    let addresses = SystemDnsResolver.resolve("example.com", 443)?;
    let selected = addresses[0];
    let response = ProductionHttpTransport.get(
        &TransportRequest {
            target: &prepared,
            selected,
        },
        &|| false,
    )?;
    Ok(ProductionSmokeResult {
        host: "example.com".into(),
        selected_ip: selected.to_string(),
        status: response.status,
        tls_validated: true,
        request_count: 1,
        body_bytes_read: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Resolver(Vec<IpAddr>);
    impl DnsResolver for Resolver {
        fn resolve(&self, _: &str, _: u16) -> Result<Vec<IpAddr>, WebProviderError> {
            Ok(self.0.clone())
        }
    }
    struct Transport {
        responses: std::sync::Mutex<Vec<TransportResponse>>,
    }
    impl HttpTransport for Transport {
        fn get(
            &self,
            _: &TransportRequest<'_>,
            _: &dyn Fn() -> bool,
        ) -> Result<TransportResponse, WebProviderError> {
            Ok(self.responses.lock().unwrap().remove(0))
        }
    }
    #[test]
    fn parser_rejects_schemes_userinfo_ports_controls_and_private_ip() {
        for value in [
            "example.com",
            "file:///x",
            "https://u:p@example.com/",
            "https://example.com:444/",
            "https://localhost/",
            "http://127.0.0.1/",
            "https://example.com/\\x",
            "https://example.com/%0d%0a",
            "https://example.com/%5cprivate",
            "https://example.com%2f@evil.example/",
            "https://[fe80::1%25eth0]/",
            "https://[::1]/",
            "https://example.com/\0",
        ] {
            assert!(prepare_url(value).is_err(), "{value}");
        }
        let parsed = prepare_url("HTTPS://ExAmPlE.com/a?token=secret#private").unwrap();
        assert_eq!(parsed.sanitized.canonical_host, "example.com");
        assert!(parsed.sanitized.fragment_present);
        assert!(!parsed.sanitized.display_url.contains("secret"));
        assert_eq!(
            prepare_url("https://example.com./")
                .unwrap()
                .sanitized
                .canonical_host,
            "example.com"
        );
        assert!(
            prepare_url("https://bücher.example/")
                .unwrap()
                .sanitized
                .idna_ascii
        );
        assert!(
            prepare_url(&format!(
                "https://example.com/{}",
                "a".repeat(MAX_URL_BYTES)
            ))
            .is_err()
        );
        assert!(prepare_url("https://[2606:4700:4700::1111]/").is_ok());
    }
    #[test]
    fn redirect_to_private_is_rejected_before_second_request() {
        let resolver = Resolver(vec!["93.184.216.34".parse().unwrap()]);
        let transport = Transport {
            responses: std::sync::Mutex::new(vec![
                TransportResponse::new(302, vec![("location".into(), "http://127.0.0.1/".into())])
                    .unwrap(),
            ]),
        };
        let result = execute_passive_scan(
            "scan",
            prepare_url("https://example.com/").unwrap(),
            QueryPolicy::Strip,
            &resolver,
            &transport,
            &UnavailableUrlhaus,
            "2026-09-02T00:00:00Z",
            &|| false,
        );
        assert_eq!(result.unwrap_err().code(), "URL_IP_LITERAL_REJECTED");
    }
    #[test]
    fn full_synthetic_flow_redacts_query_and_cookie() {
        let secret = "EDY_FAKE_COOKIE_SECRET_LEVEL4";
        let transport = Transport {
            responses: std::sync::Mutex::new(vec![
                TransportResponse::new(
                    200,
                    vec![
                        (
                            "strict-transport-security".into(),
                            "max-age=31536000".into(),
                        ),
                        (
                            "content-security-policy".into(),
                            "default-src 'self'; object-src 'none'".into(),
                        ),
                        (
                            "set-cookie".into(),
                            format!("session={secret}; Secure; HttpOnly; SameSite=Lax"),
                        ),
                    ],
                )
                .unwrap(),
            ]),
        };
        let analysis = execute_passive_scan(
            "scan",
            prepare_url("https://example.com/a?token=EDY_FAKE_QUERY_SECRET_LEVEL4").unwrap(),
            QueryPolicy::Send,
            &Resolver(vec!["93.184.216.34".parse().unwrap()]),
            &transport,
            &UnavailableUrlhaus,
            "2026-09-02T00:00:00Z",
            &|| false,
        )
        .unwrap();
        let json = serde_json::to_string(&analysis).unwrap();
        assert!(!json.contains(secret));
        assert!(!json.contains("EDY_FAKE_QUERY_SECRET_LEVEL4"));
        assert_eq!(analysis.final_http_status, Some(200));
    }
    #[test]
    fn local_reputation_is_exact_url_only() {
        let data =
            LocalUrlhausDataset::from_urls("fixture", &["https://bad.example/path"]).unwrap();
        assert_eq!(
            data.lookup(&prepare_url("https://bad.example/path").unwrap())
                .exact_match,
            Some(true)
        );
        assert_eq!(
            data.lookup(&prepare_url("https://bad.example/other").unwrap())
                .exact_match,
            Some(false)
        );
    }

    struct RebindingResolver(AtomicUsize);
    impl DnsResolver for RebindingResolver {
        fn resolve(&self, _: &str, _: u16) -> Result<Vec<IpAddr>, WebProviderError> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(vec!["93.184.216.34".parse().unwrap()])
            } else {
                Ok(vec!["127.0.0.1".parse().unwrap()])
            }
        }
    }
    struct PinRecordingTransport(std::sync::Mutex<Vec<IpAddr>>);
    impl HttpTransport for PinRecordingTransport {
        fn get(
            &self,
            request: &TransportRequest<'_>,
            _: &dyn Fn() -> bool,
        ) -> Result<TransportResponse, WebProviderError> {
            self.0.lock().unwrap().push(request.selected());
            TransportResponse::new(204, vec![])
        }
    }
    #[test]
    fn rebind_attempt_cannot_change_the_validated_pinned_connection() {
        let resolver = RebindingResolver(AtomicUsize::new(0));
        let transport = PinRecordingTransport(std::sync::Mutex::new(Vec::new()));
        let result = execute_passive_scan(
            "scan",
            prepare_url("https://example.com/").unwrap(),
            QueryPolicy::Strip,
            &resolver,
            &transport,
            &UnavailableUrlhaus,
            "2026-09-02T00:00:00Z",
            &|| false,
        )
        .unwrap();
        assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            *transport.0.lock().unwrap(),
            vec!["93.184.216.34".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(result.final_http_status, Some(204));
    }

    struct HopResolver(std::sync::Mutex<Vec<String>>);
    impl DnsResolver for HopResolver {
        fn resolve(&self, host: &str, _: u16) -> Result<Vec<IpAddr>, WebProviderError> {
            self.0.lock().unwrap().push(host.into());
            Ok(vec!["93.184.216.34".parse().unwrap()])
        }
    }
    struct CountingTransport {
        calls: AtomicUsize,
        responses: std::sync::Mutex<Vec<TransportResponse>>,
    }
    impl HttpTransport for CountingTransport {
        fn get(
            &self,
            _: &TransportRequest<'_>,
            _: &dyn Fn() -> bool,
        ) -> Result<TransportResponse, WebProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.responses.lock().unwrap().remove(0))
        }
    }
    #[test]
    fn every_redirect_host_is_resolved_once_before_its_pinned_request() {
        let resolver = HopResolver(std::sync::Mutex::new(Vec::new()));
        let transport = CountingTransport {
            calls: AtomicUsize::new(0),
            responses: std::sync::Mutex::new(vec![
                TransportResponse::new(
                    302,
                    vec![("location".into(), "https://second.example/final".into())],
                )
                .unwrap(),
                TransportResponse::new(204, vec![]).unwrap(),
            ]),
        };
        let analysis = execute_passive_scan(
            "scan",
            prepare_url("https://first.example/").unwrap(),
            QueryPolicy::Strip,
            &resolver,
            &transport,
            &UnavailableUrlhaus,
            "2026-09-02T00:00:00Z",
            &|| false,
        )
        .unwrap();
        assert_eq!(
            *resolver.0.lock().unwrap(),
            vec!["first.example", "second.example"]
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
        assert_eq!(analysis.redirects.len(), 1);
        assert!(analysis.redirects[0].followed);
    }

    struct HostResolver;
    impl DnsResolver for HostResolver {
        fn resolve(&self, host: &str, _: u16) -> Result<Vec<IpAddr>, WebProviderError> {
            Ok(vec![
                if host == "private.example" {
                    "10.0.0.1"
                } else {
                    "93.184.216.34"
                }
                .parse()
                .unwrap(),
            ])
        }
    }

    #[test]
    fn private_redirect_dns_answer_is_blocked_before_a_second_request() {
        let transport = CountingTransport {
            calls: AtomicUsize::new(0),
            responses: std::sync::Mutex::new(vec![
                TransportResponse::new(
                    302,
                    vec![("location".into(), "https://private.example/".into())],
                )
                .unwrap(),
            ]),
        };
        let result = execute_passive_scan(
            "scan",
            prepare_url("https://public.example/").unwrap(),
            QueryPolicy::Strip,
            &HostResolver,
            &transport,
            &UnavailableUrlhaus,
            "2026-09-02T00:00:00Z",
            &|| false,
        );
        assert_eq!(result.unwrap_err().code(), "TARGET_RESOLUTION_REJECTED");
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn redirect_matrix_blocks_private_downgrade_loop_and_limits_hops() {
        let run = |start: &str, responses: Vec<TransportResponse>| {
            execute_passive_scan(
                "scan",
                prepare_url(start).unwrap(),
                QueryPolicy::Strip,
                &HostResolver,
                &Transport {
                    responses: std::sync::Mutex::new(responses),
                },
                &UnavailableUrlhaus,
                "2026-09-02T00:00:00Z",
                &|| false,
            )
        };
        let private = run(
            "https://public.example/",
            vec![
                TransportResponse::new(
                    302,
                    vec![("location".into(), "https://private.example/".into())],
                )
                .unwrap(),
            ],
        );
        assert_eq!(private.unwrap_err().code(), "TARGET_RESOLUTION_REJECTED");
        let downgrade = run(
            "https://public.example/",
            vec![
                TransportResponse::new(
                    302,
                    vec![("location".into(), "http://public.example/".into())],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(downgrade.coverage.redirects, "executed_downgrade_blocked");
        assert!(!downgrade.redirects[0].followed);
        let looped = run(
            "https://public.example/",
            vec![
                TransportResponse::new(
                    302,
                    vec![("location".into(), "https://public.example/".into())],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(looped.coverage.redirects, "failed_loop");
        let responses = (0..6)
            .map(|index| {
                TransportResponse::new(302, vec![("location".into(), format!("/hop{}", index + 1))])
                    .unwrap()
            })
            .collect();
        let limited = run("https://public.example/start", responses).unwrap();
        assert_eq!(limited.coverage.redirects, "failed_limit");
        assert_eq!(limited.redirects.len(), 6);
    }

    struct ErrorTransport(&'static str);
    impl HttpTransport for ErrorTransport {
        fn get(
            &self,
            _: &TransportRequest<'_>,
            _: &dyn Fn() -> bool,
        ) -> Result<TransportResponse, WebProviderError> {
            Err(WebProviderError::new(self.0))
        }
    }
    #[test]
    fn transport_failures_and_oversized_headers_fail_closed() {
        for code in [
            "HTTP_TIMEOUT",
            "HTTP_CONNECT_FAILED",
            "TLS_OR_CONNECT_FAILED",
        ] {
            let analysis = execute_passive_scan(
                "scan",
                prepare_url("https://example.com/").unwrap(),
                QueryPolicy::Strip,
                &Resolver(vec!["93.184.216.34".parse().unwrap()]),
                &ErrorTransport(code),
                &UnavailableUrlhaus,
                "2026-09-02T00:00:00Z",
                &|| false,
            )
            .unwrap();
            assert_eq!(analysis.state, "failed");
            assert_eq!(analysis.coverage.http, "failed");
        }
        let headers = (0..65)
            .map(|index| (format!("x-{index}"), "v".into()))
            .collect();
        let analysis = execute_passive_scan(
            "scan",
            prepare_url("https://example.com/").unwrap(),
            QueryPolicy::Strip,
            &Resolver(vec!["93.184.216.34".parse().unwrap()]),
            &Transport {
                responses: std::sync::Mutex::new(vec![
                    TransportResponse::new(200, headers).unwrap(),
                ]),
            },
            &UnavailableUrlhaus,
            "2026-09-02T00:00:00Z",
            &|| false,
        )
        .unwrap();
        assert_eq!(analysis.coverage.headers, "failed_bounds");
    }

    struct ResolverError(&'static str);
    impl DnsResolver for ResolverError {
        fn resolve(&self, _: &str, _: u16) -> Result<Vec<IpAddr>, WebProviderError> {
            Err(WebProviderError::new(self.0))
        }
    }
    #[test]
    fn dns_timeout_and_failure_propagate_without_transport() {
        for code in ["DNS_TIMEOUT", "DNS_FAILED"] {
            let result = execute_passive_scan(
                "scan",
                prepare_url("https://example.com/").unwrap(),
                QueryPolicy::Strip,
                &ResolverError(code),
                &ErrorTransport("MUST_NOT_RUN"),
                &UnavailableUrlhaus,
                "2026-09-02T00:00:00Z",
                &|| false,
            );
            assert_eq!(result.unwrap_err().code(), code);
        }
    }

    #[test]
    fn ordinary_http_statuses_are_observations_not_vulnerabilities() {
        for status in [200, 204, 404, 500] {
            let analysis = execute_passive_scan(
                "scan",
                prepare_url("https://example.com/").unwrap(),
                QueryPolicy::Strip,
                &Resolver(vec!["93.184.216.34".parse().unwrap()]),
                &Transport {
                    responses: std::sync::Mutex::new(vec![
                        TransportResponse::new(status, vec![]).unwrap(),
                    ]),
                },
                &UnavailableUrlhaus,
                "2026-09-02T00:00:00Z",
                &|| false,
            )
            .unwrap();
            assert_eq!(analysis.final_http_status, Some(status));
            assert!(
                analysis
                    .findings
                    .iter()
                    .all(|finding| !finding.title.contains(&status.to_string()))
            );
        }
    }

    #[test]
    fn every_supported_redirect_status_is_handled_manually() {
        for status in [301, 302, 303, 307, 308] {
            let analysis = execute_passive_scan(
                "scan",
                prepare_url("https://example.com/start").unwrap(),
                QueryPolicy::Strip,
                &Resolver(vec!["93.184.216.34".parse().unwrap()]),
                &Transport {
                    responses: std::sync::Mutex::new(vec![
                        TransportResponse::new(status, vec![("location".into(), "/final".into())])
                            .unwrap(),
                        TransportResponse::new(204, vec![]).unwrap(),
                    ]),
                },
                &UnavailableUrlhaus,
                "2026-09-02T00:00:00Z",
                &|| false,
            )
            .unwrap();
            assert_eq!(analysis.redirects[0].status, status);
            assert!(analysis.redirects[0].followed);
        }
    }

    #[test]
    #[ignore = "explicit one-request production transport smoke against IANA example.com"]
    fn production_example_com_transport_smoke_is_bounded() {
        let result = production_transport_smoke().unwrap();
        assert_eq!(result.host, "example.com");
        assert!(result.tls_validated);
        assert_eq!(result.request_count, 1);
        assert_eq!(result.body_bytes_read, 0);
        assert!((100..=599).contains(&result.status));
    }
}
