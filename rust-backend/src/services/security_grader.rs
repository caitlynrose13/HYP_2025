use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::handlers::assessment_handler::{
    CertificateInfo, CipherSuiteInfo, KeyExchangeInfo, ProtocolSupport, VulnerabilityInfo,
};

// ====================================
// CORE TYPES

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    APlus,
    A,
    B,
    C,
    F,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GradeInput {
    pub tls13_supported: bool,
    pub tls12_supported: bool,
    pub tls11_supported: bool,
    pub tls10_supported: bool,
    pub cert_valid: bool,
    pub cert_expired: bool,
    pub cert_key_strength_ok: bool,
    pub hsts: bool,
    pub forward_secrecy: bool,
    pub weak_protocols_disabled: bool,
    pub ocsp_stapling_enabled: bool,

    // HTTP Security Headers
    pub https_redirect: bool,
    pub csp_header: bool,
    pub x_frame_options: bool,
    pub x_content_type_options: bool,
    pub expect_ct: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedScan {
    pub domain: String,
    pub grade: Grade,
    pub details: GradeInput,
    pub certificate: CertificateInfo,
    pub protocols: ProtocolSupport,
    pub cipher_suites: CipherSuiteInfo,
    pub vulnerabilities: VulnerabilityInfo,
    pub key_exchange: KeyExchangeInfo,
    pub whois: Option<WhoisInfo>,
    pub explanation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisInfo {
    pub creation_date: Option<NaiveDateTime>,
    pub registrar: Option<String>,
    pub raw: String,
}

// ====================================
// WHOIS CONFIGURATION

/// Mapping of TLDs to their respective WHOIS servers
const WHOIS_SERVERS: &[(&str, &str)] = &[
    ("com", "whois.verisign-grs.com:43"),
    ("net", "whois.verisign-grs.com:43"),
    ("org", "whois.pir.org:43"),
    ("io", "whois.nic.io:43"),
    ("co", "whois.nic.co:43"),
    ("uk", "whois.nic.uk:43"),
    ("de", "whois.denic.de:43"),
    ("info", "whois.afilias.net:43"),
    ("biz", "whois.biz:43"),
    ("us", "whois.nic.us:43"),
    ("ca", "whois.cira.ca:43"),
    ("fr", "whois.nic.fr:43"),
    ("au", "whois.auda.org.au:43"),
    ("jp", "whois.jprs.jp:43"),
    ("ru", "whois.tcinet.ru:43"),
    ("ch", "whois.nic.ch:43"),
    ("nl", "whois.domain-registry.nl:43"),
    ("se", "whois.iis.se:43"),
    ("no", "whois.norid.no:43"),
    ("es", "whois.nic.es:43"),
    ("it", "whois.nic.it:43"),
    ("eu", "whois.eu:43"),
    ("tv", "whois.nic.tv:43"),
    ("me", "whois.nic.me:43"),
    ("xyz", "whois.nic.xyz:43"),
];

/// Registrars commonly associated with suspicious domains
const SUSPICIOUS_REGISTRARS: &[&str] = &[
    "NameCheap",
    "Alibaba",
    "Bizcn.com",
    "Eranet International",
    "PDR Ltd.",
];

// ====================================
// WHOIS FUNCTIONALITY

/// Resolves the appropriate WHOIS server for a given TLD
fn get_whois_server(tld: &str) -> &'static str {
    WHOIS_SERVERS
        .iter()
        .find(|(domain_tld, _)| *domain_tld == tld)
        .map(|(_, server)| *server)
        .unwrap_or("whois.iana.org:43")
}

/// Removes www prefix to extract the root domain
fn extract_root_domain(domain: &str) -> &str {
    domain.strip_prefix("www.").unwrap_or(domain)
}

/// Extracts the top-level domain from a domain name
fn extract_tld(domain: &str) -> String {
    domain.split('.').last().unwrap_or("").to_lowercase()
}

/// Performs WHOIS lookup for a domain with referral server handling
pub fn whois_query(domain: &str) -> Result<String, String> {
    let root_domain = extract_root_domain(domain);
    let tld = extract_tld(root_domain);
    let server = get_whois_server(&tld);

    match query_whois_server(root_domain, server) {
        Ok(response) => {
            if let Some(referral_server) = extract_referral_server(&response) {
                query_whois_server(root_domain, &referral_server).or(Ok(response))
            } else {
                Ok(response)
            }
        }
        Err(e) => Err(e),
    }
}

/// Extracts referral WHOIS server from initial response
fn extract_referral_server(response: &str) -> Option<String> {
    for line in response.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.contains("whois server:") || line_lower.contains("referral server:") {
            if let Some(idx) = line.find(':') {
                let server = line[idx + 1..].trim();
                if !server.is_empty() && server != "whois.iana.org" {
                    return Some(format!("{}:43", server));
                }
            }
        }
    }
    None
}

/// Establishes TCP connection to WHOIS server and retrieves domain information
fn query_whois_server(domain: &str, server: &str) -> Result<String, String> {
    use std::net::ToSocketAddrs;

    let (hostname, port) = if server.contains(':') {
        let parts: Vec<&str> = server.split(':').collect();
        (parts[0], parts[1].parse::<u16>().unwrap_or(43))
    } else {
        (server, 43)
    };

    let addr = format!("{}:{}", hostname, port)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve {}: {}", hostname, e))?
        .next()
        .ok_or_else(|| format!("No addresses found for {}", hostname))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("Failed to set read timeout: {}", e))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Failed to set write timeout: {}", e))?;

    stream
        .write_all(format!("{}\r\n", domain).as_bytes())
        .map_err(|e| format!("Failed to write query: {}", e))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("Failed to read response: {}", e))?;

    Ok(response)
}

// ====================================
// WHOIS PARSING

/// Parses WHOIS response to extract structured information
fn parse_whois_response(response: &str) -> WhoisInfo {
    let creation_date = extract_creation_date(response);
    let registrar = extract_registrar(response);

    WhoisInfo {
        creation_date,
        registrar,
        raw: response.to_string(),
    }
}

/// Extracts domain creation date from WHOIS response using multiple patterns
fn extract_creation_date(response: &str) -> Option<NaiveDateTime> {
    let date_patterns = [
        "creation date",
        "created:",
        "registered:",
        "created on:",
        "domain registered:",
    ];

    for line in response.lines() {
        let line_lower = line.to_lowercase();

        for pattern in &date_patterns {
            if line_lower.contains(pattern) {
                if let Some(idx) = line.find(':') {
                    let date_str = line[idx + 1..].trim();

                    let formats = [
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%d",
                        "%d-%m-%Y",
                        "%m/%d/%Y",
                        "%Y/%m/%d",
                        "%d.%m.%Y",
                    ];

                    for format in &formats {
                        if let Ok(dt) = NaiveDateTime::parse_from_str(date_str, format) {
                            return Some(dt);
                        }
                        if let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, format) {
                            return Some(date.and_hms_opt(0, 0, 0)?);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Extracts registrar information from WHOIS response
fn extract_registrar(response: &str) -> Option<String> {
    for line in response.lines() {
        if line.to_lowercase().contains("registrar:") {
            if let Some(idx) = line.find(':') {
                return Some(line[idx + 1..].trim().to_string());
            }
        }
    }
    None
}

// ====================================
// SECURITY GRADING SYSTEM

/// Main grading function that applies penalty system to generate security score
pub fn grade_site(input: &GradeInput, _certificate: &CertificateInfo) -> (Grade, Vec<String>) {
    let mut score = 100;
    let mut reasons = Vec::new();

    apply_protocol_penalties(&mut score, &mut reasons, input);
    apply_certificate_penalties(&mut score, &mut reasons, input);
    apply_security_feature_penalties(&mut score, &mut reasons, input);
    apply_http_security_penalties(&mut score, &mut reasons, input);

    let mut grade = calculate_grade_from_score(score);

    // Grade capping: TLS 1.1 support limits grade to B maximum
    if (input.tls12_supported || input.tls13_supported)
        && input.tls11_supported
        && grade != Grade::F
    {
        if grade == Grade::APlus || grade == Grade::A {
            grade = Grade::B;
            reasons.push(
                "Grade capped at B due to support for obsolete TLS 1.1 protocol.".to_string(),
            );
        }
    }

    (grade, reasons)
}

/// Combines technical security assessment with domain reputation analysis
pub fn get_or_run_scan(
    domain: &str,
    input: &GradeInput,
    certificate: &CertificateInfo,
    _protocols: &ProtocolSupport,
    _cipher_suites: &CipherSuiteInfo,
    _vulnerabilities: &VulnerabilityInfo,
    _key_exchange: &KeyExchangeInfo,
    whois_response: Option<&str>,
) -> (Grade, Option<String>) {
    let (mut grade, _technical_reasons) = grade_site(input, certificate);
    let whois_info = whois_response.map(parse_whois_response);

    let whois_issues = check_whois_issues(domain, &whois_info, &mut grade);
    let explanation = if whois_issues.is_empty() {
        None
    } else {
        Some(whois_issues.join(" "))
    };

    (grade, explanation)
}

// ====================================
// PENALTY APPLICATION FUNCTIONS

/// Applies penalties for TLS protocol support
fn apply_protocol_penalties(score: &mut i32, reasons: &mut Vec<String>, input: &GradeInput) {
    // Critical failure: TLS 1.0 support
    if input.tls10_supported {
        *score = 0;
        reasons.push("Supports obsolete TLS 1.0 protocol (grade override to F).".to_string());
        return;
    }

    // Critical failure: No modern TLS support
    if !input.tls12_supported && !input.tls13_supported {
        *score = 0;
        reasons.push("Does not support any modern TLS version (1.2 or 1.3).".to_string());
        return;
    }

    // Major penalty: TLS 1.1 support
    if input.tls11_supported {
        *score -= 40;
        reasons.push("Supports obsolete TLS 1.1 protocol (major penalty applied).".to_string());
    }

    // Minor penalty: Missing TLS 1.3
    if input.tls12_supported && !input.tls13_supported {
        *score -= 10;
        reasons.push("Does not support TLS 1.3 (recommended modern standard).".to_string());
    }
}

/// Applies penalties for certificate-related issues
fn apply_certificate_penalties(score: &mut i32, reasons: &mut Vec<String>, input: &GradeInput) {
    // Critical failure: Invalid or expired certificate
    if !input.cert_valid || input.cert_expired {
        *score = 0;
        reasons.push("Certificate is invalid or expired.".to_string());
        return;
    }

    // High penalty: Weak key strength (< 2048-bit RSA)
    if !input.cert_key_strength_ok {
        *score -= 15;
        reasons.push("Certificate uses a weak key (e.g., < 2048-bit).".to_string());
    }
}

/// Applies penalties for missing security features
fn apply_security_feature_penalties(
    score: &mut i32,
    reasons: &mut Vec<String>,
    input: &GradeInput,
) {
    if !input.hsts {
        *score -= 10;
        reasons.push("HTTP Strict Transport Security (HSTS) is not enabled.".to_string());
    }

    if !input.forward_secrecy {
        *score -= 15;
        reasons.push("Perfect Forward Secrecy is not enabled.".to_string());
    }

    if !input.ocsp_stapling_enabled {
        *score -= 5;
        reasons.push("OCSP Stapling is not enabled.".to_string());
    }
}

/// Applies penalties for missing HTTP security headers
fn apply_http_security_penalties(score: &mut i32, reasons: &mut Vec<String>, input: &GradeInput) {
    if !input.https_redirect {
        *score -= 10;
        reasons.push("HTTP does not redirect to HTTPS.".to_string());
    }

    if !input.csp_header {
        *score -= 8;
        reasons.push("Content Security Policy (CSP) header is missing.".to_string());
    }

    if !input.x_frame_options {
        *score -= 5;
        reasons.push("X-Frame-Options header is missing (clickjacking protection).".to_string());
    }

    if !input.x_content_type_options {
        *score -= 3;
        reasons.push("X-Content-Type-Options header is missing.".to_string());
    }

    if !input.expect_ct {
        *score -= 2;
        reasons.push("Expect-CT header is missing (Certificate Transparency).".to_string());
    }
}

/// Converts numeric score to letter grade
fn calculate_grade_from_score(score: i32) -> Grade {
    match score {
        95..=100 => Grade::APlus,
        80..=94 => Grade::A,
        65..=79 => Grade::B,
        50..=64 => Grade::C,
        _ => Grade::F,
    }
}

// ====================================
// DOMAIN REPUTATION ANALYSIS

/// Evaluates domain reputation factors that may override technical grade
fn check_whois_issues(
    domain: &str,
    whois_info: &Option<WhoisInfo>,
    grade: &mut Grade,
) -> Vec<String> {
    let mut issues = Vec::new();

    if let Some(whois) = whois_info {
        check_domain_age(domain, whois, grade, &mut issues);
        check_privacy_protection(whois, &mut issues);
        check_suspicious_registrar(whois, &mut issues);
    }

    issues
}

/// Checks domain age for phishing risk assessment
fn check_domain_age(domain: &str, whois: &WhoisInfo, grade: &mut Grade, issues: &mut Vec<String>) {
    if let Some(creation) = whois.creation_date {
        let now = chrono::Utc::now().naive_utc();
        let age_days = (now - creation).num_days();

        if age_days < 30 {
            println!(
                "[DEBUG] Domain {} is {} days old, downgrading to F",
                domain, age_days
            );
            *grade = Grade::F;
            issues.push(format!(
                "Domain registered less than 30 days ago ({} days): suspicious for phishing.",
                age_days
            ));
        }
    }
}

/// Flags domains with privacy-protected WHOIS information
fn check_privacy_protection(whois: &WhoisInfo, issues: &mut Vec<String>) {
    let raw_lower = whois.raw.to_lowercase();
    if raw_lower.contains("redacted for privacy") || raw_lower.contains("privacy protection") {
        issues.push(
            "WHOIS info is privacy-protected: may indicate suspicious or untrustworthy domain."
                .to_string(),
        );
    }
}

/// Identifies domains registered with suspicious registrars
fn check_suspicious_registrar(whois: &WhoisInfo, issues: &mut Vec<String>) {
    if let Some(registrar) = &whois.registrar {
        for suspicious in SUSPICIOUS_REGISTRARS {
            if registrar
                .to_lowercase()
                .contains(&suspicious.to_lowercase())
            {
                issues.push(format!(
                    "Registrar '{}' is known for hosting suspicious domains.",
                    registrar
                ));
                break;
            }
        }
    }
}

// ====================================
// GRADE IMPLEMENTATION

impl Grade {
    pub fn as_str(&self) -> &'static str {
        match self {
            Grade::APlus => "A+",
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::F => "F",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Grade::APlus => "Excellent security configuration",
            Grade::A => "Very good security configuration",
            Grade::B => "Adequate security configuration",
            Grade::C => "Poor security configuration",
            Grade::F => "Failed security configuration",
        }
    }
}
