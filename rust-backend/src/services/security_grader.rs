use std::net::TcpStream;

/// Queries the WHOIS server for a given domain and returns the raw response.
/// Only works for .com/.net domains (whois.verisign-grs.com).
/// Queries the WHOIS server for a given domain and returns the raw response.
/// Supports .com/.net/.org/.io/.co/.uk/.de/.info/.biz/.us/.ca/.fr/.au/.jp/.ru/.ch/.nl/.se/.no/.es/.it/.eu/.tv/.me/.xyz
pub fn whois_query(domain: &str) -> Result<String, String> {
    let tld = domain.split('.').last().unwrap_or("").to_lowercase();
    let server = match tld.as_str() {
        "com" | "net" => "whois.verisign-grs.com:43",
        "org" => "whois.pir.org:43",
        "io" => "whois.nic.io:43",
        "co" => "whois.nic.co:43",
        "uk" => "whois.nic.uk:43",
        "de" => "whois.denic.de:43",
        "info" => "whois.afilias.net:43",
        "biz" => "whois.biz:43",
        "us" => "whois.nic.us:43",
        "ca" => "whois.cira.ca:43",
        "fr" => "whois.nic.fr:43",
        "au" => "whois.auda.org.au:43",
        "jp" => "whois.jprs.jp:43",
        "ru" => "whois.tcinet.ru:43",
        "ch" => "whois.nic.ch:43",
        "nl" => "whois.domain-registry.nl:43",
        "se" => "whois.iis.se:43",
        "no" => "whois.norid.no:43",
        "es" => "whois.nic.es:43",
        "it" => "whois.nic.it:43",
        "eu" => "whois.eu:43",
        "tv" => "whois.nic.tv:43",
        "me" => "whois.nic.me:43",
        "xyz" => "whois.nic.xyz:43",
        _ => "whois.iana.org:43", // fallback
    };
    let mut stream = TcpStream::connect(server).map_err(|e| format!("Failed to connect: {}", e))?;
    stream
        .write_all(format!("{}\r\n", domain).as_bytes())
        .map_err(|e| format!("Failed to write: {}", e))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("Failed to read: {}", e))?;
    Ok(response)
}

// Example usage in your workflow:
// let whois_resp = whois_query("example.com").ok();
// let (grade, cached) = get_or_run_scan(
//     domain,
//     &input,
//     &certificate,
//     &protocols,
//     &cipher_suites,
//     &vulnerabilities,
//     &key_exchange,
//     whois_resp.as_deref(),
// );
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    APlus,
    A,
    AMinus,
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
    pub cipher_is_strong: bool,
    pub cert_valid: bool,
    pub hsts: bool,
    pub forward_secrecy: bool,
    pub weak_protocols_disabled: bool, // TLS 1.0/1.1 disabled
}

pub fn grade_site(input: &GradeInput) -> Grade {
    // F - No TLS 1.2 or 1.3 support, or weak protocols (SSL Labs: F)
    if !input.tls12_supported || !input.tls13_supported {
        // If either TLS 1.2 or TLS 1.3 fails, treat as supporting weak protocols
        return Grade::F;
    }
    if input.tls10_supported || input.tls11_supported {
        return Grade::F;
    }

    // C - Certificate issues (expired, invalid, etc.)
    if !input.cert_valid {
        return Grade::C;
    }

    // B - Weak cipher suites or no forward secrecy
    if !input.cipher_is_strong || !input.forward_secrecy {
        return Grade::B;
    }

    // A+ - TLS 1.3 + HSTS + strong ciphers + forward secrecy
    if input.tls13_supported
        && input.hsts
        && input.tls12_supported
        && input.cipher_is_strong
        && input.forward_secrecy
    {
        return Grade::APlus;
    }

    // A - TLS 1.3 supported with strong security features
    if input.tls13_supported
        && input.tls12_supported
        && input.cipher_is_strong
        && input.forward_secrecy
    {
        return Grade::A;
    }

    // A- - Only TLS 1.2 but with excellent security (strong ciphers, forward secrecy)
    if input.tls12_supported && input.cipher_is_strong && input.cert_valid && input.forward_secrecy
    {
        return Grade::AMinus;
    }

    // B - TLS 1.2 with some security features
    if input.tls12_supported && input.cert_valid {
        return Grade::B;
    }

    Grade::F
}
use crate::handlers::assessment_handler::{
    CertificateInfo, CipherSuiteInfo, KeyExchangeInfo, ProtocolSupport, VulnerabilityInfo,
};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

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

/// Parses WHOIS response for creation date and registrar (simple version)
pub fn parse_whois_response(response: &str) -> WhoisInfo {
    let mut creation_date = None;
    let mut registrar = None;
    for line in response.lines() {
        if line.to_lowercase().contains("creation date") {
            // Example: Creation Date: 2020-01-01T12:34:56Z
            if let Some(idx) = line.find(":") {
                let date_str = line[idx + 1..].trim();
                if let Ok(dt) = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%dT%H:%M:%SZ") {
                    creation_date = Some(dt);
                } else if let Ok(dt) = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S")
                {
                    creation_date = Some(dt);
                }
            }
        }
        if line.to_lowercase().contains("registrar:") {
            if let Some(idx) = line.find(":") {
                registrar = Some(line[idx + 1..].trim().to_string());
            }
        }
    }
    WhoisInfo {
        creation_date,
        registrar,
        raw: response.to_string(),
    }
}

const LOG_PATH: &str = "scan_log.json";

pub fn load_cache() -> HashMap<String, CachedScan> {
    if !Path::new(LOG_PATH).exists() {
        return HashMap::new();
    }
    let mut file = match File::open(LOG_PATH) {
        Ok(f) => f,
        Err(_) => return HashMap::new(),
    };
    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_ok() {
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        HashMap::new()
    }
}

fn save_cache(cache: &HashMap<String, CachedScan>) {
    if let Ok(json) = serde_json::to_string_pretty(cache) {
        let _ = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(LOG_PATH)
            .and_then(|mut f| f.write_all(json.as_bytes()));
    }
}

pub fn get_or_run_scan(
    domain: &str,
    input: &GradeInput,
    certificate: &CertificateInfo,
    protocols: &ProtocolSupport,
    cipher_suites: &CipherSuiteInfo,
    vulnerabilities: &VulnerabilityInfo,
    key_exchange: &KeyExchangeInfo,
    whois_response: Option<&str>,
) -> (Grade, bool) {
    let mut cache = load_cache();
    let whois_info = whois_response.map(|resp| parse_whois_response(resp));
    if let Some(cached) = cache.get(domain) {
        if cached.details == *input {
            // Return cached result only if input matches
            return (cached.grade, true);
        }
        // Input changed, re-run scan and update cache
    }
    println!("[DEBUG] Grading input for domain {}: {:?}", domain, input);
    let mut grade = grade_site(input);
    let mut explanation = None;
    // WHOIS-based downgrade: if domain is younger than 30 days, downgrade to F
    if let Some(whois) = &whois_info {
        let mut reasons = Vec::new();
        if let Some(creation) = whois.creation_date {
            let now = Utc::now().naive_utc();
            let age_days = (now - creation).num_days();
            if age_days < 30 {
                println!(
                    "[DEBUG] Domain {} is {} days old, downgrading to F",
                    domain, age_days
                );
                grade = Grade::F;
                reasons.push(format!(
                    "Domain registered less than 30 days ago ({} days): suspicious for phishing.",
                    age_days
                ));
            }
        }
        // Check for privacy-protected registrant info
        if whois.raw.to_lowercase().contains("redacted for privacy")
            || whois.raw.to_lowercase().contains("privacy protection")
        {
            reasons.push(
                "WHOIS info is privacy-protected: may indicate suspicious or untrustworthy domain."
                    .to_string(),
            );
        }
        // Check for suspicious registrars (example list, expand as needed)
        let suspicious_registrars = [
            "NameCheap",
            "Alibaba",
            "Bizcn.com",
            "Eranet International",
            "PDR Ltd.",
        ];
        if let Some(registrar) = &whois.registrar {
            for bad in &suspicious_registrars {
                if registrar.to_lowercase().contains(&bad.to_lowercase()) {
                    reasons.push(format!(
                        "Registrar '{}' is known for hosting suspicious domains.",
                        registrar
                    ));
                }
            }
        }
        if !reasons.is_empty() {
            explanation = Some(reasons.join(" "));
        }
    }
    // Calculate actual certificate expiry if possible
    let mut cert_expiry_days = None;
    if let Some(valid_to) = &certificate.valid_to {
        // Try RFC3339, then common formats
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(valid_to, "%Y-%m-%dT%H:%M:%SZ") {
            let now = chrono::Utc::now().naive_utc();
            cert_expiry_days = Some((dt - now).num_days());
        } else if let Ok(date) = chrono::NaiveDate::parse_from_str(valid_to, "%Y-%m-%d") {
            let now = chrono::Utc::now().date_naive();
            cert_expiry_days = Some((date - now).num_days());
        }
    }
    let mut cert = certificate.clone();
    cert.days_until_expiry = cert_expiry_days;
    let entry = CachedScan {
        domain: domain.to_string(),
        grade,
        details: input.clone(),
        certificate: cert,
        protocols: protocols.clone(),
        cipher_suites: cipher_suites.clone(),
        vulnerabilities: vulnerabilities.clone(),
        key_exchange: key_exchange.clone(),
        whois: whois_info,
        explanation,
    };
    cache.insert(domain.to_string(), entry);
    save_cache(&cache);
    (grade, false)
}
