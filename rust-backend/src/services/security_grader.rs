use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;

// Import types from assessment_handler
use crate::handlers::assessment_handler::{
    CertificateInfo, CipherSuiteInfo, KeyExchangeInfo, ProtocolSupport, VulnerabilityInfo,
};

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
    pub cert_expired: bool,
    pub cert_key_strength_ok: bool,
    pub hsts: bool,
    pub forward_secrecy: bool,
    pub weak_protocols_disabled: bool,
    pub ocsp_stapling_enabled: bool,
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

/// Parses WHOIS response for creation date and registrar (simple version)
pub fn parse_whois_response(response: &str) -> WhoisInfo {
    let mut creation_date = None;
    let mut registrar = None;
    for line in response.lines() {
        if line.to_lowercase().contains("creation date") {
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

/// Returns a technical grade and explanation based on SSL Labs-like logic.
pub fn grade_site(input: &GradeInput, certificate: &CertificateInfo) -> (Grade, Vec<String>) {
    let mut score = 100;
    let mut reasons = Vec::new();

    // TLS/SSL Protocol and Version
    if !input.tls13_supported {
        score -= 10;
        reasons.push("Does not support TLS 1.3.".to_string());
    }
    if !input.tls12_supported {
        score = 0;
        reasons.push("Does not support TLS 1.2 or higher.".to_string());
        return (Grade::F, reasons);
    }
    if input.tls10_supported || input.tls11_supported {
        score -= 20;
        reasons.push("Supports obsolete TLS 1.0 or 1.1.".to_string());
    }
    if !input.weak_protocols_disabled {
        score -= 5;
        reasons.push("Weak protocols (TLS 1.0/1.1) not explicitly disabled.".to_string());
    }

    // Certificate Details
    if !input.cert_valid {
        score = 0;
        reasons.push("Certificate is invalid.".to_string());
        return (Grade::F, reasons);
    } else if input.cert_expired {
        score = 0;
        reasons.push("Certificate is expired.".to_string());
        return (Grade::F, reasons);
    }
    if !input.cert_key_strength_ok {
        score -= 15;
        reasons.push("Certificate uses a weak key (e.g., < 2048-bit).".to_string());
    }

    // Cipher Suite
    if !input.cipher_is_strong {
        score -= 25;
        reasons.push("Uses a weak or non-recommended cipher suite.".to_string());
    }

    // Additional Security Headers and Features
    if !input.hsts {
        score -= 10;
        reasons.push("HTTP Strict Transport Security (HSTS) is not enabled.".to_string());
    }
    if !input.forward_secrecy {
        score -= 15;
        reasons.push("Perfect Forward Secrecy is not enabled.".to_string());
    }
    if !input.ocsp_stapling_enabled {
        score -= 5;
        reasons.push("OCSP Stapling is not enabled.".to_string());
    }

    // Final grade mapping
    let grade = if score >= 95 {
        Grade::APlus
    } else if score >= 85 {
        Grade::A
    } else if score >= 70 {
        Grade::AMinus
    } else if score >= 50 {
        Grade::B
    } else if score >= 20 {
        Grade::C
    } else {
        Grade::F
    };

    (grade, reasons)
}

/// Combines technical grade with WHOIS-based downgrades and explanations.
pub fn get_or_run_scan(
    domain: &str,
    input: &GradeInput,
    certificate: &CertificateInfo,
    protocols: &ProtocolSupport,
    cipher_suites: &CipherSuiteInfo,
    vulnerabilities: &VulnerabilityInfo,
    key_exchange: &KeyExchangeInfo,
    whois_response: Option<&str>,
) -> (Grade, Option<String>) {
    let whois_info = whois_response.map(|resp| parse_whois_response(resp));

    println!("[DEBUG] Grading input for domain {}: {:?}", domain, input);
    let (mut grade, mut reasons) = grade_site(input, certificate);
    let mut explanation = None;

    // WHOIS-based downgrade: if domain is younger than 30 days, downgrade to F
    if let Some(whois) = &whois_info {
        let mut reasons = Vec::new();
        if let Some(creation) = whois.creation_date {
            let now = chrono::Utc::now().naive_utc();
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
    (grade, explanation)
}
