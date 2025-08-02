use chrono;
use hex;
use serde::Serialize;
use x509_parser::{extensions::GeneralName, prelude::*, public_key::PublicKey, time::ASN1Time};

// ==========
// DATA STRUCTURES

#[derive(Debug, Serialize)]
pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub expired: bool,
    pub key_size: Option<String>,
    pub signature_algorithm: String,
    pub serial_number: String,
    pub subject_alt_names: Vec<String>,
}

// ====================
// MAIN PARSING FUNCTION

pub fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate, String> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("Failed to parse certificate: {}", e))?;

    // Extract certificate fields
    let subject = extract_common_name(cert.subject());
    let issuer = extract_common_name(cert.issuer());
    let (not_before, not_after, expired) = extract_validity(&cert);
    let key_size = extract_key_size(&cert);
    let subject_alt_names = extract_subject_alt_names(&cert);

    Ok(ParsedCertificate {
        subject,
        issuer,
        not_before,
        not_after,
        expired,
        key_size,
        signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
        serial_number: format!("{:x}", cert.serial),
        subject_alt_names,
    })
}

// =========================
// HELPER FUNCTIONS

/// Extract common name from X509Name
fn extract_common_name(name: &x509_parser::x509::X509Name) -> String {
    name.iter_common_name()
        .next()
        .map(|cn| {
            cn.as_str()
                .ok()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "<invalid CN>".to_string())
        })
        .unwrap_or_else(|| "<no CN>".to_string())
}

/// Extract validity period and check if expired
fn extract_validity(cert: &X509Certificate) -> (String, String, bool) {
    let not_before_raw = cert.validity().not_before;
    let not_after_raw = cert.validity().not_after;
    let expired = not_after_raw < ASN1Time::now();

    // Convert to ISO format for consistency with calculate_days_until_expiry
    let not_before = format_asn1_time_to_iso(&not_before_raw);
    let not_after = format_asn1_time_to_iso(&not_after_raw);

    (not_before, not_after, expired)
}

/// Convert ASN1Time to ISO format string
fn format_asn1_time_to_iso(time: &ASN1Time) -> String {
    // Convert ASN1Time to string first
    let time_str = time.to_string();

    // Try to parse the new format: "Jul  7 08:34:03 2025 +00:00"
    if let Ok(dt) = chrono::DateTime::parse_from_str(&time_str, "%b %d %H:%M:%S %Y %z") {
        let result = dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        return result;
    }

    // Try alternative format with double space: "Jul  7 08:34:03 2025 +00:00"
    if let Ok(dt) = chrono::DateTime::parse_from_str(&time_str, "%b  %d %H:%M:%S %Y %z") {
        let result = dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        return result;
    }

    // Try to parse common ASN.1 time formats
    // Format 1: "YYMMDDHHMMSSZ" (YY format)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&time_str, "%y%m%d%H%M%SZ") {
        let result = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(dt, chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        return result;
    }

    // Format 2: "YYYYMMDDHHMMSSZ" (YYYY format)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&time_str, "%Y%m%d%H%M%SZ") {
        let result = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(dt, chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        return result;
    }

    // Format 3: Try RFC2822 format
    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(&time_str) {
        let result = dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        return result;
    }

    // Format 4: Try RFC3339/ISO format
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&time_str) {
        let result = dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        return result;
    }

    "<invalid date>".to_string()
}

/// Extract key size from public key
fn extract_key_size(cert: &X509Certificate) -> Option<String> {
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa_key)) => {
            let bit_size = rsa_key.key_size() * 8; // Convert bytes to bits
            Some(bit_size.to_string())
        }
        Ok(PublicKey::EC(ec_key)) => extract_ec_key_size(&ec_key),
        _ => None,
    }
}

/// Extract EC key size based on curve
fn extract_ec_key_size(ec_key: &x509_parser::public_key::ECPoint) -> Option<String> {
    let curve_info = format!("{:?}", ec_key);

    if curve_info.contains("P-256") || curve_info.contains("secp256r1") {
        Some("256".to_string())
    } else if curve_info.contains("P-384") || curve_info.contains("secp384r1") {
        Some("384".to_string())
    } else if curve_info.contains("P-521") || curve_info.contains("secp521r1") {
        Some("521".to_string())
    } else {
        Some("unknown".to_string())
    }
}

/// Extract Subject Alternative Names
fn extract_subject_alt_names(cert: &X509Certificate) -> Vec<String> {
    let mut san_list = Vec::new();

    for extension in cert.extensions() {
        if extension.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME {
            if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
                extract_san_entries(&san.general_names, &mut san_list);
            }
            break;
        }
    }

    san_list
}

/// Extract individual SAN entries
fn extract_san_entries(general_names: &[GeneralName], san_list: &mut Vec<String>) {
    for name in general_names {
        match name {
            GeneralName::DNSName(dns) => {
                san_list.push(dns.to_string());
            }
            GeneralName::IPAddress(ip) => {
                san_list.push(format_ip_address(ip));
            }
            GeneralName::URI(uri) => {
                san_list.push(uri.to_string());
            }
            GeneralName::RFC822Name(email) => {
                san_list.push(email.to_string());
            }
            _ => {} // Skip other types
        }
    }
}

/// Format IP address (IPv4 or IPv6)
fn format_ip_address(ip: &[u8]) -> String {
    match ip.len() {
        4 => {
            // IPv4
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        16 => {
            // IPv6
            ip.chunks(2)
                .map(|chunk| format!("{:02x}{:02x}", chunk[0], chunk.get(1).unwrap_or(&0)))
                .collect::<Vec<_>>()
                .join(":")
        }
        _ => {
            // Unknown format, use hex encoding
            format!("IP:{}", hex::encode(ip))
        }
    }
}
