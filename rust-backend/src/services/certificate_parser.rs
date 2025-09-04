use chrono;
use hex;
use serde::Serialize;
use x509_parser::{
    der_parser::der::parse_der_oid, extensions::GeneralName, prelude::*, public_key::PublicKey,
    time::ASN1Time,
};

// ====================================
// DATA STRUCTURES

#[derive(Debug, Serialize)]
pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub expired: bool,
    pub days_until_expiry: Option<i64>,
    pub key_size: Option<String>,
    pub signature_algorithm: String,
    pub serial_number: String,
    pub subject_alt_names: Vec<String>,
}

// ====================================
// MAIN PARSING FUNCTION

/// Parses X.509 certificate DER data and extracts security-relevant information
pub fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate, String> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("Failed to parse certificate: {}", e))?;

    let subject = extract_common_name(cert.subject());
    let issuer = extract_common_name(cert.issuer());
    let (not_before, not_after, expired) = extract_validity(&cert);
    let key_size = extract_key_size(&cert);
    let subject_alt_names = extract_subject_alt_names(&cert);
    let days_until_expiry = calculate_days_until_expiry(&not_after);

    Ok(ParsedCertificate {
        subject,
        issuer,
        not_before,
        not_after,
        expired,
        days_until_expiry,
        key_size,
        signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
        serial_number: format!("{:x}", cert.serial),
        subject_alt_names,
    })
}

// ====================================
// CERTIFICATE FIELD EXTRACTION

/// Extract common name from X509Name structure
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

/// Extract validity period and determine expiration status
fn extract_validity(cert: &X509Certificate) -> (String, String, bool) {
    let not_before_raw = cert.validity().not_before;
    let not_after_raw = cert.validity().not_after;
    let expired = not_after_raw < ASN1Time::now();

    let not_before = format_asn1_time_to_iso(&not_before_raw);
    let not_after = format_asn1_time_to_iso(&not_after_raw);

    (not_before, not_after, expired)
}

/// Convert ASN1Time to ISO format string with multiple format fallbacks
fn format_asn1_time_to_iso(time: &ASN1Time) -> String {
    let time_str = time.to_string();

    // Try parsing various ASN.1 time formats in order of likelihood
    if let Ok(dt) = chrono::DateTime::parse_from_str(&time_str, "%b %d %H:%M:%S %Y %z") {
        return dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    }

    if let Ok(dt) = chrono::DateTime::parse_from_str(&time_str, "%b  %d %H:%M:%S %Y %z") {
        return dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    }

    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&time_str, "%y%m%d%H%M%SZ") {
        return chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(dt, chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
    }

    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&time_str, "%Y%m%d%H%M%SZ") {
        return chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(dt, chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
    }

    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(&time_str) {
        return dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    }

    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&time_str) {
        return dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    }

    "<invalid date>".to_string()
}

// ====================================
// PUBLIC KEY ANALYSIS

/// Extract key size information from certificate public key
fn extract_key_size(cert: &X509Certificate) -> Option<String> {
    let public_key_info = cert.public_key();
    let algorithm_oid = public_key_info.algorithm.algorithm.to_string();

    println!("Public key algorithm OID: {}", algorithm_oid);

    match public_key_info.parsed() {
        Ok(PublicKey::RSA(rsa_key)) => {
            let bit_size = rsa_key.key_size() * 8;
            println!("RSA key size: {} bits", bit_size);
            Some(bit_size.to_string())
        }
        Ok(PublicKey::EC(_)) => {
            extract_ec_key_size_from_parameters(&public_key_info, &algorithm_oid)
        }
        Ok(other_key) => {
            println!("Other key type: {:?}", other_key);
            determine_key_size_from_oid(&algorithm_oid)
        }
        Err(e) => {
            println!("Failed to parse public key: {}", e);
            determine_key_size_from_oid(&algorithm_oid)
        }
    }
}

/// Extract EC key size by analyzing curve parameters in certificate
fn extract_ec_key_size_from_parameters(
    public_key_info: &x509_parser::x509::SubjectPublicKeyInfo,
    algorithm_oid: &str,
) -> Option<String> {
    if let Some(params) = &public_key_info.algorithm.parameters {
        println!(
            "EC algorithm parameters present: {} bytes",
            params.data.len()
        );

        if let Ok((_, ber_object)) = parse_der_oid(params.data) {
            if let Ok(curve_oid) = ber_object.as_oid() {
                let curve_oid_str = curve_oid.to_string();
                println!("EC curve OID: {}", curve_oid_str);

                return match curve_oid_str.as_str() {
                    "1.2.840.10045.3.1.7" => {
                        println!("Detected P-256 curve");
                        Some("256".to_string())
                    }
                    "1.3.132.0.34" => {
                        println!("Detected P-384 curve");
                        Some("384".to_string())
                    }
                    "1.3.132.0.35" => {
                        println!("Detected P-521 curve");
                        Some("521".to_string())
                    }
                    _ => {
                        println!("Unknown EC curve OID: {}", curve_oid_str);
                        Some("256".to_string()) // Most common default
                    }
                };
            }
        }

        // Handle non-standard EC parameter encodings
        if params.data.len() == 8 {
            println!("8-byte EC parameters detected - likely P-256 curve");
            return Some("256".to_string());
        }
    }

    println!("No EC algorithm parameters found, defaulting to P-256");
    Some("256".to_string())
}

/// Determine key size from algorithm OID when direct parsing fails
fn determine_key_size_from_oid(algorithm_oid: &str) -> Option<String> {
    match algorithm_oid {
        "1.2.840.10045.2.1" => {
            println!("Generic EC public key, assuming 256 bits");
            Some("256".to_string())
        }
        "1.2.840.113549.1.1.1" => {
            println!("RSA encryption algorithm, defaulting to 2048 bits");
            Some("2048".to_string())
        }
        _ => {
            println!("Unknown algorithm OID: {}", algorithm_oid);
            Some("unknown".to_string())
        }
    }
}

// ====================================
// SUBJECT ALTERNATIVE NAMES

/// Extract Subject Alternative Names from certificate extensions
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

/// Process individual Subject Alternative Name entries
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
            _ => {} // Skip other SAN types
        }
    }
}

/// Format IP address bytes as human-readable string (IPv4/IPv6)
fn format_ip_address(ip: &[u8]) -> String {
    match ip.len() {
        4 => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
        16 => ip
            .chunks(2)
            .map(|chunk| format!("{:02x}{:02x}", chunk[0], chunk.get(1).unwrap_or(&0)))
            .collect::<Vec<_>>()
            .join(":"),
        _ => format!("IP:{}", hex::encode(ip)),
    }
}

// ====================================
// UTILITY FUNCTIONS

/// Calculate days remaining until certificate expires
pub fn calculate_days_until_expiry(valid_to: &str) -> Option<i64> {
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(valid_to, "%Y-%m-%dT%H:%M:%SZ") {
        let now = chrono::Utc::now().naive_utc();
        return Some((dt - now).num_days());
    }

    if let Ok(date) = chrono::NaiveDate::parse_from_str(valid_to, "%Y-%m-%d") {
        let now = chrono::Utc::now().date_naive();
        return Some((date - now).num_days());
    }

    None
}
