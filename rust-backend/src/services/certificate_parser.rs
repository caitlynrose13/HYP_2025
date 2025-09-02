use chrono;
use hex;
use serde::Serialize;
use x509_parser::{
    der_parser::der::parse_der_oid, extensions::GeneralName, prelude::*, public_key::PublicKey,
    time::ASN1Time,
};

// ==========
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

// ====================
// MAIN PARSING FUNCTION

//get the certificate information like subject, issuer, validity period, key size
pub fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate, String> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("Failed to parse certificate: {}", e))?;

    // Extract certificate fields
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
    // Get the public key info
    let public_key_info = cert.public_key();

    // Check the algorithm OID first
    let algorithm_oid = public_key_info.algorithm.algorithm.to_string();
    println!("Public key algorithm OID: {}", algorithm_oid);

    match public_key_info.parsed() {
        Ok(PublicKey::RSA(rsa_key)) => {
            let bit_size = rsa_key.key_size() * 8; // Convert bytes to bits
            println!("RSA key size: {} bits", bit_size);
            Some(bit_size.to_string())
        }
        Ok(PublicKey::EC(ec_key)) => {
            // For EC keys, we need to look at the algorithm parameters
            extract_ec_key_size_improved(&public_key_info, &algorithm_oid)
        }
        Ok(other_key) => {
            println!("Other key type: {:?}", other_key);
            // For other key types, try to determine from algorithm OID
            determine_key_size_from_oid(&algorithm_oid)
        }
        Err(e) => {
            println!("Failed to parse public key: {}", e);
            // Try to determine from algorithm OID as fallback
            determine_key_size_from_oid(&algorithm_oid)
        }
    }
}

/// Improved EC key size extraction using algorithm parameters
fn extract_ec_key_size_improved(
    public_key_info: &x509_parser::x509::SubjectPublicKeyInfo,
    algorithm_oid: &str,
) -> Option<String> {
    // Check if we have algorithm parameters
    if let Some(params) = &public_key_info.algorithm.parameters {
        println!(
            "EC algorithm parameters present: {} bytes",
            params.data.len()
        );

        // Try to parse the parameters as an OID (curve identifier)
        if let Ok((_, ber_object)) = parse_der_oid(params.data) {
            if let Ok(curve_oid) = ber_object.as_oid() {
                let curve_oid_str = curve_oid.to_string();
                println!("EC curve OID: {}", curve_oid_str);

                // Map common curve OIDs to key sizes
                match curve_oid_str.as_str() {
                    "1.2.840.10045.3.1.7" => {
                        // secp256r1 (P-256)
                        println!("Detected P-256 curve");
                        Some("256".to_string())
                    }
                    "1.3.132.0.34" => {
                        // secp384r1 (P-384)
                        println!("Detected P-384 curve");
                        Some("384".to_string())
                    }
                    "1.3.132.0.35" => {
                        // secp521r1 (P-521)
                        println!("Detected P-521 curve");
                        Some("521".to_string())
                    }
                    _ => {
                        println!("Unknown EC curve OID: {}", curve_oid_str);
                        // Default to 256 for unknown curves as it's most common
                        Some("256".to_string())
                    }
                }
            } else {
                println!("Failed to extract OID from BER object");
                Some("256".to_string()) // Default assumption
            }
        } else {
            // NEW: Try alternative parsing for 8-byte parameters
            println!("Standard OID parsing failed, trying alternative methods");

            // For 8-byte parameters, often it's P-256 curve
            if params.data.len() == 8 {
                println!("8-byte EC parameters detected - likely P-256 curve");
                Some("256".to_string())
            } else {
                println!("Failed to parse EC curve OID from parameters");
                Some("256".to_string()) // Default assumption
            }
        }
    } else {
        println!("No EC algorithm parameters found");
        Some("256".to_string()) // Default assumption
    }
}

/// Determine key size from algorithm OID as fallback
fn determine_key_size_from_oid(algorithm_oid: &str) -> Option<String> {
    match algorithm_oid {
        "1.2.840.10045.2.1" => {
            // ecPublicKey - generic EC, assume P-256
            println!("Generic EC public key, assuming 256 bits");
            Some("256".to_string())
        }
        "1.2.840.113549.1.1.1" => {
            // rsaEncryption - can't determine size without parsing the key
            println!("RSA encryption algorithm, size unknown");
            Some("2048".to_string()) // Common default
        }
        _ => {
            println!("Unknown algorithm OID: {}", algorithm_oid);
            Some("unknown".to_string())
        }
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

/// Calculate days until certificate expiry
pub fn calculate_days_until_expiry(valid_to: &str) -> Option<i64> {
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(valid_to, "%Y-%m-%dT%H:%M:%SZ") {
        let now = chrono::Utc::now().naive_utc();
        let days = (dt - now).num_days();
        Some(days)
    } else if let Ok(date) = chrono::NaiveDate::parse_from_str(valid_to, "%Y-%m-%d") {
        let now = chrono::Utc::now().date_naive();
        let days = (date - now).num_days();
        Some(days)
    } else {
        None
    }
}
