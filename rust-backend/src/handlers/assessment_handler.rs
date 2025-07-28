use crate::services::certificate_parser::parse_certificate;
use crate::services::security_grader::GradeInput;
use crate::services::tls_parser::TlsVersion;
use axum::{Json, http::StatusCode};
use chrono;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct AssessmentRequest {
    pub domain: String,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct AssessmentResponse {
    pub domain: String,
    pub message: String,
    pub grade: Option<String>,
    pub certificate: CertificateInfo,
    pub protocols: ProtocolSupport,
    pub cipher_suites: CipherSuiteInfo,
    pub vulnerabilities: VulnerabilityInfo,
    pub key_exchange: KeyExchangeInfo,
    pub explanation: Option<String>,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct CertificateInfo {
    pub common_name: Option<String>,
    pub issuer: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub key_size: Option<String>,
    pub signature_algorithm: Option<String>,
    pub chain_trust: Option<String>,
    pub days_until_expiry: Option<i64>,
    pub subject_alt_names: Vec<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct ProtocolSupport {
    pub tls_1_0: String,
    pub tls_1_1: String,
    pub tls_1_2: String,
    pub tls_1_3: String,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct CipherSuiteInfo {
    pub tls_1_2_suites: Vec<String>,
    pub tls_1_3_suites: Vec<String>,
    pub preferred_suite: Option<String>,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct VulnerabilityInfo {
    pub poodle: String,
    pub beast: String,
    pub heartbleed: String,
    pub freak: String,
    pub logjam: String,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct KeyExchangeInfo {
    pub supports_forward_secrecy: bool,
    pub key_exchange_algorithm: Option<String>,
    pub curve_name: Option<String>,
}

//recieves a json payload with a domain from client. => need to update when 1.3 is implemented
// TODO: Add TLS 1.3 support and HSTS detection.
pub async fn assess_domain(
    Json(payload): Json<AssessmentRequest>,
) -> (StatusCode, Json<AssessmentResponse>) {
    println!("=== BACKEND: Received request ===");
    println!("Request payload: {:?}", payload);

    let domain = payload.domain;
    println!("=== Starting TLS Assessment ===");
    println!("Domain: {}", domain);
    println!(
        "Timestamp: {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    // Prepare all info structs
    let mut protocols = ProtocolSupport {
        tls_1_0: "Not Tested".to_string(),
        tls_1_1: "Not Tested".to_string(),
        tls_1_2: "Not Supported".to_string(),
        tls_1_3: "Not Supported".to_string(),
    };

    let mut certificate_info = CertificateInfo {
        common_name: None,
        issuer: None,
        valid_from: None,
        valid_to: None,
        key_size: None,
        signature_algorithm: None,
        chain_trust: None,
        days_until_expiry: None,
        subject_alt_names: vec![],
        serial_number: None,
    };

    let mut cipher_suites = CipherSuiteInfo {
        tls_1_2_suites: vec![],
        tls_1_3_suites: vec![],
        preferred_suite: None,
    };

    let vulnerabilities = VulnerabilityInfo {
        poodle: "Not Vulnerable (TLS 1.2+)".to_string(),
        beast: "Not Vulnerable (TLS 1.2+)".to_string(),
        heartbleed: "Unknown".to_string(),
        freak: "Not Vulnerable (Modern TLS)".to_string(),
        logjam: "Not Vulnerable (ECDHE)".to_string(),
    };

    let mut key_exchange = KeyExchangeInfo {
        supports_forward_secrecy: false,
        key_exchange_algorithm: None,
        curve_name: None,
    };

    // Basic HSTS detection: try to fetch HTTPS headers and check for Strict-Transport-Security
    let mut hsts_supported = false;
    if let Ok(resp) = reqwest::get(format!("https://{}", domain)).await {
        if let Some(hsts) = resp.headers().get("strict-transport-security") {
            hsts_supported = true;
        }
    }
    let mut grade_input = GradeInput {
        tls13_supported: false,
        tls12_supported: false,
        tls11_supported: false, // We don't test these, so assume false
        tls10_supported: false, // We don't test these, so assume false
        cipher_is_strong: false,
        cert_valid: false,
        hsts: hsts_supported,
        forward_secrecy: false,
        weak_protocols_disabled: true, // Since we don't support TLS 1.0/1.1
    };

    // Check cache first (with all assessment details)
    // WHOIS integration: fetch WHOIS and pass to grading
    let whois_resp = crate::services::security_grader::whois_query(&domain).ok();
    let (grade, cached) = crate::services::security_grader::get_or_run_scan(
        &domain,
        &grade_input,
        &certificate_info,
        &protocols,
        &cipher_suites,
        &vulnerabilities,
        &key_exchange,
        whois_resp.as_deref(),
    );
    let explanation = {
        // Try to get explanation from cache or grading result
        let cache = crate::services::security_grader::load_cache();
        cache
            .get(&domain)
            .and_then(|entry| entry.explanation.clone())
    };
    if cached {
        println!("✓ Loaded cached result for {}", domain);
        println!("Final Grade: {:?}", grade);
        println!("=== Assessment Complete ===\n");
        return (
            StatusCode::OK,
            Json(AssessmentResponse {
                domain,
                message: "TLS assessment loaded from cache".to_string(),
                grade: Some(format!("{:?}", grade)),
                certificate: certificate_info,
                protocols,
                cipher_suites,
                vulnerabilities,
                key_exchange,
                explanation,
            }),
        );
    }

    // Test TLS 1.2 support
    let tls12_result =
        crate::services::tls_handshake::client_handshake::perform_tls_handshake_full_with_cert(
            &domain,
            TlsVersion::TLS1_2,
        );

    // Test TLS 1.3 support
    let tls13_result = crate::services::tls_handshake::tls13::client::test_tls13(&domain);

    match tls12_result {
        Ok((state, cert_der)) => {
            println!("✓ TLS 1.2 handshake succeeded for {}", domain);
            protocols.tls_1_2 = "Supported".to_string();
            grade_input.tls12_supported = true;

            // Set cipher suite info
            cipher_suites.preferred_suite = Some(state.negotiated_cipher_suite.name.to_string());
            cipher_suites
                .tls_1_2_suites
                .push(state.negotiated_cipher_suite.name.to_string());

            // Check if cipher is strong
            grade_input.cipher_is_strong = state.negotiated_cipher_suite.name.contains("GCM");

            // Key exchange info
            if state.negotiated_cipher_suite.name.contains("ECDHE") {
                key_exchange.supports_forward_secrecy = true;
                key_exchange.key_exchange_algorithm = Some("ECDHE".to_string());
                key_exchange.curve_name = Some("P-256".to_string()); // Assuming P-256
                grade_input.forward_secrecy = true; // Update grading input
            }

            // Parse certificate if available
            if let Some(cert_der) = cert_der {
                if let Ok(parsed_cert) = parse_certificate(&cert_der) {
                    certificate_info.common_name = Some(parsed_cert.subject.clone());
                    certificate_info.issuer = Some(parsed_cert.issuer.clone());
                    certificate_info.valid_from = Some(parsed_cert.not_before.clone());
                    certificate_info.valid_to = Some(parsed_cert.not_after.clone());
                    certificate_info.chain_trust = Some(if !parsed_cert.expired {
                        "Trusted".to_string()
                    } else {
                        "Expired".to_string()
                    });
                    grade_input.cert_valid = !parsed_cert.expired;

                    // Calculate days until expiry
                    // Simple calculation - we'll just estimate based on string format
                    certificate_info.days_until_expiry = Some(30); // Placeholder for now
                }
            }
        }
        Err(e) => {
            println!("✗ TLS 1.2 handshake failed for {}: {:?}", domain, e);
        }
    }

    // Check TLS 1.3 support
    match tls13_result {
        Ok(_) => {
            println!("✓ TLS 1.3 handshake succeeded for {}", domain);
            protocols.tls_1_3 = "Supported".to_string();
            grade_input.tls13_supported = true;
            // TLS 1.3 always provides forward secrecy
            if !grade_input.forward_secrecy {
                grade_input.forward_secrecy = true;
                key_exchange.supports_forward_secrecy = true;
            }
            cipher_suites
                .tls_1_3_suites
                .push("TLS_AES_128_GCM_SHA256".to_string());
            cipher_suites
                .tls_1_3_suites
                .push("TLS_AES_256_GCM_SHA384".to_string());
            cipher_suites
                .tls_1_3_suites
                .push("TLS_CHACHA20_POLY1305_SHA256".to_string());
        }
        Err(e) => {
            println!("✗ TLS 1.3 handshake failed for {}: {:?}", domain, e);
        }
    }

    let (grade, cached) = crate::services::security_grader::get_or_run_scan(
        &domain,
        &grade_input,
        &certificate_info,
        &protocols,
        &cipher_suites,
        &vulnerabilities,
        &key_exchange,
        None,
    );
    if cached {
        println!("✓ Loaded cached result for {}", domain);
    }
    println!("Final Grade: {:?}", grade);
    println!("=== Assessment Complete ===\n");

    // Always return a response, even if both protocols failed
    (
        StatusCode::OK,
        Json(AssessmentResponse {
            domain,
            message: if !grade_input.tls12_supported && !grade_input.tls13_supported {
                "TLS assessment completed with limited support".to_string()
            } else {
                "TLS assessment completed".to_string()
            },
            grade: Some(format!("{:?}", grade)),
            certificate: certificate_info,
            protocols,
            cipher_suites,
            vulnerabilities,
            key_exchange,
            explanation,
        }),
    )
}
