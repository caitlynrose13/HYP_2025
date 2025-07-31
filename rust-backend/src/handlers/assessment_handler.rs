use crate::AppState;
use crate::db;
use crate::db::insert_scan;
use crate::services::certificate_parser::parse_certificate;
use crate::services::openssl_probe::{test_tls10, test_tls11};
use crate::services::security_grader::GradeInput;
use crate::services::tls_parser::TlsVersion;
use axum::{Json, extract::State, http::StatusCode};
use chrono;
use serde::{Deserialize, Serialize}; // If you have a global pool, otherwise pass it in

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
    pub tls_scan_duration: Option<String>,
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
    State(state): State<AppState>,
    Json(payload): Json<AssessmentRequest>,
) -> (StatusCode, Json<AssessmentResponse>) {
    let scan_start = std::time::Instant::now();

    println!("=== BACKEND: Received request ===");
    println!("Request payload: {:?}", payload);

    let domain = payload.domain;
    println!("=== Starting TLS Assessment ===");
    println!("Domain: {}", domain);
    println!(
        "Timestamp: {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    // Check cache/database first
    let cached_record = match db::get_recent_scan(&state.pool, &domain).await {
        Ok(record) => record,
        Err(e) => {
            eprintln!("DB error: {:?}", e);
            None
        }
    };
    if let Some(record) = cached_record {
        println!("✓ Loaded scan from database for {}", domain);
        return (
            StatusCode::OK,
            Json(AssessmentResponse {
                domain: record.domain,
                message: "TLS assessment loaded from cache".to_string(),
                grade: Some(record.grade),
                certificate: serde_json::from_str(&record.certificate_json).unwrap(),
                protocols: serde_json::from_str(&record.protocols_json).unwrap(),
                cipher_suites: serde_json::from_str(&record.cipher_suites_json).unwrap(),
                vulnerabilities: serde_json::from_str(&record.vulnerabilities_json).unwrap(),
                key_exchange: serde_json::from_str(&record.key_exchange_json).unwrap(),
                explanation: record.explanation,
                tls_scan_duration: record.tls_scan_duration,
            }),
        );
    }
    println!(
        "No recent scan found in database for {}, running new assessment...",
        domain
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

    let mut key_exchange = KeyExchangeInfo {
        supports_forward_secrecy: false,
        key_exchange_algorithm: None,
        curve_name: None,
    };
    // Basic HSTS detection
    let mut hsts_supported = false;
    if let Ok(resp) = reqwest::get(format!("https://{}", domain)).await {
        if let Some(_hsts) = resp.headers().get("strict-transport-security") {
            hsts_supported = true;
        }
    }
    let mut grade_input = GradeInput {
        tls13_supported: false,
        tls12_supported: false,
        tls11_supported: false,
        tls10_supported: false,
        cipher_is_strong: false,
        cert_valid: false,
        hsts: hsts_supported,
        forward_secrecy: false,
        weak_protocols_disabled: true,
    };

    // WHOIS integration: fetch WHOIS and pass to grading
    let whois_resp = crate::services::security_grader::whois_query(&domain).ok();

    // Test TLS 1.2 support
    let tls12_result =
        crate::services::tls_handshake::client_handshake::perform_tls_handshake_full_with_cert(
            &domain,
            TlsVersion::TLS1_2,
        );

    // --- TLS 1.2 ---
    match tls12_result {
        Ok((state, cert_der)) => {
            println!("✓ TLS 1.2 handshake succeeded for {}", domain);
            protocols.tls_1_2 = "Supported".to_string();
            grade_input.tls12_supported = true;

            // Use the negotiated cipher suite bytes and map to name
            let suite_name = crate::services::tls_parser::get_cipher_suite_name(
                &state.negotiated_cipher_suite.id,
            );
            cipher_suites.preferred_suite = Some(suite_name.clone());
            cipher_suites.tls_1_2_suites.push(suite_name.clone());

            grade_input.cipher_is_strong = suite_name.contains("GCM");

            if suite_name.contains("ECDHE") {
                grade_input.forward_secrecy = true;
                key_exchange.supports_forward_secrecy = true;
                key_exchange.key_exchange_algorithm = Some("ECDHE".to_string());
                key_exchange.curve_name = Some("P-256".to_string());
            }

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

                    // Calculate days until expiry (TLS 1.2)
                    if let Some(valid_to) = &certificate_info.valid_to {
                        if let Ok(dt) =
                            chrono::NaiveDateTime::parse_from_str(valid_to, "%Y-%m-%dT%H:%M:%SZ")
                        {
                            let now = chrono::Utc::now().naive_utc();
                            certificate_info.days_until_expiry = Some((dt - now).num_days());
                        } else if let Ok(date) =
                            chrono::NaiveDate::parse_from_str(valid_to, "%Y-%m-%d")
                        {
                            let now = chrono::Utc::now().date_naive();
                            certificate_info.days_until_expiry = Some((date - now).num_days());
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("✗ TLS 1.2 handshake failed for {}: {:?}", domain, e);
        }
    }

    // Test TLS 1.3 support
    let tls13_result =
        crate::services::tls_handshake::tls13::client::perform_tls13_handshake_minimal(&domain);

    // --- TLS 1.3 ---
    match tls13_result {
        Ok((state, Some(cert_der))) => {
            println!("TLS 1.3 handshake succeeded for {}", domain);
            protocols.tls_1_3 = "Supported".to_string();
            grade_input.tls13_supported = true;
            if !grade_input.forward_secrecy {
                grade_input.forward_secrecy = true;
                key_exchange.supports_forward_secrecy = true;
            }

            // Get the negotiated cipher suite name from the handshake state
            let suite_name =
                crate::services::tls_parser::get_cipher_suite_name(&state.negotiated_cipher_suite);
            cipher_suites.preferred_suite = Some(suite_name.clone());
            cipher_suites.tls_1_3_suites.push(suite_name);

            // --- TLS 1.3 certificate parsing and expiry calculation ---
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

                // Calculate days until expiry (TLS 1.3)
                if let Some(valid_to) = &certificate_info.valid_to {
                    if let Ok(dt) =
                        chrono::NaiveDateTime::parse_from_str(valid_to, "%Y-%m-%dT%H:%M:%SZ")
                    {
                        let now = chrono::Utc::now().naive_utc();
                        certificate_info.days_until_expiry = Some((dt - now).num_days());
                    } else if let Ok(date) = chrono::NaiveDate::parse_from_str(valid_to, "%Y-%m-%d")
                    {
                        let now = chrono::Utc::now().date_naive();
                        certificate_info.days_until_expiry = Some((date - now).num_days());
                    }
                }
            }
        }
        Ok((_, None)) => {
            println!("No certificate found in TLS 1.3 handshake");
        }
        Err(e) => {
            println!("TLS 1.3 handshake failed: {:?}", e);
        }
    }

    // Check TLS 1.0 and 1.1 support
    protocols.tls_1_0 = if test_tls10(&domain) {
        grade_input.tls10_supported = true;
        "Supported".to_string()
    } else {
        "Not Supported".to_string()
    };
    protocols.tls_1_1 = if test_tls11(&domain) {
        grade_input.tls11_supported = true;
        "Supported".to_string()
    } else {
        "Not Supported".to_string()
    };

    // Dynamic vulnerability checks
    let poodle_status = if protocols.tls_1_0 == "Supported" {
        "Potentially Vulnerable".to_string()
    } else {
        "Not Vulnerable".to_string()
    };

    let beast_status = if protocols.tls_1_0 == "Supported" {
        "Potentially Vulnerable".to_string()
    } else {
        "Not Vulnerable".to_string()
    };

    // Heartbleed left as "Unknown" for now
    let heartbleed_status = "Unknown".to_string();

    let freak_status = if cipher_suites
        .tls_1_2_suites
        .iter()
        .any(|s| s.contains("EXPORT"))
    {
        "Potentially Vulnerable".to_string()
    } else {
        "Not Vulnerable".to_string()
    };

    let logjam_status = if let Some(suite) = &cipher_suites.preferred_suite {
        if suite.contains("ECDHE") {
            "Not Vulnerable".to_string()
        } else {
            "Potentially Vulnerable".to_string()
        }
    } else {
        "Unknown".to_string()
    };

    let vulnerabilities = VulnerabilityInfo {
        poodle: poodle_status,
        beast: beast_status,
        heartbleed: heartbleed_status,
        freak: freak_status,
        logjam: logjam_status,
    };

    let (grade, explanation) = crate::services::security_grader::get_or_run_scan(
        &domain,
        &grade_input,
        &certificate_info,
        &protocols,
        &cipher_suites,
        &vulnerabilities,
        &key_exchange,
        whois_resp.as_deref(),
    );

    println!("Final Grade: {:?}", grade);
    println!("=== Assessment Complete ===\n");

    let scan_duration = scan_start.elapsed().as_secs_f32();
    let scan_duration_str = format!("{:.2}s", scan_duration);

    // Insert scan record into the database
    println!("Inserting new scan record into database for {}", domain);
    let certificate_json = serde_json::to_string(&certificate_info).unwrap();
    let protocols_json = serde_json::to_string(&protocols).unwrap();
    let cipher_suites_json = serde_json::to_string(&cipher_suites).unwrap();
    let vulnerabilities_json = serde_json::to_string(&vulnerabilities).unwrap();
    let key_exchange_json = serde_json::to_string(&key_exchange).unwrap();
    let details_json = "{}";
    let scanned_by = "anonymous";

    let _ = insert_scan(
        &state.pool,
        &domain,
        scanned_by,
        &format!("{:?}", grade),
        &certificate_json,
        &protocols_json,
        &cipher_suites_json,
        &vulnerabilities_json,
        &key_exchange_json,
        explanation.as_deref(),
        Some(&scan_duration_str),
        details_json,
    )
    .await;

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
            tls_scan_duration: Some(scan_duration_str),
        }),
    )
}
