use crate::AppState;
use crate::services::certificate_parser::parse_certificate;
use crate::services::openssl_probe::{test_tls10, test_tls11};
use crate::services::security_grader::{Grade, GradeInput};
use crate::services::tls_parser::TlsVersion;
use axum::extract::{Json, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct AssessmentRequest {
    pub domain: String,
}

#[derive(Serialize)]
pub struct AssessmentResponse {
    pub domain: String,
    pub grade: Grade,
    pub certificate: CertificateInfo,
    pub protocols: ProtocolSupport,
    pub cipher_suites: CipherSuiteInfo,
    pub vulnerabilities: VulnerabilityInfo,
    pub key_exchange: KeyExchangeInfo,
    pub message: String,
    pub explanation: String,
    pub tls_scan_duration: String,
}

// ====================================
// DATA STRUCTURES

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct ProtocolSupport {
    pub tls_1_0: String,
    pub tls_1_1: String,
    pub tls_1_2: String,
    pub tls_1_3: String,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct CipherSuiteInfo {
    pub tls_1_2_suites: Vec<String>,
    pub tls_1_3_suites: Vec<String>,
    pub preferred_suite: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct VulnerabilityInfo {
    pub poodle: String,
    pub beast: String,
    pub heartbleed: String,
    pub freak: String,
    pub logjam: String,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct KeyExchangeInfo {
    pub supports_forward_secrecy: bool,
    pub key_exchange_algorithm: Option<String>,
    pub curve_name: Option<String>,
}

// ====================================
// DATA STRUCTURES

struct AssessmentData {
    pub certificate_info: CertificateInfo,
    pub protocols: ProtocolSupport,
    pub cipher_suites: CipherSuiteInfo,
    pub vulnerabilities: VulnerabilityInfo,
    pub key_exchange: KeyExchangeInfo,
    pub grade_input: GradeInput,
}

impl AssessmentData {
    fn new() -> Self {
        Self {
            certificate_info: CertificateInfo::default(),
            protocols: ProtocolSupport {
                tls_1_0: "Not Tested".to_string(),
                tls_1_1: "Not Tested".to_string(),
                tls_1_2: "Not Supported".to_string(),
                tls_1_3: "Not Supported".to_string(),
            },
            cipher_suites: CipherSuiteInfo::default(),
            vulnerabilities: VulnerabilityInfo::default(),
            key_exchange: KeyExchangeInfo::default(),
            grade_input: GradeInput {
                tls13_supported: false,
                tls12_supported: false,
                tls11_supported: false,
                tls10_supported: false,
                cert_valid: false,
                cert_expired: false,
                cert_key_strength_ok: false,
                hsts: false,
                forward_secrecy: false,
                weak_protocols_disabled: true,
                ocsp_stapling_enabled: false,
            },
        }
    }
}

// ====================================
// MAIN ASSESSMENT HANDLER

/// Main entry point for TLS domain assessment
pub async fn assess_domain(
    State(state): State<AppState>,
    Json(payload): Json<AssessmentRequest>,
) -> (StatusCode, Json<AssessmentResponse>) {
    let scan_start = std::time::Instant::now();
    let domain = payload.domain.trim();

    // Check for cached results first
    if let Some(cached_response) = check_cached_scan(&state, domain).await {
        return cached_response;
    }

    println!("=== STARTING NEW TLS ASSESSMENT ===");
    println!("Domain: {}", domain);
    println!(
        "Timestamp: {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC") //LIBARY!!!!
    );

    // Initialize assessment data
    let mut assessment_data = AssessmentData::new();

    // Perform security checks
    assessment_data.grade_input.hsts = check_hsts_support(domain).await;
    assess_tls_protocols(domain, &mut assessment_data).await;

    // Calculate final grade and explanation
    let whois_resp = crate::services::security_grader::whois_query(domain).ok();
    let (grade, explanation) = crate::services::security_grader::get_or_run_scan(
        domain,
        &assessment_data.grade_input,
        &assessment_data.certificate_info,
        &assessment_data.protocols,
        &assessment_data.cipher_suites,
        &assessment_data.vulnerabilities,
        &assessment_data.key_exchange,
        whois_resp.as_deref(),
    );

    println!("Final Grade: {:?}", grade);
    println!("=== Assessment Complete ===\n");

    // Store results and prepare response
    let scan_duration_str = format!("{:.2}s", scan_start.elapsed().as_secs_f32());
    store_scan_result(
        &state,
        domain,
        &grade,
        &assessment_data,
        &explanation,
        &scan_duration_str,
    )
    .await;

    (
        StatusCode::OK,
        Json(AssessmentResponse {
            domain: domain.to_string(),
            grade,
            certificate: assessment_data.certificate_info,
            protocols: assessment_data.protocols,
            cipher_suites: assessment_data.cipher_suites,
            vulnerabilities: assessment_data.vulnerabilities,
            key_exchange: assessment_data.key_exchange,
            message: get_assessment_message(&assessment_data.grade_input),
            explanation: explanation.unwrap_or_else(|| "No issues found".to_string()),
            tls_scan_duration: scan_duration_str,
        }),
    )
}

// ====================================
// CACHE MANAGEMENT=

/// Check for recent cached scan results
async fn check_cached_scan(
    state: &AppState,
    domain: &str,
) -> Option<(StatusCode, Json<AssessmentResponse>)> {
    println!("=== CHECKING DATABASE FOR RECENT SCAN ===");

    match crate::db::get_recent_scan(&state.pool, domain).await {
        Ok(Some(recent_scan)) => {
            println!(
                "Found recent scan for {} from database! Skipping new assessment.",
                domain
            );

            // Deserialize cached data
            let certificate_info: CertificateInfo =
                serde_json::from_str(&recent_scan.certificate_json).unwrap_or_default();
            let protocols: ProtocolSupport =
                serde_json::from_str(&recent_scan.protocols_json).unwrap_or_default();
            let cipher_suites: CipherSuiteInfo =
                serde_json::from_str(&recent_scan.cipher_suites_json).unwrap_or_default();
            let vulnerabilities: VulnerabilityInfo =
                serde_json::from_str(&recent_scan.vulnerabilities_json).unwrap_or_default();
            let key_exchange: KeyExchangeInfo =
                serde_json::from_str(&recent_scan.key_exchange_json).unwrap_or_default();

            let grade = parse_grade_from_string(&recent_scan.grade);

            Some((
                StatusCode::OK,
                Json(AssessmentResponse {
                    domain: domain.to_string(),
                    grade,
                    certificate: certificate_info,
                    protocols,
                    cipher_suites,
                    vulnerabilities,
                    key_exchange,
                    message: "Cached result (no new assessment needed)".to_string(),
                    explanation: recent_scan
                        .explanation
                        .unwrap_or_else(|| "No explanation".to_string()),
                    tls_scan_duration: recent_scan
                        .tls_scan_duration
                        .unwrap_or_else(|| "< 0.01s".to_string()),
                }),
            ))
        }
        Ok(None) => {
            println!(
                "No recent scan found for {}, running new assessment...",
                domain
            );
            None
        }
        Err(e) => {
            println!("Database error when checking for recent scan: {:?}", e);
            None
        }
    }
}

// ====================================
// TLS PROTOCOL ASSESSMENT

/// Assess all TLS protocol versions and cipher suites
async fn assess_tls_protocols(domain: &str, data: &mut AssessmentData) {
    assess_tls12(domain, data).await;
    assess_tls13(domain, data).await;
    assess_legacy_protocols(domain, data);
    assess_vulnerabilities(data);
}

/// Assess TLS 1.2 support and extract cipher/certificate information
async fn assess_tls12(domain: &str, data: &mut AssessmentData) {
    let tls12_result =
        crate::services::tls_handshake::client_handshake::perform_tls_handshake_full_with_cert(
            domain,
            TlsVersion::TLS1_2,
        );

    match tls12_result {
        Ok((state, cert_der)) => {
            println!("TLS 1.2 handshake succeeded for {}", domain);
            data.protocols.tls_1_2 = "Supported".to_string();
            data.grade_input.tls12_supported = true;

            // Extract the actual cipher that was negotiated
            let suite_name = crate::services::tls_parser::get_cipher_suite_name(
                &state.negotiated_cipher_suite.id,
            );
            data.cipher_suites.tls_1_2_suites.push(suite_name.clone());
            data.cipher_suites.preferred_suite = Some(suite_name.clone());

            // Extract key exchange info for TLS 1.2
            extract_tls12_key_exchange_info(&suite_name, &state, data);

            // Process certificate if available
            if let Some(cert_der) = cert_der {
                process_certificate(&cert_der, &mut data.certificate_info, &mut data.grade_input);
            }
        }
        Err(e) => {
            println!("✗ TLS 1.2 handshake failed for {}: {:?}", domain, e);
            data.protocols.tls_1_2 = "Not Supported".to_string();
            data.grade_input.tls12_supported = false;
        }
    }
}

/// Extract curve information from TLS 1.2 handshake state
fn extract_actual_curve_from_handshake(
    state: &crate::services::tls_handshake::client_handshake::TlsConnectionState,
) -> Option<String> {
    // TLS 1.2: negotiated_cipher_suite is a CipherSuite struct with .id field
    let suite_name =
        crate::services::tls_parser::get_cipher_suite_name(&state.negotiated_cipher_suite.id);

    if suite_name.contains("ECDHE") {
        Some("P-256".to_string())
    } else if suite_name.contains("DHE") {
        Some("DHE".to_string())
    } else {
        None
    }
}

/// Assess TLS 1.3 support and extract cipher/certificate information
async fn assess_tls13(domain: &str, data: &mut AssessmentData) {
    let tls13_result =
        crate::services::tls_handshake::tls13::client::perform_tls13_handshake_full_with_cert(
            domain,
        );

    match tls13_result {
        Ok((state, cert_der)) => {
            println!("✓ TLS 1.3 handshake succeeded for {}", domain);
            data.protocols.tls_1_3 = "Supported".to_string();
            data.grade_input.tls13_supported = true;

            // Extract key exchange information (TLS 1.3 always has forward secrecy)
            extract_tls13_key_exchange_info(&state, data);

            // Extract cipher suite information - TLS 1.3 stores raw bytes
            let suite_name =
                crate::services::tls_parser::get_cipher_suite_name(&state.negotiated_cipher_suite);
            data.cipher_suites.preferred_suite = Some(suite_name.clone());
            data.cipher_suites.tls_1_3_suites.push(suite_name);

            // Process certificate if available
            if let Some(cert_der) = cert_der {
                process_certificate(&cert_der, &mut data.certificate_info, &mut data.grade_input);
            }
        }
        Err(e) => {
            println!("✗ TLS 1.3 handshake failed for {}: {:?}", domain, e);
            data.protocols.tls_1_3 = "Not Supported".to_string();
            data.grade_input.tls13_supported = false;
        }
    }
}

/// Test legacy TLS protocol support (1.0 and 1.1)
fn assess_legacy_protocols(domain: &str, data: &mut AssessmentData) {
    data.protocols.tls_1_0 = if test_tls10(domain) {
        data.grade_input.tls10_supported = true;
        "Supported".to_string()
    } else {
        "Not Supported".to_string()
    };

    data.protocols.tls_1_1 = if test_tls11(domain) {
        data.grade_input.tls11_supported = true;
        "Supported".to_string()
    } else {
        "Not Supported".to_string()
    };
}

// ===================
// KEY EXCHANGE ANALYSIS

/// Extract key exchange information from TLS 1.2 handshake
fn extract_tls12_key_exchange_info(
    suite_name: &str,
    state: &crate::services::tls_handshake::client_handshake::TlsConnectionState,
    data: &mut AssessmentData,
) {
    if suite_name.contains("ECDHE") {
        data.grade_input.forward_secrecy = true;
        data.key_exchange.supports_forward_secrecy = true;
        data.key_exchange.key_exchange_algorithm = Some("ECDHE".to_string());

        if let Some(curve) = extract_actual_curve_from_handshake(state) {
            data.key_exchange.curve_name = Some(curve);
        } else {
            data.key_exchange.curve_name = Some("Unknown".to_string());
        }
    }
}

/// Extract key exchange information from TLS 1.3 handshake
fn extract_tls13_key_exchange_info(
    state: &crate::services::tls_handshake::tls13::client::Tls13ConnectionState,
    data: &mut AssessmentData,
) {
    if !data.grade_input.forward_secrecy {
        data.grade_input.forward_secrecy = true;
        data.key_exchange.supports_forward_secrecy = true;
        data.key_exchange.key_exchange_algorithm = Some("ECDHE".to_string());

        if let Some(curve) = extract_actual_curve_from_tls13_handshake(state) {
            data.key_exchange.curve_name = Some(curve);
        } else {
            data.key_exchange.curve_name = Some("Unknown".to_string());
        }
    }
}

/// Extract curve information from TLS 1.3 handshake state
fn extract_actual_curve_from_tls13_handshake(
    _state: &crate::services::tls_handshake::tls13::client::Tls13ConnectionState,
) -> Option<String> {
    // TLS 1.3 implementation uses ring's X25519 for key exchange
    Some("X25519".to_string())
}

// ====================================
// CERTIFICATE PROCESSING

/// Process and extract certificate information
fn process_certificate(
    cert_der: &[u8],
    cert_info: &mut CertificateInfo,
    grade_input: &mut GradeInput,
) {
    if let Ok(parsed_cert) = parse_certificate(cert_der) {
        cert_info.common_name = Some(parsed_cert.subject.clone());
        cert_info.issuer = Some(parsed_cert.issuer.clone());
        cert_info.valid_from = Some(parsed_cert.not_before.clone());
        cert_info.valid_to = Some(parsed_cert.not_after.clone());
        cert_info.key_size = parsed_cert.key_size.clone();
        cert_info.signature_algorithm = Some(parsed_cert.signature_algorithm.clone());
        cert_info.serial_number = Some(parsed_cert.serial_number.clone());
        cert_info.subject_alt_names = parsed_cert.subject_alt_names.clone();

        cert_info.chain_trust = Some(if !parsed_cert.expired {
            "Trusted".to_string()
        } else {
            "Expired".to_string()
        });

        grade_input.cert_valid = !parsed_cert.expired;
        grade_input.cert_expired = parsed_cert.expired;

        // Key strength logic: RSA >= 2048, EC >= 256
        grade_input.cert_key_strength_ok = false;
        if let Some(ref key_size_str) = cert_info.key_size {
            if let Ok(bits) = key_size_str.parse::<u32>() {
                // EC keys typically 256, 384, 521; RSA should be >= 2048
                if cert_info
                    .signature_algorithm
                    .as_ref()
                    .map_or(false, |alg| alg.contains("RSA"))
                {
                    if bits >= 2048 {
                        grade_input.cert_key_strength_ok = true;
                    }
                } else if cert_info
                    .signature_algorithm
                    .as_ref()
                    .map_or(false, |alg| alg.contains("ECDSA") || alg.contains("EC"))
                {
                    if bits >= 256 {
                        grade_input.cert_key_strength_ok = true;
                    }
                }
            }
        }

        calculate_days_until_expiry(cert_info);
    }
}

/// Calculate days until certificate expiry
fn calculate_days_until_expiry(cert_info: &mut CertificateInfo) {
    if let Some(valid_to) = &cert_info.valid_to {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(valid_to, "%Y-%m-%dT%H:%M:%SZ") {
            let now = chrono::Utc::now().naive_utc();
            let days = (dt - now).num_days();
            cert_info.days_until_expiry = Some(days);
        } else if let Ok(date) = chrono::NaiveDate::parse_from_str(valid_to, "%Y-%m-%d") {
            let now = chrono::Utc::now().date_naive();
            let days = (date - now).num_days();
            cert_info.days_until_expiry = Some(days);
        } else {
            cert_info.days_until_expiry = None;
        }
    } else {
        cert_info.days_until_expiry = None;
    }
}

// ====================================
// VULNERABILITY ASSESSMENT

/// Assess common TLS vulnerabilities based on protocol support
fn assess_vulnerabilities(data: &mut AssessmentData) {
    data.vulnerabilities = VulnerabilityInfo {
        poodle: if data.protocols.tls_1_0 == "Supported" {
            "Potentially Vulnerable".to_string()
        } else {
            "Not Vulnerable".to_string()
        },
        beast: if data.protocols.tls_1_0 == "Supported" {
            "Potentially Vulnerable".to_string()
        } else {
            "Not Vulnerable".to_string()
        },
        heartbleed: "Unknown".to_string(),
        freak: if data
            .cipher_suites
            .tls_1_2_suites
            .iter()
            .any(|s| s.contains("EXPORT"))
        {
            "Potentially Vulnerable".to_string()
        } else {
            "Not Vulnerable".to_string()
        },
        logjam: if let Some(suite) = &data.cipher_suites.preferred_suite {
            if suite.contains("ECDHE") {
                "Not Vulnerable".to_string()
            } else {
                "Potentially Vulnerable".to_string()
            }
        } else {
            "Unknown".to_string()
        },
    };
}

// ====================================
// UTILITY FUNCTIONS

/// Check if a domain supports HSTS (HTTP Strict Transport Security) //LIBRARY!!!!
async fn check_hsts_support(domain: &str) -> bool {
    if let Ok(resp) = reqwest::get(format!("https://{}", domain)).await {
        resp.headers().get("strict-transport-security").is_some()
    } else {
        false
    }
}

/// Store scan results in database
async fn store_scan_result(
    state: &AppState,
    domain: &str,
    grade: &Grade,
    data: &AssessmentData,
    explanation: &Option<String>,
    scan_duration_str: &str,
) {
    println!("Inserting new scan record into database for {}", domain);

    let certificate_json = serde_json::to_string(&data.certificate_info).unwrap();
    let protocols_json = serde_json::to_string(&data.protocols).unwrap();
    let cipher_suites_json = serde_json::to_string(&data.cipher_suites).unwrap();
    let vulnerabilities_json = serde_json::to_string(&data.vulnerabilities).unwrap();
    let key_exchange_json = serde_json::to_string(&data.key_exchange).unwrap();
    let details_json = "{}";

    match crate::db::insert_scan(
        &state.pool,
        domain,
        "anonymous",
        &format!("{:?}", grade),
        &certificate_json,
        &protocols_json,
        &cipher_suites_json,
        &vulnerabilities_json,
        &key_exchange_json,
        explanation.as_deref(),
        Some(scan_duration_str),
        details_json,
    )
    .await
    {
        Ok(_) => println!("Database insert successful for {}", domain),
        Err(e) => println!("Database insert failed for {}: {:?}", domain, e),
    }
}

/// Parse grade string back to Grade enum
fn parse_grade_from_string(grade_str: &str) -> Grade {
    match grade_str {
        "APlus" => Grade::APlus,
        "A" => Grade::A,
        "B" => Grade::B,
        "C" => Grade::C,
        "F" => Grade::F,
        _ => Grade::F,
    }
}

/// Generate assessment completion message
fn get_assessment_message(grade_input: &GradeInput) -> String {
    if !grade_input.tls12_supported && !grade_input.tls13_supported {
        "TLS assessment completed with limited support".to_string()
    } else {
        "TLS assessment completed".to_string()
    }
}
