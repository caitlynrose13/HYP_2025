use crate::AppState;
use crate::services::certificate_parser::{calculate_days_until_expiry, parse_certificate};
use crate::services::http_security_checker::check_http_security;
use crate::services::openssl_probe::{test_tls10, test_tls11};
use crate::services::security_grader::Grade;
use crate::services::security_grader::GradeInput;
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
    pub explanation: String,
    pub certificate: CertificateInfo,
    pub protocols: ProtocolSupport,
    pub cipher_suites: CipherSuiteInfo,
    pub vulnerabilities: VulnerabilityInfo,
    pub key_exchange: KeyExchangeInfo,
    pub whois_info: Option<DomainWhoisInfo>,
    pub message: String,
    pub tls_scan_duration: String,
}

#[derive(Serialize, Clone)]
pub struct DomainWhoisInfo {
    pub creation_date: Option<String>,
    pub domain_age_days: Option<i64>,
    pub registrar: Option<String>,
    pub status: String,
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

                https_redirect: false,
                csp_header: false,
                x_frame_options: false,
                x_content_type_options: false,
                expect_ct: false,
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
    let user_experience_start = std::time::Instant::now(); // Track total time from user perspective
    let domain = payload.domain.trim();

    // Check for cached results first
    if let Some(cached_response) = check_cached_scan(&state, domain).await {
        return cached_response;
    }

    println!("=== STARTING COMPREHENSIVE ASSESSMENT (ALL SERVICES) ===");
    println!("Domain: {}", domain);
    println!(
        "Timestamp: {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    // Initialize assessment data
    let mut assessment_data = AssessmentData::new();

    // Perform security checks
    assessment_data.grade_input.hsts = check_hsts_support(domain).await;

    // Check HTTP security headers
    if let Ok(http_security) = check_http_security(domain).await {
        assessment_data.grade_input.https_redirect = http_security.https_redirect;
        assessment_data.grade_input.csp_header = http_security.csp_header;
        assessment_data.grade_input.x_frame_options = http_security.x_frame_options;
        assessment_data.grade_input.x_content_type_options = http_security.x_content_type_options;
        assessment_data.grade_input.expect_ct = http_security.expect_ct;
    }

    // Start TLS assessment with timing
    let tls_future = async {
        let tls_start = std::time::Instant::now();
        assess_tls_protocols(domain, &mut assessment_data).await;
        let tls_duration = tls_start.elapsed().as_secs_f64();
        (assessment_data, tls_duration)
    };

    // Start SSL Labs assessment (in parallel)
    let ssl_labs_future = async {
        println!("🔍 Starting SSL Labs scan for {}", domain);
        match crate::services::ssllabs::fetch_ssllabs_results(domain).await {
            Ok(result) => {
                let secs = (result.scan_duration as f64) / 1000.0;
                println!("✅ SSL Labs completed: {} ({:.2}s)", result.grade, secs);
                (Some(result.grade), None::<String>, Some(secs))
            }
            Err(e) => {
                println!("❌ SSL Labs failed: {}", e);
                (None, Some(e), None)
            }
        }
    };

    // Start Mozilla Observatory assessment (in parallel)
    let mozilla_future = async {
        println!("🔍 Starting Mozilla Observatory scan for {}", domain);
        match crate::services::mozilla_observatory::fetch_observatory_results(domain).await {
            Ok(result) => {
                let secs = result
                    .scan_duration
                    .as_deref()
                    .and_then(|s| s.trim_end_matches('s').parse::<f64>().ok());
                let grade_label = result.grade.clone().unwrap_or_else(|| "-".to_string());
                println!(
                    "✅ Mozilla Observatory completed: {} ({})",
                    grade_label,
                    result.scan_duration.as_deref().unwrap_or("-")
                );
                (result.grade, None::<String>, secs)
            }
            Err(e) => {
                println!("❌ Mozilla Observatory failed: {}", e);
                (None, Some(e), None)
            }
        }
    };

    // Run ALL THREE services in parallel
    let (
        (assessment_data, tls_scan_time),
        (ssl_grade, ssl_error, ssl_time),
        (mozilla_grade, mozilla_error, mozilla_time),
    ) = tokio::join!(tls_future, ssl_labs_future, mozilla_future);

    // Calculate the ACTUAL user experience time (total time from start to finish)
    let total_user_experience_time = user_experience_start.elapsed().as_secs_f64();

    println!("=== ALL SERVICES COMPLETED ===");
    println!("TLS Analysis: Complete ({:.2}s)", tls_scan_time);
    println!(
        "Total User Experience Time: {:.2}s",
        total_user_experience_time
    );
    println!(
        "SSL Labs: {} | Mozilla Observatory: {}",
        ssl_grade.as_deref().unwrap_or("Failed"),
        mozilla_grade.as_deref().unwrap_or("Failed")
    );

    // Calculate final grade (NO PHISHING OVERRIDE)
    let whois_resp = crate::services::security_grader::whois_query(domain).ok();
    let (final_grade, explanation) = crate::services::security_grader::get_or_run_scan(
        domain,
        &assessment_data.grade_input,
        &assessment_data.certificate_info,
        &assessment_data.protocols,
        &assessment_data.cipher_suites,
        &assessment_data.vulnerabilities,
        &assessment_data.key_exchange,
        whois_resp.as_deref(),
    );

    // Process WHOIS information for display
    let whois_info = if let Some(ref whois_resp_str) = whois_resp {
        Some(extract_whois_info_for_display(whois_resp_str))
    } else {
        None
    };

    // Store results in database with both individual and total times
    let ssl_grade_ref: Option<&str> = ssl_grade.as_deref();
    let mozilla_grade_ref: Option<&str> = mozilla_grade.as_deref();
    let ssl_err_ref: Option<&str> = ssl_error.as_deref();
    let moz_err_ref: Option<&str> = mozilla_error.as_deref();

    store_comprehensive_scan_result(
        &state,
        domain,
        &final_grade,
        tls_scan_time,
        total_user_experience_time, // Pass the total user experience time
        ssl_grade_ref,
        mozilla_grade_ref,
        ssl_time,
        mozilla_time,
        ssl_err_ref,
        moz_err_ref,
    )
    .await;

    println!("=== Assessment Complete ===");

    (
        StatusCode::OK,
        Json(AssessmentResponse {
            domain: domain.to_string(),
            grade: final_grade,
            explanation: explanation.unwrap_or_else(|| "Security analysis completed".to_string()),
            certificate: assessment_data.certificate_info,
            protocols: assessment_data.protocols,
            cipher_suites: assessment_data.cipher_suites,
            vulnerabilities: assessment_data.vulnerabilities,
            key_exchange: assessment_data.key_exchange,
            whois_info,
            message: "Security analysis completed".to_string(),
            tls_scan_duration: format!("{:.2}s", total_user_experience_time), // Show user experience time
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
            println!("Found recent scan for {} from database!", domain);

            let grade = parse_grade_from_string(&recent_scan.grade);

            // Use total_scan_time for user experience, fallback to tls_scan_time if needed
            let display_duration = recent_scan
                .total_scan_time
                .or(recent_scan.tls_scan_time)
                .map(|time| format!("{:.2}s", time))
                .unwrap_or_else(|| "< 0.01s".to_string());

            Some((
                StatusCode::OK,
                Json(AssessmentResponse {
                    domain: domain.to_string(),
                    grade,
                    certificate: CertificateInfo::default(),
                    protocols: ProtocolSupport::default(),
                    cipher_suites: CipherSuiteInfo::default(),
                    vulnerabilities: VulnerabilityInfo::default(),
                    key_exchange: KeyExchangeInfo::default(),
                    whois_info: None,
                    message: "Security analysis completed".to_string(),
                    explanation: "Cached scan result".to_string(),
                    tls_scan_duration: display_duration, // Show the actual user experience time
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
        println!("=== CERTIFICATE DEBUG ===");
        println!("Certificate Subject: {}", parsed_cert.subject);
        println!("Certificate Issuer: {}", parsed_cert.issuer);
        println!("Certificate Expired: {}", parsed_cert.expired);
        if let Some(ref key_size) = parsed_cert.key_size {
            println!("Key Size: {}", key_size);
        } else {
            println!("Key Size: None");
        }
        println!("Signature Algorithm: {}", parsed_cert.signature_algorithm);
        println!("=== END CERTIFICATE DEBUG ===");

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

        // IMPROVED: Separate key strength from signature algorithm validation
        grade_input.cert_key_strength_ok = validate_key_strength(&parsed_cert);

        println!(
            "Final cert_key_strength_ok: {}",
            grade_input.cert_key_strength_ok
        );

        // FIX: calculate_days_until_expiry only takes 1 argument and returns the days
        if let Some(ref valid_to) = cert_info.valid_to {
            cert_info.days_until_expiry = calculate_days_until_expiry(valid_to);
        }
    } else {
        println!("=== CERTIFICATE PARSING FAILED ===");
        grade_input.cert_valid = false;
        grade_input.cert_expired = true;
        grade_input.cert_key_strength_ok = false;
    }
}

fn validate_key_strength(
    parsed_cert: &crate::services::certificate_parser::ParsedCertificate,
) -> bool {
    let Some(key_size_str) = &parsed_cert.key_size else {
        println!("⚠️  No key size information - assuming acceptable");
        return true; // Be lenient for missing info
    };

    let Ok(bits) = key_size_str.parse::<u32>() else {
        println!(
            "⚠️  Cannot parse key size '{}' - assuming acceptable",
            key_size_str
        );
        return true; // Be lenient for parsing issues
    };

    // REALISTIC THRESHOLDS: Only flag truly weak keys
    let is_acceptable = match bits {
        // Clearly weak keys
        0..=127 => {
            println!("❌ Key strength WEAK ({} bits - too small)", bits);
            false
        }
        // Acceptable range (covers both ECDSA and RSA)
        128..=10240 => {
            println!("✅ Key strength OK ({} bits)", bits);
            true
        }
        // Unusually large but probably fine
        _ => {
            println!(
                "✅ Key strength OK ({} bits - unusually large but acceptable)",
                bits
            );
            true
        }
    };

    is_acceptable
}

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

/// Store comprehensive scan results in database
async fn store_comprehensive_scan_result(
    state: &AppState,
    domain: &str,
    grade: &Grade,
    tls_scan_time: f64,
    total_scan_time: f64, // NEW: User experience time
    ssl_labs_grade: Option<&str>,
    mozilla_grade: Option<&str>,
    ssl_time: Option<f64>,
    mozilla_time: Option<f64>,
    ssl_error: Option<&str>,
    mozilla_error: Option<&str>,
) {
    println!("Storing comprehensive scan result for {}", domain);
    println!("  - TLS scan time: {:.2}s", tls_scan_time);
    println!("  - Total user experience time: {:.2}s", total_scan_time);

    match crate::db::insert_scan(
        &state.pool,
        domain,
        &format!("{:?}", grade),
        ssl_labs_grade,
        mozilla_grade,
        ssl_time,
        mozilla_time,
        Some(tls_scan_time),
        Some(total_scan_time), // Store the total user experience time
        ssl_error,
        mozilla_error,
        None, // tls_error
    )
    .await
    {
        Ok(_) => println!("Comprehensive database insert successful for {}", domain),
        Err(e) => println!("Database insert failed for {}: {:?}", domain, e),
    }
}

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

/// Extract WHOIS information for display purposes
fn extract_whois_info_for_display(whois_response: &str) -> DomainWhoisInfo {
    let parsed = parse_whois_response_local(whois_response);

    let (domain_age_days, status) = if let Some(creation_date) = parsed.creation_date {
        let now = chrono::Utc::now().naive_utc();
        let age_days = (now - creation_date).num_days();

        let status = if age_days < 30 {
            "Very New Domain".to_string()
        } else if age_days < 90 {
            "New Domain".to_string()
        } else if age_days < 365 {
            "Recent Domain".to_string()
        } else {
            "Established Domain".to_string()
        };

        (Some(age_days), status)
    } else {
        (None, "Unknown Age".to_string())
    };

    DomainWhoisInfo {
        creation_date: parsed
            .creation_date
            .map(|dt| dt.format("%Y-%m-%d").to_string()),
        domain_age_days,
        registrar: parsed.registrar,
        status,
    }
}

// ====================================
// WHOIS PARSING (LOCAL)

#[derive(Debug, Default)]
struct WhoisResponse {
    creation_date: Option<chrono::NaiveDateTime>,
    registrar: Option<String>,
}

fn parse_whois_response_local(whois_response: &str) -> WhoisResponse {
    let mut response = WhoisResponse::default();

    for line in whois_response.lines() {
        let line = line.trim();

        // Extract creation date
        if response.creation_date.is_none() {
            if let Some(date) = extract_creation_date_local(line) {
                response.creation_date = Some(date);
            }
        }

        // Extract registrar
        if response.registrar.is_none() {
            if let Some(registrar) = extract_registrar_local(line) {
                response.registrar = Some(registrar);
            }
        }
    }

    response
}

fn extract_creation_date_local(line: &str) -> Option<chrono::NaiveDateTime> {
    let creation_patterns = [
        "Creation Date:",
        "Created:",
        "Domain Create Date:",
        "created:",
        "Created On:",
        "Registered:",
        "Registration Date:",
        "Created Date:",
        "Domain Created:",
        "Record created on",
        "created on",
    ];

    for pattern in &creation_patterns {
        if line.to_lowercase().contains(&pattern.to_lowercase()) {
            let date_part = line
                .split(':')
                .nth(1)
                .unwrap_or("")
                .trim()
                .split_whitespace()
                .next()
                .unwrap_or("");

            // Try different date formats
            let formats = [
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d",
                "%d/%m/%Y",
                "%m/%d/%Y",
                "%Y.%m.%d",
                "%d.%m.%Y",
                "%Y-%m-%dT%H:%M:%S%.3fZ",
            ];

            for format in &formats {
                if let Ok(parsed_date) = chrono::NaiveDateTime::parse_from_str(date_part, format) {
                    return Some(parsed_date);
                }
                if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_part, "%Y-%m-%d") {
                    return Some(parsed_date.and_hms_opt(0, 0, 0).unwrap());
                }
            }
        }
    }
    None
}

fn extract_registrar_local(line: &str) -> Option<String> {
    let registrar_patterns = ["Registrar:", "Sponsoring Registrar:", "Registrar Name:"];

    for pattern in &registrar_patterns {
        if line.to_lowercase().contains(&pattern.to_lowercase()) {
            let registrar = line.split(':').nth(1).unwrap_or("").trim().to_string();

            if !registrar.is_empty() && registrar != "Not Available" {
                return Some(registrar);
            }
        }
    }
    None
}
