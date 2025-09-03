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
    pub security_warnings: SecurityWarnings,
    pub message: String,
    pub tls_scan_duration: String,
}

#[derive(Serialize, Clone)]
pub struct SecurityWarnings {
    pub is_phishing_suspicious: bool,
    pub phishing_risk_score: u32,
    pub warning_message: Option<String>,
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

/// Main entry point for TLS domain assessment - NOW WITH ALL SERVICES
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

    // Start TLS assessment
    let tls_future = async {
        assess_tls_protocols(domain, &mut assessment_data).await;
        assessment_data
    };

    // Start SSL Labs assessment (in parallel)
    let ssl_labs_future = async {
        println!("🔍 Starting SSL Labs scan for {}", domain);
        match crate::services::ssllabs::fetch_ssllabs_results(domain).await {
            Ok(result) => {
                let secs = (result.scan_duration as f64) / 1000.0;
                println!("✅ SSL Labs completed: {} ({:.2}s)", result.grade, secs);
                (Some(result.grade), None::<String>, Some(secs)) // grade: Option<String>, err: Option<String>, time: Option<f64>
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
                // result.scan_duration like "1.23s" -> parse to f64 seconds
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
                (result.grade, None::<String>, secs) // grade: Option<String>, err: Option<String>, time: Option<f64>
            }
            Err(e) => {
                println!("❌ Mozilla Observatory failed: {}", e);
                (None, Some(e), None)
            }
        }
    };

    // Run ALL THREE services in parallel
    let (
        assessment_data,
        (ssl_grade, ssl_error, ssl_time),
        (mozilla_grade, mozilla_error, mozilla_time),
    ) = tokio::join!(tls_future, ssl_labs_future, mozilla_future);

    println!("=== ALL SERVICES COMPLETED ===");
    println!("TLS Analysis: Complete");
    println!(
        "SSL Labs: {} | Mozilla Observatory: {}",
        ssl_grade.as_deref().unwrap_or("Failed"),
        mozilla_grade.as_deref().unwrap_or("Failed")
    );

    // Calculate final grade
    let whois_resp = crate::services::security_grader::whois_query(domain).ok();
    let (tls_grade, explanation) = crate::services::security_grader::get_or_run_scan(
        domain,
        &assessment_data.grade_input,
        &assessment_data.certificate_info,
        &assessment_data.protocols,
        &assessment_data.cipher_suites,
        &assessment_data.vulnerabilities,
        &assessment_data.key_exchange,
        whois_resp.as_deref(),
    );

    // Perform phishing analysis
    let phishing_analysis = perform_phishing_analysis(domain).await;

    // Apply phishing grade override
    let (final_grade, final_explanation) = if phishing_analysis.is_suspicious {
        let risk_score = phishing_analysis.risk_score;
        match risk_score {
            90..=100 => (
                Grade::F,
                "CRITICAL PHISHING RISK: This site is highly likely to be fraudulent.".to_string(),
            ),
            80..=89 => (
                Grade::F,
                format!(
                    "HIGH PHISHING RISK ({}%): Site appears fraudulent despite good TLS security.",
                    risk_score
                ),
            ),
            70..=79 => {
                if matches!(tls_grade, Grade::APlus | Grade::A) {
                    (
                        Grade::C,
                        format!(
                            "MODERATE PHISHING RISK ({}%): TLS security is good but site shows suspicious patterns.",
                            risk_score
                        ),
                    )
                } else {
                    (
                        Grade::F,
                        format!(
                            "MODERATE PHISHING RISK ({}%): Combined with weak TLS security.",
                            risk_score
                        ),
                    )
                }
            }
            60..=69 => {
                let downgraded_grade = match tls_grade {
                    Grade::APlus => Grade::A,
                    Grade::A => Grade::B,
                    Grade::B => Grade::C,
                    other => other,
                };
                (
                    downgraded_grade,
                    format!(
                        "LOW-MODERATE PHISHING RISK ({}%): Site shows some suspicious patterns.",
                        risk_score
                    ),
                )
            }
            _ => (
                tls_grade,
                format!(
                    "LOW PHISHING RISK ({}%): Minor suspicious patterns detected.",
                    risk_score
                ),
            ),
        }
    } else {
        (
            tls_grade,
            explanation
                .clone()
                .unwrap_or_else(|| "No issues found".to_string()),
        )
    };

    // Process WHOIS information for display
    let whois_info = if let Some(ref whois_resp_str) = whois_resp {
        Some(extract_whois_info_for_display(whois_resp_str))
    } else {
        None
    };

    // Generate security warnings for frontend
    let security_warnings = generate_security_warnings(&phishing_analysis);

    // Calculate scan duration
    let scan_duration = scan_start.elapsed();
    let scan_duration_str = format!("{:.2}s", scan_duration.as_secs_f64());

    // Store ALL results in database (including individual service grades)
    // Normalize nested Options to borrowed forms
    let ssl_grade_ref: Option<&str> = ssl_grade.as_deref();
    let mozilla_grade_ref: Option<&str> = mozilla_grade.as_deref();
    let ssl_err_ref: Option<&str> = ssl_error.as_deref();
    let moz_err_ref: Option<&str> = mozilla_error.as_deref();

    store_comprehensive_scan_result(
        &state,
        domain,
        &final_grade,
        &assessment_data,
        &Some(final_explanation.clone()),
        &scan_duration_str,
        &phishing_analysis,
        ssl_grade_ref,
        mozilla_grade_ref,
        ssl_time,     // already Option<f64>
        mozilla_time, // already Option<f64>
        ssl_err_ref,
        moz_err_ref,
    )
    .await;

    println!("=== Assessment Complete ===");

    // Determine message
    let message = if security_warnings.is_phishing_suspicious {
        "Security analysis completed - PHISHING DETECTED".to_string()
    } else {
        "Security analysis completed".to_string()
    };

    (
        StatusCode::OK,
        Json(AssessmentResponse {
            domain: domain.to_string(),
            grade: final_grade,
            explanation: final_explanation,
            certificate: assessment_data.certificate_info,
            protocols: assessment_data.protocols,
            cipher_suites: assessment_data.cipher_suites,
            vulnerabilities: assessment_data.vulnerabilities,
            key_exchange: assessment_data.key_exchange,
            whois_info,
            security_warnings,
            message,
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
                "Found recent scan for {} from database! Using cached phishing data.",
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

            let security_warnings = SecurityWarnings {
                is_phishing_suspicious: recent_scan.is_phishing_detected.unwrap_or(false),
                phishing_risk_score: recent_scan.phishing_risk_score.unwrap_or(0) as u32,
                warning_message: recent_scan.phishing_warning_message.clone(),
            };

            // Use cached explanation and grade (no phishing override needed)
            let final_explanation = recent_scan
                .explanation
                .unwrap_or_else(|| "No explanation".to_string());

            // Log cached phishing status
            if security_warnings.is_phishing_suspicious {
                println!(
                    "🚨 CACHED PHISHING ALERT: Risk Score {}/100",
                    security_warnings.phishing_risk_score
                );
                if let Some(ref warning) = security_warnings.warning_message {
                    println!("Cached Warning: {}", warning);
                }
            }

            // Determine message before moving security_warnings
            let message = if security_warnings.is_phishing_suspicious {
                "Security analysis completed - PHISHING DETECTED".to_string()
            } else {
                "Security analysis completed".to_string()
            };

            Some((
                StatusCode::OK,
                Json(AssessmentResponse {
                    domain: domain.to_string(),
                    grade, // Use original cached grade
                    certificate: certificate_info,
                    protocols,
                    cipher_suites,
                    vulnerabilities,
                    key_exchange,
                    whois_info: None,
                    security_warnings,              // Move happens here
                    message,                        // Use pre-calculated message
                    explanation: final_explanation, // Use cached explanation
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

/// Store scan results in database
async fn store_scan_result(
    state: &AppState,
    domain: &str,
    grade: &Grade,
    data: &AssessmentData,
    explanation: &Option<String>,
    scan_duration_str: &str,
    // NEW: Add phishing analysis parameter
    phishing_analysis: &crate::services::phishing_detector::PhishingAnalysis,
) {
    println!("Inserting new scan record into database for {}", domain);

    let certificate_json = serde_json::to_string(&data.certificate_info).unwrap();
    let protocols_json = serde_json::to_string(&data.protocols).unwrap();
    let cipher_suites_json = serde_json::to_string(&data.cipher_suites).unwrap();
    let vulnerabilities_json = serde_json::to_string(&data.vulnerabilities).unwrap();
    let key_exchange_json = serde_json::to_string(&data.key_exchange).unwrap();
    let details_json = "{}";

    // Extract phishing data
    let is_phishing_detected = if phishing_analysis.is_suspicious {
        Some(true)
    } else {
        Some(false)
    };
    let phishing_risk_score = Some(phishing_analysis.risk_score as i32);
    let phishing_warning_message = if phishing_analysis.is_suspicious {
        Some(format!(
            "PHISHING RISK DETECTED ({}% confidence). This site shows suspicious patterns commonly used by fraudulent websites.",
            phishing_analysis.risk_score
        ))
    } else {
        None
    };

    match crate::db::insert_scan(
        &state.pool,
        domain,
        "anonymous",
        &format!("{:?}", grade),
        // NEW: Individual service grades (not available in TLS-only assessment)
        None,                                                  // ssl_labs_grade
        None,                                                  // mozilla_observatory_grade
        Some(&format!("{:?}", grade)), // tls_analyzer_grade (use same as overall grade for now)
        None,                          // ssl_labs_scan_time
        None,                          // mozilla_scan_time
        Some(scan_duration_str.parse::<f64>().unwrap_or(0.0)), // tls_scan_time
        None,                          // ssl_labs_error
        None,                          // mozilla_error
        None,                          // tls_error
        &certificate_json,
        &protocols_json,
        &cipher_suites_json,
        &vulnerabilities_json,
        &key_exchange_json,
        explanation.as_deref(),
        Some(scan_duration_str),
        details_json,
        is_phishing_detected,
        phishing_risk_score,
        phishing_warning_message.as_deref(),
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

/// Generate simple security warning flag for frontend display
fn generate_security_warnings(
    phishing_analysis: &crate::services::phishing_detector::PhishingAnalysis,
) -> SecurityWarnings {
    //  Only show warning for higher risk scores
    let is_suspicious = phishing_analysis.risk_score >= 75;

    let warning_message = if is_suspicious {
        Some(format!(
            "PHISHING RISK DETECTED ({}% confidence). This site shows suspicious patterns commonly used by fraudulent websites. Avoid entering personal information.",
            phishing_analysis.risk_score
        ))
    } else {
        None
    };

    SecurityWarnings {
        is_phishing_suspicious: is_suspicious,
        phishing_risk_score: phishing_analysis.risk_score,
        warning_message,
    }
}

/// Perform phishing analysis on a domain
async fn perform_phishing_analysis(
    domain: &str,
) -> crate::services::phishing_detector::PhishingAnalysis {
    // Try to fetch the homepage content for analysis
    let page_content = fetch_page_content(domain).await;

    crate::services::phishing_detector::analyze_for_phishing(domain, page_content.as_deref())
}

/// Fetch page content for phishing analysis
async fn fetch_page_content(domain: &str) -> Option<String> {
    // Try HTTPS first, then HTTP
    let urls = [format!("https://{}", domain), format!("http://{}", domain)];

    for url in &urls {
        if let Ok(response) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .ok()?
            .get(url)
            .send()
            .await
        {
            if response.status().is_success() {
                if let Ok(content) = response.text().await {
                    println!(
                        "Fetched content from {} for phishing analysis ({} chars)",
                        url,
                        content.len()
                    );
                    return Some(content);
                }
            }
        }
    }

    println!(
        "Could not fetch content from {} for phishing analysis",
        domain
    );
    None
}

/// Extract WHOIS information for API display
fn extract_whois_info_for_display(whois_response: &str) -> DomainWhoisInfo {
    // Parse the WHOIS response using the existing parser
    let parsed_whois = parse_whois_response_local(whois_response);

    let (creation_date_str, domain_age_days) = if let Some(creation) = parsed_whois.creation_date {
        let now = chrono::Utc::now().naive_utc();
        let age_days = (now - creation).num_days();
        (
            Some(creation.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
            Some(age_days),
        )
    } else {
        (None, None)
    };

    let status = if let Some(age) = domain_age_days {
        if age < 30 {
            "Very New Domain (< 30 days)".to_string()
        } else if age < 90 {
            "New Domain (< 90 days)".to_string()
        } else if age < 365 {
            "Young Domain (< 1 year)".to_string()
        } else {
            "Established Domain".to_string()
        }
    } else {
        "Unknown Age".to_string()
    };

    DomainWhoisInfo {
        creation_date: creation_date_str,
        domain_age_days,
        registrar: parsed_whois.registrar,
        status,
    }
}

/// Local WHOIS parser (duplicated from security_grader for now)
fn parse_whois_response_local(response: &str) -> LocalWhoisInfo {
    let creation_date = extract_creation_date_local(response);
    let registrar = extract_registrar_local(response);

    LocalWhoisInfo {
        creation_date,
        registrar,
    }
}

struct LocalWhoisInfo {
    creation_date: Option<chrono::NaiveDateTime>,
    registrar: Option<String>,
}

fn extract_creation_date_local(response: &str) -> Option<chrono::NaiveDateTime> {
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

                    // Try multiple date formats
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
                        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(date_str, format) {
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

fn extract_registrar_local(response: &str) -> Option<String> {
    for line in response.lines() {
        if line.to_lowercase().contains("registrar:") {
            if let Some(idx) = line.find(':') {
                return Some(line[idx + 1..].trim().to_string());
            }
        }
    }
    None
}

// Remove or comment out the comprehensive assessment function for now
// since the required services don't exist yet

// ====================================
// COMPREHENSIVE SCAN STORAGE

/// Store comprehensive scan results in database (including individual service grades)
async fn store_comprehensive_scan_result(
    state: &AppState,
    domain: &str,
    grade: &Grade,
    data: &AssessmentData,
    explanation: &Option<String>,
    scan_duration_str: &str,
    phishing_analysis: &crate::services::phishing_detector::PhishingAnalysis,
    ssl_labs_grade: Option<&str>,
    mozilla_grade: Option<&str>,
    ssl_time: Option<f64>,
    mozilla_time: Option<f64>,
    ssl_error: Option<&str>,
    mozilla_error: Option<&str>,
) {
    println!("Storing comprehensive scan result for {}", domain);

    let certificate_json = serde_json::to_string(&data.certificate_info).unwrap();
    let protocols_json = serde_json::to_string(&data.protocols).unwrap();
    let cipher_suites_json = serde_json::to_string(&data.cipher_suites).unwrap();
    let vulnerabilities_json = serde_json::to_string(&data.vulnerabilities).unwrap();
    let key_exchange_json = serde_json::to_string(&data.key_exchange).unwrap();
    let details_json = "{}";

    let is_phishing_detected = Some(phishing_analysis.is_suspicious);
    let phishing_risk_score = Some(phishing_analysis.risk_score as i32);
    let phishing_warning_message = if phishing_analysis.is_suspicious {
        Some(format!(
            "PHISHING RISK DETECTED ({}% confidence). This site shows suspicious patterns.",
            phishing_analysis.risk_score
        ))
    } else {
        None
    };

    match crate::db::insert_scan(
        &state.pool,
        domain,
        "anonymous",
        &format!("{:?}", grade),
        ssl_labs_grade,
        mozilla_grade,
        Some(&format!("{:?}", grade)),
        ssl_time,
        mozilla_time,
        Some(scan_duration_str.parse::<f64>().unwrap_or(0.0)),
        ssl_error,
        mozilla_error,
        None,
        &certificate_json,
        &protocols_json,
        &cipher_suites_json,
        &vulnerabilities_json,
        &key_exchange_json,
        explanation.as_deref(),
        Some(scan_duration_str),
        details_json,
        is_phishing_detected,
        phishing_risk_score,
        phishing_warning_message.as_deref(),
    )
    .await
    {
        Ok(_) => println!("Comprehensive database insert successful for {}", domain),
        Err(e) => println!("Database insert failed for {}: {:?}", domain, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::certificate_parser::ParsedCertificate;

    #[test]
    fn test_parse_grade_from_string() {
        assert_eq!(parse_grade_from_string("APlus"), Grade::APlus);
        assert_eq!(parse_grade_from_string("A"), Grade::A);
        assert_eq!(parse_grade_from_string("B"), Grade::B);
        assert_eq!(parse_grade_from_string("C"), Grade::C);
        assert_eq!(parse_grade_from_string("F"), Grade::F);
        assert_eq!(parse_grade_from_string("Invalid"), Grade::F);
    }

    #[test]
    fn test_assessment_data_new() {
        let data = AssessmentData::new();
        assert_eq!(data.protocols.tls_1_2, "Not Supported");
        assert_eq!(data.protocols.tls_1_3, "Not Supported");
        assert!(!data.grade_input.tls13_supported);
        assert!(!data.grade_input.cert_valid);
    }

    #[test]
    fn test_generate_security_warnings_low_risk() {
        let analysis = crate::services::phishing_detector::PhishingAnalysis {
            is_suspicious: false,
            risk_score: 30,
            detected_patterns: vec![],
            content_warnings: vec![],
            domain_warnings: vec![],
            recommendation: crate::services::phishing_detector::PhishingRecommendation::Safe,
        };

        let warnings = generate_security_warnings(&analysis);
        assert!(!warnings.is_phishing_suspicious);
        assert_eq!(warnings.phishing_risk_score, 30);
        assert!(warnings.warning_message.is_none());
    }

    #[test]
    fn test_generate_security_warnings_high_risk() {
        let analysis = crate::services::phishing_detector::PhishingAnalysis {
            is_suspicious: true,
            risk_score: 85,
            detected_patterns: vec!["Suspicious domain".to_string()],
            content_warnings: vec![],
            domain_warnings: vec![],
            recommendation: crate::services::phishing_detector::PhishingRecommendation::HighRisk,
        };

        let warnings = generate_security_warnings(&analysis);
        assert!(warnings.is_phishing_suspicious);
        assert_eq!(warnings.phishing_risk_score, 85);
        assert!(warnings.warning_message.is_some());
        assert!(
            warnings
                .warning_message
                .unwrap()
                .contains("PHISHING RISK DETECTED")
        );
    }

    #[test]
    fn test_extract_whois_info_for_display() {
        let whois_response = "Creation Date: 2020-01-15T10:30:00Z\nRegistrar: Test Registrar";
        let info = extract_whois_info_for_display(whois_response);

        assert!(info.creation_date.is_some());
        assert!(info.domain_age_days.is_some());
        assert_eq!(info.registrar, Some("Test Registrar".to_string()));
        assert_eq!(info.status, "Established Domain");
    }

    #[test]
    fn test_validate_key_strength() {
        let cert_weak = ParsedCertificate {
            subject: "test".to_string(),
            issuer: "test".to_string(),
            not_before: "2023-01-01".to_string(),
            not_after: "2024-01-01".to_string(),
            key_size: Some("64".to_string()),
            signature_algorithm: "SHA256".to_string(),
            serial_number: "123".to_string(),
            subject_alt_names: vec![],
            expired: false,
            days_until_expiry: Some(-365), // Add missing field
        };

        let cert_strong = ParsedCertificate {
            subject: "test".to_string(),
            issuer: "test".to_string(),
            not_before: "2023-01-01".to_string(),
            not_after: "2024-01-01".to_string(),
            key_size: Some("2048".to_string()),
            signature_algorithm: "SHA256".to_string(),
            serial_number: "123".to_string(),
            subject_alt_names: vec![],
            expired: false,
            days_until_expiry: Some(365), // Add missing field
        };

        assert!(!validate_key_strength(&cert_weak));
        assert!(validate_key_strength(&cert_strong));
    }

    #[tokio::test]
    async fn test_assessment_request_serialization() {
        let request = AssessmentRequest {
            domain: "example.com".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("example.com"));

        let deserialized: AssessmentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.domain, "example.com");
    }

    #[test]
    fn test_certificate_info_default() {
        let cert_info = CertificateInfo::default();
        assert!(cert_info.common_name.is_none());
        assert!(cert_info.issuer.is_none());
        assert!(cert_info.days_until_expiry.is_none());
        assert!(cert_info.subject_alt_names.is_empty());
    }

    #[test]
    fn test_vulnerability_info_assessment() {
        let mut data = AssessmentData::new();
        data.protocols.tls_1_0 = "Supported".to_string();
        data.cipher_suites
            .tls_1_2_suites
            .push("TLS_RSA_WITH_RC4_128_SHA".to_string());

        assess_vulnerabilities(&mut data);

        assert_eq!(data.vulnerabilities.poodle, "Potentially Vulnerable");
        assert_eq!(data.vulnerabilities.beast, "Potentially Vulnerable");
        assert_eq!(data.vulnerabilities.heartbleed, "Unknown");
    }

    #[test]
    fn test_protocol_support_default() {
        let protocols = ProtocolSupport::default();
        assert_eq!(protocols.tls_1_0, "");
        assert_eq!(protocols.tls_1_1, "");
        assert_eq!(protocols.tls_1_2, "");
        assert_eq!(protocols.tls_1_3, "");
    }

    #[test]
    fn test_key_exchange_info_default() {
        let key_exchange = KeyExchangeInfo::default();
        assert!(!key_exchange.supports_forward_secrecy);
        assert!(key_exchange.key_exchange_algorithm.is_none());
        assert!(key_exchange.curve_name.is_none());
    }
}
