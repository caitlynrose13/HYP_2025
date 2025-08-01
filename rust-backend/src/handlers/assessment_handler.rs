use crate::AppState;
use crate::services::certificate_parser::parse_certificate;
use crate::services::openssl_probe::{test_tls10, test_tls11};
use crate::services::security_grader::{Grade, GradeInput};
use crate::services::tls_parser::TlsVersion;
use axum::extract::{Json, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

// ====================================
// REQUEST/RESPONSE MODELS

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

// ======================
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

// ===========================================
// MAIN ASSESSMENT HANDLER

pub async fn assess_domain(
    State(state): State<AppState>,
    Json(payload): Json<AssessmentRequest>,
) -> (StatusCode, Json<AssessmentResponse>) {
    let scan_start = std::time::Instant::now();
    let domain = payload.domain.trim();

    // Check for cached result first
    if let Some(cached_response) = check_cached_scan(&state, domain).await {
        return cached_response;
    }

    println!("=== STARTING NEW TLS ASSESSMENT ===");
    println!("Domain: {}", domain);
    println!(
        "Timestamp: {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    // Initialize data structures
    let mut assessment_data = AssessmentData::new();

    // Perform HSTS check
    let hsts_supported = check_hsts_support(domain).await;
    assessment_data.grade_input.hsts = hsts_supported;

    // Run TLS assessments
    assess_tls_protocols(domain, &mut assessment_data).await;

    // Calculate final grade
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

    // Store result in database
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

    // Return response
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

// ==========================================
// HELPER STRUCTURES

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
                cipher_is_strong: false,
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

// ============================
// CACHED SCAN HANDLING

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

// ================================================
// TLS PROTOCOL ASSESSMENT

async fn assess_tls_protocols(domain: &str, data: &mut AssessmentData) {
    // Test TLS 1.2
    assess_tls12(domain, data).await;

    // Test TLS 1.3
    assess_tls13(domain, data).await;

    // Test legacy protocols
    assess_legacy_protocols(domain, data);

    // Assess vulnerabilities based on protocol support
    assess_vulnerabilities(data);
}

async fn assess_tls12(domain: &str, data: &mut AssessmentData) {
    let tls12_result =
        crate::services::tls_handshake::client_handshake::perform_tls_handshake_full_with_cert(
            domain,
            TlsVersion::TLS1_2,
        );

    match tls12_result {
        Ok((state, cert_der)) => {
            println!("✓ TLS 1.2 handshake succeeded for {}", domain);
            data.protocols.tls_1_2 = "Supported".to_string();
            data.grade_input.tls12_supported = true;

            let suite_name = crate::services::tls_parser::get_cipher_suite_name(
                &state.negotiated_cipher_suite.id,
            );
            data.cipher_suites.preferred_suite = Some(suite_name.clone());
            data.cipher_suites.tls_1_2_suites.push(suite_name.clone());

            if !data.grade_input.cipher_is_strong {
                data.grade_input.cipher_is_strong = is_cipher_suite_strong(&suite_name);
            }

            if suite_name.contains("ECDHE") {
                data.grade_input.forward_secrecy = true;
                data.key_exchange.supports_forward_secrecy = true;
                data.key_exchange.key_exchange_algorithm = Some("ECDHE".to_string());
                data.key_exchange.curve_name = Some("P-256".to_string());
            }

            if let Some(cert_der) = cert_der {
                process_certificate(&cert_der, &mut data.certificate_info, &mut data.grade_input);
            }
        }
        Err(e) => {
            println!("✗ TLS 1.2 handshake failed for {}: {:?}", domain, e);
        }
    }
}

async fn assess_tls13(domain: &str, data: &mut AssessmentData) {
    let tls13_result =
        crate::services::tls_handshake::tls13::client::perform_tls13_handshake_full_with_cert(
            domain,
        );

    match tls13_result {
        Ok((state, cert_der_opt)) => {
            println!("✓ TLS 1.3 handshake succeeded for {}", domain);
            data.protocols.tls_1_3 = "Supported".to_string();
            data.grade_input.tls13_supported = true;
            data.grade_input.cipher_is_strong = true; // TLS 1.3 cipher suites are always strong

            if !data.grade_input.forward_secrecy {
                data.grade_input.forward_secrecy = true;
                data.key_exchange.supports_forward_secrecy = true;
            }

            let suite_name =
                crate::services::tls_parser::get_cipher_suite_name(&state.negotiated_cipher_suite);
            data.cipher_suites.preferred_suite = Some(suite_name.clone());
            data.cipher_suites.tls_1_3_suites.push(suite_name);

            if let Some(cert_der) = cert_der_opt {
                process_certificate(&cert_der, &mut data.certificate_info, &mut data.grade_input);
            }
        }
        Err(e) => {
            println!("✗ TLS 1.3 handshake failed: {:?}", e);
        }
    }
}

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

// ==============================
// HELPER FUNCTIONS

async fn check_hsts_support(domain: &str) -> bool {
    if let Ok(resp) = reqwest::get(format!("https://{}", domain)).await {
        resp.headers().get("strict-transport-security").is_some()
    } else {
        false
    }
}

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
        cert_info.chain_trust = Some(if !parsed_cert.expired {
            "Trusted".to_string()
        } else {
            "Expired".to_string()
        });

        grade_input.cert_valid = !parsed_cert.expired;
        grade_input.cert_expired = parsed_cert.expired;

        if !parsed_cert.expired && cert_info.chain_trust == Some("Trusted".to_string()) {
            grade_input.cert_key_strength_ok = true;
        }

        calculate_days_until_expiry(cert_info);
    }
}

fn calculate_days_until_expiry(cert_info: &mut CertificateInfo) {
    if let Some(valid_to) = &cert_info.valid_to {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(valid_to, "%Y-%m-%dT%H:%M:%SZ") {
            let now = chrono::Utc::now().naive_utc();
            cert_info.days_until_expiry = Some((dt - now).num_days());
        } else if let Ok(date) = chrono::NaiveDate::parse_from_str(valid_to, "%Y-%m-%d") {
            let now = chrono::Utc::now().date_naive();
            cert_info.days_until_expiry = Some((date - now).num_days());
        }
    }
}

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
        Ok(_) => println!("[DEBUG]Database insert successful for {}", domain),
        Err(e) => println!("[ERROR]Database insert failed for {}: {:?}", domain, e),
    }
}

fn parse_grade_from_string(grade_str: &str) -> Grade {
    match grade_str {
        "APlus" => Grade::APlus,
        "A" => Grade::A,
        "AMinus" => Grade::AMinus,
        "B" => Grade::B,
        "C" => Grade::C,
        "F" => Grade::F,
        _ => Grade::F,
    }
}

fn get_assessment_message(grade_input: &GradeInput) -> String {
    if !grade_input.tls12_supported && !grade_input.tls13_supported {
        "TLS assessment completed with limited support".to_string()
    } else {
        "TLS assessment completed".to_string()
    }
}

fn is_cipher_suite_strong(cipher_suite_name: &str) -> bool {
    let cipher_lower = cipher_suite_name.to_lowercase();

    // TLS 1.3 cipher suites are all strong by design
    if cipher_lower.contains("tls_aes") || cipher_lower.contains("tls_chacha20") {
        return true;
    }

    // For TLS 1.2, check for strong characteristics
    let has_forward_secrecy = cipher_lower.contains("ecdhe") || cipher_lower.contains("dhe");
    let has_strong_encryption = cipher_lower.contains("aes_256_gcm")
        || cipher_lower.contains("aes_128_gcm")
        || cipher_lower.contains("chacha20");

    // Avoid weak algorithms
    let has_weak_elements = cipher_lower.contains("md5")
        || cipher_lower.contains("sha1")
        || cipher_lower.contains("des")
        || cipher_lower.contains("rc4")
        || cipher_lower.contains("null")
        || cipher_lower.contains("export");

    has_forward_secrecy && has_strong_encryption && !has_weak_elements
}
