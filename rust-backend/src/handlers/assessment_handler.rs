use crate::services::certificate_parser::parse_certificate;
use crate::services::tls_parser::TlsVersion;
use axum::{Json, http::StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct AssessmentRequest {
    pub domain: String,
}

#[derive(Serialize)]
pub struct AssessmentResponse {
    pub domain: String,
    pub message: String,
    pub cipher_suite: Option<String>,
    pub tls_version: Option<String>,
    //info for detailed tab
    pub cert_common_name: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_valid_from: Option<String>,
    pub cert_valid_to: Option<String>,
    pub cert_key_size: Option<String>,
    pub cert_signature_algorithm: Option<String>,
    pub cert_chain_trust: Option<String>,
}

pub async fn assess_domain(
    Json(payload): Json<AssessmentRequest>,
) -> (StatusCode, Json<AssessmentResponse>) {
    let domain = payload.domain;
    println!(
        "[DEBUG] assess_domain: Starting handshake for domain: {}",
        domain
    );
    match crate::services::tls_handshake::client_handshake::perform_tls_handshake_full_with_cert(
        &domain,
        TlsVersion::TLS1_2,
    ) {
        Ok((state, cert_der)) => {
            println!(
                "[DEBUG] assess_domain: Handshake complete. Got cert_der: {}",
                cert_der.as_ref().map(|v| v.len()).unwrap_or(0)
            );
            let parsed = cert_der.as_ref().and_then(|der| {
                println!(
                    "[DEBUG] assess_domain: Parsing certificate ({} bytes)...",
                    der.len()
                );
                let res = parse_certificate(der);
                match &res {
                    Ok(cert) => println!(
                        "[DEBUG] assess_domain: Certificate parsed: subject='{}', issuer='{}'",
                        cert.subject, cert.issuer
                    ),
                    Err(e) => println!("[DEBUG] assess_domain: Certificate parse error: {}", e),
                }
                res.ok()
            });
            println!("[DEBUG] assess_domain: Returning success response");
            (
                StatusCode::OK,
                Json(AssessmentResponse {
                    domain,
                    message: "TLS handshake succeeded".to_string(),
                    cipher_suite: Some(state.negotiated_cipher_suite.name.to_string()),
                    tls_version: Some(format!("{:?}", state.negotiated_tls_version)),
                    cert_common_name: parsed.as_ref().map(|c| c.subject.clone()),
                    cert_issuer: parsed.as_ref().map(|c| c.issuer.clone()),
                    cert_valid_from: parsed.as_ref().map(|c| c.not_before.clone()),
                    cert_valid_to: parsed.as_ref().map(|c| c.not_after.clone()),
                    cert_key_size: None, // Not parsed in current parser
                    cert_signature_algorithm: None, // Not parsed in current parser
                    cert_chain_trust: Some(if parsed.as_ref().map_or(false, |c| !c.expired) {
                        "Trusted".to_string()
                    } else {
                        "Expired/Untrusted".to_string()
                    }),
                }),
            )
        }
        Err(e) => {
            println!("[DEBUG] assess_domain: Handshake failed: {:?}", e);
            println!("[DEBUG] assess_domain: Returning error response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AssessmentResponse {
                    domain,
                    message: format!("TLS handshake failed: {:?}", e),
                    cipher_suite: None,
                    tls_version: None,
                    cert_common_name: None,
                    cert_issuer: None,
                    cert_valid_from: None,
                    cert_valid_to: None,
                    cert_key_size: None,
                    cert_signature_algorithm: None,
                    cert_chain_trust: None,
                }),
            )
        }
    }
}
