use crate::models::scan_result::ScanResult;
use crate::services::tls_handshake::TlsVersion;
use crate::services::{certificate_parser, tls_handshake, tls_parser};

#[derive(Debug)]
pub enum ScanError {
    Handshake(String),
    Parse(String),
}

pub fn scan_domain(domain: &str) -> Result<ScanResult, ScanError> {
    let raw_tls = tls_handshake::perform_tls_handshake(domain, TlsVersion::Tls1_3)
        .map_err(|e| ScanError::Handshake(format!("{:?}", e)))?;

    let parsed_tls = tls_parser::parse_tls_response(&raw_tls)
        .map_err(|e| ScanError::Parse(format!("{:?}", e)))?;

    let cert_info = parsed_tls
        .cert_der
        .as_ref()
        .map(|der| certificate_parser::parse_certificate(der))
        .transpose()
        .map_err(|e| ScanError::Parse(format!("cert parse error: {:?}", e)))?;

    Ok(ScanResult {
        domain: domain.to_string(),
        version: parsed_tls.negotiated_version,
        cert_info,
    })
}
