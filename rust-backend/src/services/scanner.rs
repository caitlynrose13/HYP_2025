use crate::models::scan_result::ScanResult;
use crate::services::tls_handshake::TlsVersion;
use crate::services::{certificate_parser, tls_handshake, tls_parser};

#[derive(Debug)]
pub enum ScanError {
    Handshake(String),
    Parse(String),
}

pub fn scan_domain(domain: &str) -> Result<ScanResult, ScanError> {
    let raw_tls =
        tls_handshake::perform_tls_handshake(domain, TlsVersion::Tls1_2).map_err(|e| {
            println!("TLS HANDSHAKE FAILED {:?}", e);
            ScanError::Handshake(format!("{:?}", e))
        })?;

    println!("RAW TLS RESPONSE: {:?}", raw_tls);
    println!("RAW HEX: {}", hex::encode(&raw_tls));

    let parsed_tls = tls_parser::parse_tls_response(&raw_tls).map_err(|e| {
        println!("TLS PARSING FAILED {:?}", e);
        ScanError::Handshake(format!("{:?}", e))
    })?;

    let cert_info = parsed_tls
        .cert_der
        .as_ref()
        .map(|der| certificate_parser::parse_certificate(der))
        .transpose()
        .map_err(|e| {
            println!("CERT PARSING FAILED {:?}", e);
            ScanError::Handshake(format!("cert parse error{:?}", e))
        })?;

    println!("SUCCESS {}", domain);
    Ok(ScanResult {
        domain: domain.to_string(),
        version: parsed_tls.negotiated_version,
        cert_info,
    })
}
