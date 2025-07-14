use serde::Serialize;
use x509_parser::prelude::*;
use x509_parser::time::ASN1Time;

#[derive(Debug, Serialize)]
pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub expired: bool,
}

pub fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate, String> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("Failed to parse certificate: {}", e))?;

    let subject = cert
        .subject()
        .iter_common_name()
        .next()
        .map(|cn| {
            cn.as_str()
                .ok()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "<invalid CN>".to_string())
        })
        .unwrap_or_else(|| "<no CN>".to_string()); // If no common name found in subject

    let issuer = cert
        .issuer()
        .iter_common_name()
        .next()
        .map(|cn| {
            cn.as_str()
                .ok()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "<invalid CN>".to_string())
        })
        .unwrap_or_else(|| "<no CN>".to_string());

    let not_before_raw = cert.validity().not_before;
    let not_after_raw = cert.validity().not_after;
    let expired = not_after_raw < ASN1Time::now();

    let not_before = not_before_raw
        .to_rfc2822()
        .unwrap_or_else(|_| "<invalid date>".to_string());
    let not_after = not_after_raw
        .to_rfc2822()
        .unwrap_or_else(|_| "<invalid date>".to_string());

    Ok(ParsedCertificate {
        subject,
        issuer,
        not_before,
        not_after,
        expired,
    })
}
