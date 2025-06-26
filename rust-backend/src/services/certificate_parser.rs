use serde::Serialize;
use x509_parser::prelude::*;
use x509_parser::time::ASN1Time;

#[derive(Debug, Serialize)]
pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
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
            // Handle the Result from as_str() here.
            // We use `ok().map()` to convert Option<Result<T, E>> to Option<Option<T>>,
            // then `flatten()` to get Option<T>, then unwrap_or for default.
            cn.as_str()
                .ok() // Convert Result<&str, X509Error> to Option<&str> (errors become None)
                .map(|s| s.to_string()) // If Some(&str), convert to Some(String)
                .unwrap_or_else(|| "<invalid CN>".to_string()) // If None (error or actual None), use default
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

    let not_after_raw = cert.validity().not_after;
    let expired = not_after_raw < ASN1Time::now();

    let not_after = not_after_raw
        .to_rfc2822()
        .unwrap_or_else(|_| "<invalid date>".to_string());

    Ok(ParsedCertificate {
        subject,
        issuer,
        not_after,
        expired,
    })
}
