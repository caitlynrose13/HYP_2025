use webpki::{DnsNameRef, EndEntityCert, Time};
use webpki_roots::TLS_SERVER_ROOTS;

use std::time::SystemTime;

use crate::services::errors::TlsError;

//checks if a server's certificate chain is valid and matches the hostname
//uses webpki for certificate validation and hostname matching

// Validates a server's certificate chain and hostname
pub fn validate_server_certificate(
    server_certificates_der: &[Vec<u8>],
    hostname: &str,
) -> Result<(), TlsError> {
    if server_certificates_der.is_empty() {
        return Err(TlsError::CertificateError(
            "No certificates provided by server".to_string(),
        ));
    }

    // The first certificate is the end-entity certificate
    let end_entity_cert = EndEntityCert::try_from(server_certificates_der[0].as_slice())
        .map_err(|e| TlsError::CertificateError(format!("Invalid end-entity cert: {:?}", e)))?;

    // The rest are intermediate certificates
    let intermediates: Vec<&[u8]> = server_certificates_der[1..]
        .iter()
        .map(Vec::as_slice)
        .collect();

    // Get the current time in seconds
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let time = Time::from_seconds_since_unix_epoch(now);

    //create a list of trust anchors from the webpki_roots
    let trust_anchors: Vec<webpki::TrustAnchor> = TLS_SERVER_ROOTS
        .iter()
        .map(|ta| webpki::TrustAnchor {
            subject: ta.subject,
            spki: ta.spki,
            name_constraints: ta.name_constraints,
        })
        .collect();

    // Verify the end-entity certificate against the trust anchors and intermediates
    end_entity_cert.verify_is_valid_tls_server_cert(
        &[],
        &webpki::TlsServerTrustAnchors(&trust_anchors),
        &intermediates,
        time,
    )?;

    // Verify the end-entity certificate matches the hostname (the subject alr name must match the hostname)
    let dns_name = DnsNameRef::try_from_ascii_str(hostname)
        .map_err(|_| TlsError::CertificateError(format!("Invalid hostname: {}", hostname)))?;
    end_entity_cert.verify_is_valid_for_dns_name(dns_name)?;

    println!("Certificate chain and hostname are valid.");
    Ok(())
}
