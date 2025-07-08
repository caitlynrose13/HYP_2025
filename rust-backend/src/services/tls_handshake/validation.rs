// src/services/tls_handshake/validation.rs

//NOT DONE

use p256::EncodedPoint;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::services::errors::TlsError;
use crate::services::tls_parser::ServerKeyExchangeParsed;

pub fn verify_server_key_exchange_signature(
    ske: &ServerKeyExchangeParsed,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    cert_chain: &[Vec<u8>],
) -> Result<(), TlsError> {
    println!("    Attempting to verify ServerKeyExchange signature...");

    let cert_der = cert_chain
        .get(0)
        .ok_or_else(|| TlsError::CertificateError("No server certificate provided.".into()))?;

    // `from_der` is now in scope because `FromDer` trait is imported
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| TlsError::CertificateError(format!("Failed to parse server cert: {:?}", e)))?;

    let spki_bytes = cert.tbs_certificate.subject_pki.subject_public_key.data;

    let pub_key_point = EncodedPoint::from_bytes(spki_bytes)
        .map_err(|_| TlsError::CertificateError("Invalid SPKI EC point format.".into()))?;

    let verifying_key = VerifyingKey::from_encoded_point(&pub_key_point).map_err(|e| {
        TlsError::CertificateError(format!("Failed to create VerifyingKey from point: {:?}", e))
    })?;

    let mut hasher = Sha256::new();
    hasher.update(client_random);
    hasher.update(server_random);
    hasher.update(&[ske.curve_type]);
    hasher.update(&(ske.named_curve as u16).to_be_bytes());
    hasher.update(&[ske.public_key.len() as u8]);
    hasher.update(&ske.public_key);
    let message_hash = hasher.finalize();

    if ske.signature_algorithm != [0x04, 0x03] {
        return Err(TlsError::HandshakeFailed(format!(
            "Unsupported signature algorithm: 0x{:02X}{:02X}, expected ECDSA_P256_SHA256 (0x0403)",
            ske.signature_algorithm[0], ske.signature_algorithm[1]
        )));
    }

    if ske.signature.len() != 64 {
        return Err(TlsError::HandshakeFailed(
            "Signature must be exactly 64 bytes (ECDSA P-256)".into(),
        ));
    }

    let signature = Signature::from_slice(&ske.signature)
        .map_err(|e| TlsError::HandshakeFailed(format!("Invalid signature format: {:?}", e)))?;

    verifying_key
        .verify(message_hash.as_slice(), &signature)
        .map_err(|e| {
            TlsError::HandshakeFailed(format!("Signature verification failed: {:?}", e))
        })?;

    println!("    ServerKeyExchange signature successfully verified!");
    Ok(())
}
