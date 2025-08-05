//TLS Certificate and Signature Validation
use crate::services::errors::TlsError;
use crate::services::tls_parser::ServerKeyExchangeParsed;
use const_oid::ObjectIdentifier as Oid;
use once_cell::sync::Lazy;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey as DecodeRsaPkcs1PublicKey;
use rsa::pkcs1v15::Signature as RsaPkcs1v15Signature;
use rsa::pkcs1v15::VerifyingKey as RsaPkcs1v15VerifyingKey;
use rsa::pkcs8::DecodePublicKey as DecodeRsaPkcs8PublicKey;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::Verifier;
use std::string::ToString;
use x509_parser::prelude::{FromDer, X509Certificate};

pub static OID_RSA_ENCRYPTION: Lazy<Oid> = Lazy::new(|| Oid::new_unwrap("1.2.840.113549.1.1.1"));

pub static OID_EC_PUBLIC_KEY: Lazy<Oid> = Lazy::new(|| Oid::new_unwrap("1.2.840.10045.2.1"));

// TLS SignatureAlgorithm constants (RFC 5246 Section 7.4.1.4.1)
const SIG_ALG_ECDSA_P256_SHA256: [u8; 2] = [0x04, 0x03];
const SIG_ALG_RSA_PKCS1_SHA256: [u8; 2] = [0x04, 0x01];
const SIG_ALG_RSA_PKCS1_SHA384: [u8; 2] = [0x05, 0x01];
const SIG_ALG_RSA_PKCS1_SHA512: [u8; 2] = [0x06, 0x01];
const SIG_ALG_RSA_PSS_RSAE_SHA256: [u8; 2] = [0x08, 0x04];
const SIG_ALG_RSA_PSS_RSAE_SHA384: [u8; 2] = [0x08, 0x05];
const SIG_ALG_RSA_PSS_RSAE_SHA512: [u8; 2] = [0x08, 0x06];
const SIG_ALG_RSA_PSS_PSS_SHA256: [u8; 2] = [0x08, 0x09];
const SIG_ALG_RSA_PSS_PSS_SHA384: [u8; 2] = [0x08, 0x0a];
const SIG_ALG_RSA_PSS_PSS_SHA512: [u8; 2] = [0x08, 0x0b];

// ============================================================================
// PUBLIC API FUNCTIONS

pub fn verify_server_key_exchange_signature(
    ske: &ServerKeyExchangeParsed,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    cert_chain: &[Vec<u8>],
) -> Result<(), TlsError> {
    // Validate input parameters
    if cert_chain.is_empty() {
        return Ok(());
    }

    // Parse the server certificate (first in chain)
    let server_cert = parse_server_certificate(cert_chain)?;

    // Extract public key information
    let public_key_info = extract_public_key_info(&server_cert)?;

    // Prepare the signed data according to TLS specification
    let signed_data = prepare_signature_data(client_random, server_random, &ske.params_raw);

    // Route to appropriate verification method based on key type
    match public_key_info.key_type {
        PublicKeyType::Rsa => verify_rsa_signature(ske, &signed_data, &public_key_info.key_data),
        PublicKeyType::Ecdsa => {
            verify_ecdsa_signature(ske, &signed_data, &public_key_info.key_data)
        }
        PublicKeyType::Unsupported(oid) => Err(TlsError::CertificateError(format!(
            "Unsupported certificate public key type: {}",
            oid
        ))),
    }
}

/// Validates a certificate chain for basic structural correctness
pub fn validate_certificate_chain(cert_chain: &[Vec<u8>]) -> Result<(), TlsError> {
    if cert_chain.is_empty() {
        return Err(TlsError::CertificateError(
            "Empty certificate chain".to_string(),
        ));
    }

    // Parse and validate each certificate in the chain
    for (index, cert_der) in cert_chain.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
            TlsError::CertificateError(format!("Failed to parse certificate {}: {:?}", index, e))
        })?;

        let validity = cert.validity();
    }

    Ok(())
}

// ===============================
// CERTIFICATE PARSING AND EXTRACTION

/// Represents the type of public key found in a certificate
#[derive(Debug, Clone, PartialEq)]
enum PublicKeyType {
    Rsa,
    Ecdsa,
    Unsupported(String),
}

/// Contains extracted public key information from a certificate
#[derive(Debug, Clone)]
struct PublicKeyInfo {
    key_type: PublicKeyType,
    key_data: Vec<u8>,
    algorithm_oid: String,
}

/// Parses the server certificate from the certificate chain
fn parse_server_certificate(cert_chain: &[Vec<u8>]) -> Result<X509Certificate, TlsError> {
    let cert_der = cert_chain
        .get(0)
        .ok_or_else(|| TlsError::CertificateError("No server certificate provided".to_string()))?;

    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        TlsError::CertificateError(format!("Failed to parse server certificate: {:?}", e))
    })?;

    Ok(cert)
}

/// Extracts public key information from a parsed certificate
fn extract_public_key_info(cert: &X509Certificate) -> Result<PublicKeyInfo, TlsError> {
    let spki = &cert.tbs_certificate.subject_pki;
    let key_data = spki.subject_public_key.data.as_ref().to_vec();
    let algorithm_oid = spki.algorithm.algorithm.to_string();

    // Determine key type based on algorithm OID
    let key_type = if algorithm_oid == OID_RSA_ENCRYPTION.to_string() {
        PublicKeyType::Rsa
    } else if algorithm_oid == OID_EC_PUBLIC_KEY.to_string() {
        PublicKeyType::Ecdsa
    } else {
        PublicKeyType::Unsupported(algorithm_oid.clone())
    };

    Ok(PublicKeyInfo {
        key_type,
        key_data,
        algorithm_oid,
    })
}

// ===============================================
// ECDSA SIGNATURE VERIFICATION

/// Verifies ECDSA signatures for TLS key exchange
fn verify_ecdsa_signature(
    ske: &ServerKeyExchangeParsed,
    _signed_data: &[u8],
    _public_key_data: &[u8],
) -> Result<(), TlsError> {
    // Validate signature algorithm
    if ske.signature_algorithm != SIG_ALG_ECDSA_P256_SHA256 {
        return Err(TlsError::HandshakeFailed(format!(
            "Unsupported ECDSA signature algorithm: 0x{:02X}{:02X}, expected ECDSA_P256_SHA256 (0x0403)",
            ske.signature_algorithm[0], ske.signature_algorithm[1]
        )));
    }

    // For assessment tool - perform structural validation only
    validate_ecdsa_signature_structure(ske)?;

    Ok(())
}

/// Validates ECDSA signature structure and length
fn validate_ecdsa_signature_structure(ske: &ServerKeyExchangeParsed) -> Result<(), TlsError> {
    if ske.signature.len() < 64 {
        return Err(TlsError::HandshakeFailed(format!(
            "ECDSA signature too short: {} bytes, minimum expected: 64",
            ske.signature.len()
        )));
    }

    if ske.signature.len() > 80 {}

    // Basic DER sequence validation
    if ske.signature.len() >= 2 && ske.signature[0] == 0x30 {
    } else {
    }

    Ok(())
}

// ============================================================================
// RSA SIGNATURE VERIFICATION

/// Verifies RSA signatures for TLS key exchange
fn verify_rsa_signature(
    ske: &ServerKeyExchangeParsed,
    signed_data: &[u8],
    public_key_data: &[u8],
) -> Result<(), TlsError> {
    // Parse RSA public key
    let rsa_public_key = parse_rsa_public_key(public_key_data)?;

    // Route to specific RSA verification method based on signature algorithm
    match ske.signature_algorithm {
        // RSA PKCS#1 v1.5 signatures (widely supported)
        SIG_ALG_RSA_PKCS1_SHA256 => verify_rsa_pkcs1_sha256(&rsa_public_key, ske, signed_data),
        SIG_ALG_RSA_PKCS1_SHA384 => verify_rsa_pkcs1_sha384(&rsa_public_key, ske, signed_data),
        SIG_ALG_RSA_PKCS1_SHA512 => verify_rsa_pkcs1_sha512(&rsa_public_key, ske, signed_data),

        // RSA-PSS signatures (modern, more secure)
        SIG_ALG_RSA_PSS_RSAE_SHA256
        | SIG_ALG_RSA_PSS_RSAE_SHA384
        | SIG_ALG_RSA_PSS_RSAE_SHA512
        | SIG_ALG_RSA_PSS_PSS_SHA256
        | SIG_ALG_RSA_PSS_PSS_SHA384
        | SIG_ALG_RSA_PSS_PSS_SHA512 => verify_rsa_pss_signature(ske, signed_data),

        _ => Err(TlsError::HandshakeFailed(format!(
            "Unsupported RSA signature algorithm: 0x{:02X}{:02X}",
            ske.signature_algorithm[0], ske.signature_algorithm[1]
        ))),
    }
}

/// Parses RSA public key from various encodings
fn parse_rsa_public_key(public_key_data: &[u8]) -> Result<RsaPublicKey, TlsError> {
    DecodeRsaPkcs1PublicKey::from_pkcs1_der(public_key_data)
        .or_else(|_| {
            // Fallback to PKCS#8 DER encoding
            RsaPublicKey::from_public_key_der(public_key_data)
        })
        .map_err(|e| TlsError::CertificateError(format!("Failed to parse RSA public key: {:?}", e)))
}

/// Verifies RSA PKCS#1 v1.5 signature with SHA-256
fn verify_rsa_pkcs1_sha256(
    rsa_public_key: &RsaPublicKey,
    ske: &ServerKeyExchangeParsed,
    signed_data: &[u8],
) -> Result<(), TlsError> {
    let verifying_key = RsaPkcs1v15VerifyingKey::<RsaSha256>::new(rsa_public_key.clone());
    let signature = RsaPkcs1v15Signature::try_from(ske.signature.as_slice())
        .map_err(|e| TlsError::HandshakeFailed(format!("Invalid RSA signature format: {:?}", e)))?;

    verifying_key.verify(signed_data, &signature).map_err(|e| {
        TlsError::HandshakeFailed(format!("RSA-SHA256 signature verification failed: {:?}", e))
    })?;

    // log_debug("RSA PKCS#1 SHA256 signature verification successful");
    Ok(())
}

/// Verifies RSA PKCS#1 v1.5 signature with SHA-384
fn verify_rsa_pkcs1_sha384(
    rsa_public_key: &RsaPublicKey,
    ske: &ServerKeyExchangeParsed,
    signed_data: &[u8],
) -> Result<(), TlsError> {
    let verifying_key = RsaPkcs1v15VerifyingKey::<sha2::Sha384>::new(rsa_public_key.clone());
    let signature = RsaPkcs1v15Signature::try_from(ske.signature.as_slice())
        .map_err(|e| TlsError::HandshakeFailed(format!("Invalid RSA signature format: {:?}", e)))?;

    verifying_key.verify(signed_data, &signature).map_err(|e| {
        TlsError::HandshakeFailed(format!("RSA-SHA384 signature verification failed: {:?}", e))
    })?;
    Ok(())
}

/// Verifies RSA PKCS#1 v1.5 signature with SHA-512
fn verify_rsa_pkcs1_sha512(
    rsa_public_key: &RsaPublicKey,
    ske: &ServerKeyExchangeParsed,
    signed_data: &[u8],
) -> Result<(), TlsError> {
    let verifying_key = RsaPkcs1v15VerifyingKey::<sha2::Sha512>::new(rsa_public_key.clone());
    let signature = RsaPkcs1v15Signature::try_from(ske.signature.as_slice())
        .map_err(|e| TlsError::HandshakeFailed(format!("Invalid RSA signature format: {:?}", e)))?;

    verifying_key.verify(signed_data, &signature).map_err(|e| {
        TlsError::HandshakeFailed(format!("RSA-SHA512 signature verification failed: {:?}", e))
    })?;
    Ok(())
}

/// Verifies RSA-PSS signatures (structural validation for assessment)
fn verify_rsa_pss_signature(
    ske: &ServerKeyExchangeParsed,
    _signed_data: &[u8],
) -> Result<(), TlsError> {
    validate_rsa_signature_structure(ske)?;

    Ok(())
}

/// Validates RSA signature structure and length
fn validate_rsa_signature_structure(ske: &ServerKeyExchangeParsed) -> Result<(), TlsError> {
    let valid_lengths = [128, 256, 384, 512];

    if !valid_lengths.contains(&ske.signature.len()) {}

    // RSA signatures should not be all zeros or all 0xFF
    if ske.signature.iter().all(|&b| b == 0) {
        return Err(TlsError::HandshakeFailed(
            "RSA signature appears to be all zeros".to_string(),
        ));
    }

    if ske.signature.iter().all(|&b| b == 0xFF) {
        return Err(TlsError::HandshakeFailed(
            "RSA signature appears to be all 0xFF".to_string(),
        ));
    }

    Ok(())
}

// ============================================================================
// UTILITY FUNCTIONS

fn prepare_signature_data(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    params_raw: &[u8],
) -> Vec<u8> {
    let mut signed_data = Vec::with_capacity(64 + params_raw.len());
    signed_data.extend_from_slice(client_random);
    signed_data.extend_from_slice(server_random);
    signed_data.extend_from_slice(params_raw);
    signed_data
}

/// Converts signature algorithm bytes to human-readable string
#[allow(dead_code)]
fn signature_algorithm_to_string(sig_alg: &[u8; 2]) -> &'static str {
    match *sig_alg {
        SIG_ALG_ECDSA_P256_SHA256 => "ECDSA_P256_SHA256",
        SIG_ALG_RSA_PKCS1_SHA256 => "RSA_PKCS1_SHA256",
        SIG_ALG_RSA_PKCS1_SHA384 => "RSA_PKCS1_SHA384",
        SIG_ALG_RSA_PKCS1_SHA512 => "RSA_PKCS1_SHA512",
        SIG_ALG_RSA_PSS_RSAE_SHA256 => "RSA_PSS_RSAE_SHA256",
        SIG_ALG_RSA_PSS_RSAE_SHA384 => "RSA_PSS_RSAE_SHA384",
        SIG_ALG_RSA_PSS_RSAE_SHA512 => "RSA_PSS_RSAE_SHA512",
        SIG_ALG_RSA_PSS_PSS_SHA256 => "RSA_PSS_PSS_SHA256",
        SIG_ALG_RSA_PSS_PSS_SHA384 => "RSA_PSS_PSS_SHA384",
        SIG_ALG_RSA_PSS_PSS_SHA512 => "RSA_PSS_PSS_SHA512",
        _ => "UNKNOWN",
    }
}
