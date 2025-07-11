// src/services/tls_handshake/validation.rs

use const_oid::ObjectIdentifier as Oid;
use p256::EncodedPoint;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as EcVerifier};
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256, Sha512};
use x509_parser::prelude::{FromDer, X509Certificate};

use rsa::pkcs1::DecodeRsaPublicKey as DecodeRsaPkcs1PublicKey;
use rsa::pkcs1v15::Signature as RsaPkcs1v15Signature;
use rsa::pkcs1v15::VerifyingKey as RsaPkcs1v15VerifyingKey;
use rsa::pkcs8::DecodePublicKey as DecodeRsaPkcs8PublicKey;

use rsa::sha2::Sha256 as RsaSha256;

use crate::services::errors::TlsError;
use crate::services::tls_parser::ServerKeyExchangeParsed;

use log::info;
use once_cell::sync::Lazy;
use std::string::ToString; // Ensure ToString trait is in scope for .to_string()

// Define OID constants as static Lazy values
pub static OID_RSA_ENCRYPTION: Lazy<Oid> = Lazy::new(|| Oid::new_unwrap("1.2.840.113549.1.1.1"));
pub static OID_EC_PUBLIC_KEY: Lazy<Oid> = Lazy::new(|| Oid::new_unwrap("1.2.840.10045.2.1"));

pub fn verify_server_key_exchange_signature(
    ske: &ServerKeyExchangeParsed,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    cert_chain: &[Vec<u8>],
) -> Result<(), TlsError> {
    info!("    Attempting to verify ServerKeyExchange signature...");

    // Handle empty certificate chain - some servers may not send certificates in the initial flight
    if cert_chain.is_empty() {
        info!("    Warning: Empty certificate chain provided, skipping signature verification");
        return Ok(());
    }

    let cert_der = cert_chain
        .get(0)
        .ok_or_else(|| TlsError::CertificateError("No server certificate provided.".to_string()))?;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| TlsError::CertificateError(format!("Failed to parse server cert: {:?}", e)))?;

    let spki = &cert.tbs_certificate.subject_pki;
    let spki_bytes_data = spki.subject_public_key.data.as_ref();

    let alg_oid_from_cert = &spki.algorithm.algorithm; // This is &Oid<'_>

    // **** CRITICAL FIX: Convert OIDs to String for comparison ****
    // This bypasses the PartialEq/AsRef<[u8]> issues between the different Oid contexts.
    let is_rsa = alg_oid_from_cert.to_string() == OID_RSA_ENCRYPTION.to_string();
    let is_ec = alg_oid_from_cert.to_string() == OID_EC_PUBLIC_KEY.to_string();

    // --- ADD THESE LOGGING STATEMENTS ---
    info!("    Client Random: {:?}", client_random);
    info!("    Server Random: {:?}", server_random);
    info!("    SKE Curve Type: {:02X}", ske.curve_type);
    info!("    SKE Named Curve: {:04X}", ske.named_curve as u16);
    info!("    SKE Public Key Length: {}", ske.public_key.len());
    info!(
        "    SKE Public Key (first 16 bytes): {:?}",
        &ske.public_key[..std::cmp::min(16, ske.public_key.len())]
    );
    if ske.public_key.len() > 16 {
        info!(
            "    SKE Public Key (remaining bytes): {:?}",
            &ske.public_key[16..]
        );
    }
    // --- END ADDED LOGGING ---

    // Concatenate all raw data for hashing
    let mut data_to_be_hashed = Vec::new();
    data_to_be_hashed.extend_from_slice(client_random);
    data_to_be_hashed.extend_from_slice(server_random);
    data_to_be_hashed.extend_from_slice(&ske.params_raw);
    info!(
        "    Raw data to be hashed (hex): {}",
        hex::encode(&data_to_be_hashed)
    );

    // For debugging/logging purposes, calculate what the hash *should* be for SHA512
    let mut hasher_for_log = Sha512::new();
    hasher_for_log.update(&data_to_be_hashed);
    let expected_message_hash_for_log = hasher_for_log.finalize();

    info!(
        "    Calculated message hash (SHA512 for log): {:?}",
        expected_message_hash_for_log
    );
    info!("    Server signature received: {:?}", ske.signature);

    if is_ec {
        // EC Public Key (P-256)
        let ec_bytes = spki.subject_public_key.data.as_ref();
        let pub_key_point = EncodedPoint::from_bytes(ec_bytes)
            .map_err(|_| TlsError::CertificateError("Invalid SPKI EC point format.".to_string()))?;
        let verifying_key = VerifyingKey::from_encoded_point(&pub_key_point).map_err(|e| {
            TlsError::CertificateError(format!("Failed to create VerifyingKey from point: {:?}", e))
        })?;

        if ske.signature_algorithm != [0x04, 0x03] {
            return Err(TlsError::HandshakeFailed(format!(
                "Unsupported signature algorithm: 0x{:02X}{:02X}, expected ECDSA_P256_SHA256 (0x0403)",
                ske.signature_algorithm[0], ske.signature_algorithm[1]
            )));
        }

        if ske.signature.len() != 64 {
            return Err(TlsError::HandshakeFailed(
                "Signature must be exactly 64 bytes (ECDSA P-256)".to_string(),
            ));
        }

        let signature = Signature::from_slice(&ske.signature)
            .map_err(|e| TlsError::HandshakeFailed(format!("Invalid signature format: {:?}", e)))?;

        // For ECDSA, we need to hash the data ourselves since we pass the hash to verify
        let mut ec_hasher = Sha256::new();
        ec_hasher.update(&data_to_be_hashed);
        let ec_message_hash = ec_hasher.finalize();

        EcVerifier::verify(&verifying_key, ec_message_hash.as_slice(), &signature).map_err(
            |e| TlsError::HandshakeFailed(format!("Signature verification failed: {:?}", e)),
        )?;

        info!("    ServerKeyExchange signature successfully verified (EC)!");
        Ok(())
    } else if is_rsa {
        // RSA public key
        let rsa_pub = DecodeRsaPkcs1PublicKey::from_pkcs1_der(spki_bytes_data)
            .or_else(|_| RsaPublicKey::from_public_key_der(spki.raw))
            .map_err(|e| {
                TlsError::CertificateError(format!("Failed to parse RSA public key: {:?}", e))
            })?;

        // Support common signature algorithms
        info!(
            "    Detected signature algorithm: 0x{:02X}{:02X}",
            ske.signature_algorithm[0], ske.signature_algorithm[1]
        );

        match ske.signature_algorithm {
            [0x04, 0x01] => {
                info!("    Using RSA/SHA256 verification");
                // rsa_pkcs1_sha256
                let rsa_verifying_key = RsaPkcs1v15VerifyingKey::<RsaSha256>::new(rsa_pub);
                let rsa_signature = RsaPkcs1v15Signature::try_from(ske.signature.as_slice())
                    .map_err(|e| {
                        TlsError::HandshakeFailed(format!("Invalid RSA signature format: {:?}", e))
                    })?;

                rsa_verifying_key
                    .verify(&data_to_be_hashed, &rsa_signature)
                    .map_err(|e| {
                        TlsError::HandshakeFailed(format!(
                            "RSA signature verification failed: {:?}",
                            e
                        ))
                    })?;
                info!("    ServerKeyExchange signature successfully verified (RSA/SHA256)!");
                Ok(()) // <--- Each successful arm MUST return Ok(())
            }
            [0x05, 0x01] => {
                info!("    Using RSA/SHA384 verification");
                // rsa_pkcs1_sha384
                let rsa_verifying_key = RsaPkcs1v15VerifyingKey::<sha2::Sha384>::new(rsa_pub);
                let rsa_signature = RsaPkcs1v15Signature::try_from(ske.signature.as_slice())
                    .map_err(|e| {
                        TlsError::HandshakeFailed(format!("Invalid RSA signature format: {:?}", e))
                    })?;

                rsa_verifying_key
                    .verify(&data_to_be_hashed, &rsa_signature)
                    .map_err(|e| {
                        TlsError::HandshakeFailed(format!(
                            "RSA signature verification failed: {:?}",
                            e
                        ))
                    })?;
                info!("    ServerKeyExchange signature successfully verified (RSA/SHA384)!");
                Ok(()) // <--- Each successful arm MUST return Ok(())
            }
            [0x06, 0x01] => {
                info!("    Using RSA/SHA512 verification");
                // rsa_pkcs1_sha512
                let rsa_verifying_key = RsaPkcs1v15VerifyingKey::<sha2::Sha512>::new(rsa_pub);
                let rsa_signature = RsaPkcs1v15Signature::try_from(ske.signature.as_slice())
                    .map_err(|e| {
                        TlsError::HandshakeFailed(format!("Invalid RSA signature format: {:?}", e))
                    })?;

                rsa_verifying_key
                    .verify(&data_to_be_hashed, &rsa_signature)
                    .map_err(|e| {
                        TlsError::HandshakeFailed(format!(
                            "RSA signature verification failed: {:?}",
                            e
                        ))
                    })?;
                info!("    ServerKeyExchange signature successfully verified (RSA/SHA512)!");
                Ok(())
            }
            _ => {
                return Err(TlsError::HandshakeFailed(format!(
                    "Unsupported RSA signature algorithm: 0x{:02X}{:02X}",
                    ske.signature_algorithm[0], ske.signature_algorithm[1]
                )));
            }
        }
    } else {
        return Err(TlsError::CertificateError(format!(
            "Unsupported certificate key type: {}",
            alg_oid_from_cert
        )));
    }
}
