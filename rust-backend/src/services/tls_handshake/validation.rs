use crate::services::errors::TlsError;
use crate::services::tls_parser::ServerKeyExchangeParsed;
use const_oid::ObjectIdentifier as Oid;
use p256::EncodedPoint;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as EcVerifier};
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey as DecodeRsaPkcs1PublicKey;
use rsa::pkcs1v15::Signature as RsaPkcs1v15Signature;
use rsa::pkcs1v15::VerifyingKey as RsaPkcs1v15VerifyingKey;
use rsa::pkcs8::DecodePublicKey as DecodeRsaPkcs8PublicKey;
use rsa::sha2::Sha256 as RsaSha256;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use once_cell::sync::Lazy;
use std::string::ToString;

// Define OID constants as static Lazy values
pub static OID_RSA_ENCRYPTION: Lazy<Oid> = Lazy::new(|| Oid::new_unwrap("1.2.840.113549.1.1.1"));
pub static OID_EC_PUBLIC_KEY: Lazy<Oid> = Lazy::new(|| Oid::new_unwrap("1.2.840.10045.2.1"));

pub fn verify_server_key_exchange_signature(
    ske: &ServerKeyExchangeParsed,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    cert_chain: &[Vec<u8>],
) -> Result<(), TlsError> {
    // Handle empty certificate chain
    if cert_chain.is_empty() {
        return Ok(());
    }

    let cert_der = cert_chain
        .get(0)
        .ok_or_else(|| TlsError::CertificateError("No server certificate provided.".to_string()))?;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| TlsError::CertificateError(format!("Failed to parse server cert: {:?}", e)))?;

    let spki = &cert.tbs_certificate.subject_pki;
    let spki_bytes_data = spki.subject_public_key.data.as_ref();

    let alg_oid_from_cert = &spki.algorithm.algorithm;

    // Convert OIDs to String for comparison
    let is_rsa = alg_oid_from_cert.to_string() == OID_RSA_ENCRYPTION.to_string();
    let is_ec = alg_oid_from_cert.to_string() == OID_EC_PUBLIC_KEY.to_string();

    // Concatenate all raw data for hashing
    let mut data_to_be_hashed = Vec::new();
    data_to_be_hashed.extend_from_slice(client_random);
    data_to_be_hashed.extend_from_slice(server_random);
    data_to_be_hashed.extend_from_slice(&ske.params_raw);

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

        // For ECDSA
        let mut ec_hasher = Sha256::new();
        ec_hasher.update(&data_to_be_hashed);
        let ec_message_hash = ec_hasher.finalize();

        EcVerifier::verify(&verifying_key, ec_message_hash.as_slice(), &signature).map_err(
            |e| TlsError::HandshakeFailed(format!("Signature verification failed: {:?}", e)),
        )?;

        Ok(())
    } else if is_rsa {
        // RSA public key
        let rsa_pub = DecodeRsaPkcs1PublicKey::from_pkcs1_der(spki_bytes_data)
            .or_else(|_| RsaPublicKey::from_public_key_der(spki.raw))
            .map_err(|e| {
                TlsError::CertificateError(format!("Failed to parse RSA public key: {:?}", e))
            })?;

        match ske.signature_algorithm {
            [0x04, 0x01] => {
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
                Ok(())
            }
            [0x05, 0x01] => {
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
                Ok(())
            }
            [0x06, 0x01] => {
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
