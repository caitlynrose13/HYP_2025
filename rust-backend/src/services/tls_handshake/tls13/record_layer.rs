// TLS 1.3 record layer encryption/decryption
use crate::services::errors::TlsError;
use crate::services::tls_parser::CipherSuite;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit},
};
use chacha20poly1305::ChaCha20Poly1305;

/// Compute TLS 1.3 nonce by XORing IV with sequence number
/// RFC 8446 Section 5.3: The nonce is formed by XORing the static IV with the sequence number
pub fn compute_nonce(iv: &[u8; 12], sequence_number: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(iv);

    // Convert sequence number to 8-byte big-endian representation
    let seq_bytes = sequence_number.to_be_bytes();

    // XOR with the last 8 bytes of the nonce (IV is 12 bytes, sequence is 8 bytes)
    // Per RFC 8446: nonce = static_iv XOR (0x00000000 || sequence_number)
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }

    nonce
}

/// Derive AEAD key and IV from a traffic secret (TLS 1.3)
pub fn derive_tls13_aead_key_iv(
    traffic_secret: &[u8],
    cipher_suite: &CipherSuite,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let key_len = match cipher_suite.id {
        [0x13, 0x01] => 16, // TLS_AES_128_GCM_SHA256
        [0x13, 0x02] => 32, // TLS_AES_256_GCM_SHA384
        [0x13, 0x03] => 32, // TLS_CHACHA20_POLY1305_SHA256
        _ => {
            return Err(TlsError::UnsupportedCipherSuite(format!(
                "Unsupported cipher suite for key derivation: {:02x}{:02x}",
                cipher_suite.id[0], cipher_suite.id[1]
            )));
        }
    };
    let iv_len = 12;
    let use_sha384 =
        cipher_suite.hash_algorithm == crate::services::tls_parser::HashAlgorithm::Sha384;
    let prk = if use_sha384 {
        ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA384, traffic_secret)
    } else {
        ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, traffic_secret)
    };
    let key = crate::services::tls_handshake::keys::hkdf_expand_label_dynamic(
        &prk,
        b"key",
        &[],
        key_len,
        use_sha384,
    )?;
    let iv = crate::services::tls_handshake::keys::hkdf_expand_label_dynamic(
        &prk,
        b"iv",
        &[],
        iv_len,
        use_sha384,
    )?;
    if iv.len() != 12 {
        return Err(TlsError::DecryptionError(format!(
            "IV derivation error: expected 12 bytes, got {} bytes",
            iv.len()
        )));
    }
    Ok((key, iv))
}

/// Decrypt a TLS 1.3 record using the correct traffic secret
pub fn decrypt_record(
    ciphertext: &[u8],
    handshake_traffic_secret: &[u8],
    application_traffic_secret: &[u8],
    sequence_number: u64,
    record_type: u8,
    version_major: u8,
    version_minor: u8,
    record_length: u16,
    cipher_suite: &CipherSuite,
) -> Result<Vec<u8>, TlsError> {
    // Select correct traffic secret
    // During handshake phase, ALL records (including ApplicationData) use handshake traffic secret
    // Only after handshake completion should we use application traffic secret
    let traffic_secret = match record_type {
        0x16 => handshake_traffic_secret,
        0x17 => {
            // During handshake phase, ApplicationData records are encrypted with handshake traffic secret
            // This is per RFC 8446 - handshake messages are wrapped in ApplicationData records
            handshake_traffic_secret
        }
        _ => handshake_traffic_secret,
    };

    let (key, iv) = derive_tls13_aead_key_iv(traffic_secret, cipher_suite)?;
    let iv_array: [u8; 12] = iv
        .try_into()
        .map_err(|_| TlsError::DecryptionError("IV must be exactly 12 bytes".to_string()))?;
    let nonce = compute_nonce(&iv_array, sequence_number);

    // TLS 1.3 AAD: opaque_type (1) || legacy_record_version (2) || length (2)
    // The length field in AAD should match the record header length field
    let mut aad = Vec::with_capacity(5);
    aad.push(record_type); // This is always 0x17 for encrypted TLS 1.3 records
    aad.push(version_major); // 0x03
    aad.push(version_minor); // 0x03  
    aad.extend_from_slice(&record_length.to_be_bytes());

    // Verify ciphertext is long enough for auth tag
    if ciphertext.len() < 16 {
        return Err(TlsError::DecryptionError(
            "Ciphertext too short for auth tag".to_string(),
        ));
    }

    let plaintext = match cipher_suite.id {
        [0x13, 0x01] => {
            let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| {
                TlsError::DecryptionError("Failed to create AES-128-GCM cipher".to_string())
            })?;
            cipher
                .decrypt(
                    GenericArray::from_slice(&nonce),
                    aes_gcm::aead::Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| TlsError::DecryptionError("AES-128-GCM decryption failed".to_string()))
        }
        [0x13, 0x02] => {
            let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
                TlsError::DecryptionError("Failed to create AES-256-GCM cipher".to_string())
            })?;
            cipher
                .decrypt(
                    GenericArray::from_slice(&nonce),
                    aes_gcm::aead::Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| TlsError::DecryptionError("AES-256-GCM decryption failed".to_string()))
        }
        [0x13, 0x03] => {
            let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| {
                TlsError::DecryptionError("Failed to create ChaCha20-Poly1305 cipher".to_string())
            })?;
            cipher
                .decrypt(
                    GenericArray::from_slice(&nonce),
                    aes_gcm::aead::Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| {
                    TlsError::DecryptionError("ChaCha20-Poly1305 decryption failed".to_string())
                })
        }
        _ => {
            return Err(TlsError::DecryptionError(format!(
                "Unsupported cipher suite for decryption: {:02x}{:02x}",
                cipher_suite.id[0], cipher_suite.id[1]
            )));
        }
    }?;

    process_tls13_plaintext(plaintext)
}

/// Helper function to process TLS 1.3 plaintext (remove padding and extract content type)
fn process_tls13_plaintext(mut plaintext: Vec<u8>) -> Result<Vec<u8>, TlsError> {
    // Remove trailing zero bytes which are padding
    while let Some(&0) = plaintext.last() {
        plaintext.pop();
    }

    // The last byte should be the real content type
    if plaintext.pop().is_none() {
        return Err(TlsError::DecryptionError(
            "Invalid TLS 1.3 plaintext: missing content type".to_string(),
        ));
    }

    Ok(plaintext)
}
