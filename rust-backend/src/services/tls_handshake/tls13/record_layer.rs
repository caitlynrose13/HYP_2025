// TLS 1.3 record layer encryption/decryption
use crate::services::errors::TlsError;
use crate::services::tls_parser::CipherSuite;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit},
};
use chacha20poly1305::ChaCha20Poly1305;

use ring::hkdf::{HKDF_SHA256, Prk};

/// Compute TLS 1.3 nonce by XORing IV with sequence number
/// RFC 8446 Section 5.3: The nonce is formed by XORing the static IV with the sequence number
pub fn compute_nonce(iv: &[u8; 12], sequence_number: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];

    // Copy the IV to the nonce
    nonce.copy_from_slice(iv);

    // Convert sequence number to big-endian bytes (8 bytes)
    let seq_bytes = sequence_number.to_be_bytes();

    // DEBUG: Print before XOR
    println!("[NONCE_DEBUG] IV: {}", hex::encode(iv));
    println!("[NONCE_DEBUG] Sequence: {}", sequence_number);
    println!("[NONCE_DEBUG] Sequence bytes: {}", hex::encode(&seq_bytes));
    println!("[NONCE_DEBUG] Nonce before XOR: {}", hex::encode(&nonce));

    // XOR the last 8 bytes of the nonce with the sequence number
    // This is the standard TLS 1.3 nonce computation
    for i in 0..8 {
        let old_val = nonce[4 + i];
        nonce[4 + i] ^= seq_bytes[i];
        println!(
            "[NONCE_DEBUG] nonce[{}]: 0x{:02x} ^ 0x{:02x} = 0x{:02x}",
            4 + i,
            old_val,
            seq_bytes[i],
            nonce[4 + i]
        );
    }

    println!("[NONCE_DEBUG] Final nonce: {}", hex::encode(&nonce));
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
            return Err(TlsError::DecryptionError(format!(
                "Unsupported cipher suite for key derivation: {:02x}{:02x}",
                cipher_suite.id[0], cipher_suite.id[1]
            )));
        }
    };

    let iv_len = 12; // Always 12 for GCM/Poly1305 in TLS 1.3

    // Create a PRK from the traffic secret
    let prk = Prk::new_less_safe(HKDF_SHA256, traffic_secret);

    // Use the correct HKDF-Expand-Label function that adds the "tls13 " prefix
    let key = crate::services::tls_handshake::keys::hkdf_expand_label(&prk, b"key", &[], key_len)?;
    let iv = crate::services::tls_handshake::keys::hkdf_expand_label(&prk, b"iv", &[], iv_len)?;

    println!(
        "[KEY_DERIVATION] Traffic secret: {}",
        hex::encode(traffic_secret)
    );
    println!(
        "[KEY_DERIVATION] Derived key ({}b): {}",
        key_len,
        hex::encode(&key)
    );
    println!(
        "[KEY_DERIVATION] Derived IV ({}b): {}",
        iv_len,
        hex::encode(&iv)
    );

    // CRITICAL DEBUG: Check actual lengths
    println!("[KEY_DERIVATION] Key actual length: {}", key.len());
    println!("[KEY_DERIVATION] IV actual length: {}", iv.len());

    if iv.len() != 12 {
        return Err(TlsError::DecryptionError(format!(
            "IV derivation error: expected 12 bytes, got {} bytes",
            iv.len()
        )));
    }

    Ok((key, iv))
}

/// Decrypt a TLS 1.3 record using AES-GCM and the derived key/IV
pub fn decrypt_record(
    ciphertext: &[u8],
    traffic_secret: &[u8],
    sequence_number: u64,
    record_type: u8,
    version_major: u8,
    version_minor: u8,
    record_length: u16, // The original length field from TLS record header
    cipher_suite: &CipherSuite,
) -> Result<Vec<u8>, TlsError> {
    // 1. Derive key and IV from traffic secret
    let (key, iv) = derive_tls13_aead_key_iv(traffic_secret, cipher_suite)?;

    // 2. Construct the nonce: XOR the static IV with the record sequence number
    let iv_array: [u8; 12] = iv
        .try_into()
        .map_err(|_| TlsError::DecryptionError("IV must be exactly 12 bytes".to_string()))?;

    let nonce = compute_nonce(&iv_array, sequence_number);

    println!(
        "[DECRYPT_CALL] Traffic secret: {}",
        hex::encode(traffic_secret)
    );
    println!("[DECRYPT_CALL] IV: {}", hex::encode(&iv_array));
    println!("[DECRYPT_CALL] Sequence: {}", sequence_number);
    println!("[DECRYPT_CALL] Final nonce: {}", hex::encode(&nonce));

    // 3. Construct AAD
    // The user has suggested that the AAD length should be the record length minus the auth tag size.
    // Note: RFC 8446, Section 5.2 specifies that the AAD should use the full length of the
    // encrypted record (TLSCiphertext.length), which includes the authentication tag.
    // This change implements the user's suggestion, which may be required for the specific server
    // being communicated with.
    let tag_len = 16; // AES-GCM and ChaCha20/Poly1305 use a 16-byte tag.
    let aad_length = record_length.saturating_sub(tag_len);

    let mut aad = Vec::with_capacity(5);
    aad.push(record_type);
    aad.push(version_major);
    aad.push(version_minor);
    aad.extend_from_slice(&aad_length.to_be_bytes());

    println!("[AAD_DEBUG] Record type: 0x{:02x}", record_type);
    println!(
        "[AAD_DEBUG] Version: 0x{:02x}{:02x}",
        version_major, version_minor
    );
    println!(
        "[AAD_DEBUG] Record length from header (RFC-compliant AAD length): {} (0x{:04x})",
        record_length, record_length
    );
    println!(
        "[AAD_DEBUG] Using non-standard AAD length (payload only): {} (0x{:04x})",
        aad_length, aad_length
    );
    println!(
        "[AAD_DEBUG] Ciphertext buffer length: {} (0x{:04x})",
        ciphertext.len(),
        ciphertext.len()
    );
    println!("[AAD_DEBUG] Final AAD: {}", hex::encode(&aad));

    // Verify we have enough data
    if ciphertext.len() < 16 {
        return Err(TlsError::DecryptionError(
            "Ciphertext too short for auth tag".to_string(),
        ));
    }

    // CRITICAL: Verify that ciphertext length matches record_length
    if ciphertext.len() != record_length as usize {
        println!(
            "[CRYPTO_WARNING] Length mismatch: ciphertext={}, record_length={}",
            ciphertext.len(),
            record_length
        );
    }

    println!(
        "[CRYPTO] Record: {} bytes, Key: {}, Nonce: {}, AAD: {}",
        ciphertext.len(),
        hex::encode(&key),
        hex::encode(&nonce),
        hex::encode(&aad)
    );

    if ciphertext.len() >= 32 {
        println!(
            "[CRYPTO] Ciphertext start: {}",
            hex::encode(&ciphertext[..16])
        );
        println!(
            "[CRYPTO] Ciphertext end (auth tag): {}",
            hex::encode(&ciphertext[ciphertext.len() - 16..])
        );
    }

    // Debug: Show ciphertext structure before decryption
    println!(
        "[CIPHERTEXT_DEBUG] Full ciphertext length: {}",
        ciphertext.len()
    );
    println!("[CIPHERTEXT_DEBUG] Expected: {} bytes total", record_length);
    println!(
        "[CIPHERTEXT_DEBUG] Expected: {} payload + 16 auth tag",
        record_length.saturating_sub(16)
    );
    if ciphertext.len() >= 16 {
        println!(
            "[CIPHERTEXT_DEBUG] Auth tag (last 16): {:02x?}",
            &ciphertext[ciphertext.len() - 16..]
        );
    } else {
        println!("[CIPHERTEXT_DEBUG] Ciphertext too short for auth tag display");
    }

    // The `aes-gcm` crate expects the ciphertext to include the auth tag (payload + tag as one slice).
    // Do NOT split the ciphertext and tag; pass the full buffer as msg.
    let plaintext = match cipher_suite.id {
        [0x13, 0x01] => {
            // TLS_AES_128_GCM_SHA256
            println!("[CRYPTO] Using AES-128-GCM for decryption");

            let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| {
                TlsError::DecryptionError("Failed to create AES-GCM cipher".to_string())
            })?;

            let nonce_array = GenericArray::from_slice(&nonce);

            // MAIN DECRYPTION ATTEMPT
            // The `aes-gcm` crate's `decrypt` function expects the full ciphertext,
            // including the 16-byte authentication tag. It handles splitting them internally.
            let decrypt_result = cipher.decrypt(
                nonce_array,
                aes_gcm::aead::Payload {
                    msg: ciphertext, // Pass the full ciphertext (payload + auth tag)
                    aad: &aad,
                },
            );

            match decrypt_result {
                Ok(plaintext) => {
                    println!(
                        "[CRYPTO] ✅ Decryption SUCCESS! Length: {}",
                        plaintext.len()
                    );
                    plaintext
                }
                Err(e) => {
                    println!("[CRYPTO] ❌ Main decryption failed: {:?}", e);

                    // Try with corrected AAD if there's a length mismatch
                    if ciphertext.len() != record_length as usize {
                        println!(
                            "[CRYPTO] Trying with corrected AAD using actual ciphertext length..."
                        );
                        let mut corrected_aad = Vec::with_capacity(5);
                        corrected_aad.push(record_type);
                        corrected_aad.push(version_major);
                        corrected_aad.push(version_minor);
                        corrected_aad.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
                        println!("[CRYPTO] Corrected AAD: {}", hex::encode(&corrected_aad));

                        match cipher.decrypt(
                            nonce_array,
                            aes_gcm::aead::Payload {
                                msg: ciphertext, // Use full ciphertext here too
                                aad: &corrected_aad,
                            },
                        ) {
                            Ok(plaintext) => {
                                println!(
                                    "[CRYPTO] ✅ Decryption SUCCESS with corrected AAD! Length: {}",
                                    plaintext.len()
                                );
                                return Ok(process_tls13_plaintext(plaintext)?);
                            }
                            Err(e2) => {
                                println!("[CRYPTO] ❌ Corrected AAD also failed: {:?}", e2);
                            }
                        }
                    }

                    // Automatic fallback to alternative approaches
                    println!("[CRYPTO] Trying alternative decryption approaches...");
                    match decrypt_record_alternative_approaches(
                        ciphertext,
                        traffic_secret,
                        sequence_number,
                        cipher_suite,
                    ) {
                        Ok(alt_plaintext) => {
                            println!(
                                "[CRYPTO] ✅ Decryption SUCCESS with alternative approach! Length: {}",
                                alt_plaintext.len()
                            );
                            return Ok(process_tls13_plaintext(alt_plaintext)?);
                        }
                        Err(_) => {
                            return Err(TlsError::DecryptionError(
                                "AES-128-GCM decryption failed with all approaches".to_string(),
                            ));
                        }
                    }
                }
            }
        }
        [0x13, 0x02] => {
            // TLS_AES_256_GCM_SHA384
            println!("[CRYPTO] Using AES-256-GCM for decryption");
            let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
                TlsError::DecryptionError("Failed to create AES-256-GCM cipher".to_string())
            })?;

            cipher
                .decrypt(
                    GenericArray::from_slice(&nonce),
                    aes_gcm::aead::Payload {
                        msg: ciphertext, // Pass the full ciphertext
                        aad: &aad,
                    },
                )
                .map_err(|e| {
                    TlsError::DecryptionError(format!("AES-256-GCM decryption failed: {:?}", e))
                })?
        }
        [0x13, 0x03] => {
            // TLS_CHACHA20_POLY1305_SHA256
            println!("[CRYPTO] Using ChaCha20-Poly1305 for decryption");
            let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| {
                TlsError::DecryptionError("Failed to create ChaCha20-Poly1305 cipher".to_string())
            })?;

            cipher
                .decrypt(
                    GenericArray::from_slice(&nonce),
                    aes_gcm::aead::Payload {
                        msg: ciphertext, // Pass the full ciphertext
                        aad: &aad,
                    },
                )
                .map_err(|e| {
                    TlsError::DecryptionError(format!(
                        "ChaCha20-Poly1305 decryption failed: {:?}",
                        e
                    ))
                })?
        }
        _ => {
            return Err(TlsError::DecryptionError(format!(
                "Unsupported cipher suite: {:02x}{:02x}",
                cipher_suite.id[0], cipher_suite.id[1]
            )));
        }
    };

    // Process the TLS 1.3 plaintext
    process_tls13_plaintext(plaintext)
}

/// Helper function to process TLS 1.3 plaintext (remove padding and extract content type)
fn process_tls13_plaintext(mut plaintext: Vec<u8>) -> Result<Vec<u8>, TlsError> {
    if !plaintext.is_empty() {
        println!(
            "[DEBUG] Decryption successful! Plaintext first bytes: {}",
            hex::encode(&plaintext[..std::cmp::min(32, plaintext.len())])
        );
    }

    // TLS 1.3 CRITICAL: Remove trailing zeros and content type byte
    // RFC 8446 Section 5.4: The real content type is at the end of the plaintext
    // Format: content || zeros || content_type

    // Remove trailing zero bytes
    while let Some(&0) = plaintext.last() {
        plaintext.pop();
    }

    // The last byte should be the real content type
    if let Some(&content_type_byte) = plaintext.last() {
        plaintext.pop(); // Remove the content type byte
        println!(
            "[TLS13_PLAINTEXT] Real content type: 0x{:02x}, actual content length: {}",
            content_type_byte,
            plaintext.len()
        );
    } else {
        return Err(TlsError::DecryptionError(
            "Invalid TLS 1.3 plaintext: missing content type".to_string(),
        ));
    }

    Ok(plaintext)
}

/// Try alternative decryption approaches when the standard one fails
pub fn decrypt_record_alternative_approaches(
    ciphertext: &[u8],
    traffic_secret: &[u8],
    sequence_number: u64,
    cipher_suite: &CipherSuite,
) -> Result<Vec<u8>, TlsError> {
    println!("[ALT_DECRYPT] Trying alternative decryption approaches");

    // Derive key and IV
    let (key, iv) = derive_tls13_aead_key_iv(traffic_secret, cipher_suite)?;
    let iv_array: [u8; 12] = iv
        .try_into()
        .map_err(|_| TlsError::DecryptionError("IV must be exactly 12 bytes".to_string()))?;

    if cipher_suite.id == [0x13, 0x01] {
        let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| {
            TlsError::DecryptionError("Failed to create AES-GCM cipher".to_string())
        })?;

        // Try comprehensive TLS 1.3 record scenarios
        let scenarios = vec![
            // (record_type, version_major, version_minor, record_length_adjustment, sequence)
            (0x17, 0x03, 0x03, 0, sequence_number), // Standard ApplicationData
            (0x16, 0x03, 0x03, 0, sequence_number), // Handshake type
            (0x17, 0x03, 0x04, 0, sequence_number), // TLS 1.3 version
            (0x17, 0x03, 0x01, 0, sequence_number), // TLS 1.0 version
            (0x17, 0x03, 0x02, 0, sequence_number), // TLS 1.1 version
            (0x17, 0x03, 0x03, -16, sequence_number), // Length without auth tag
            (0x17, 0x03, 0x03, 0, 0),               // Sequence 0
            (0x17, 0x03, 0x03, 0, 1),               // Sequence 1
            (0x16, 0x03, 0x03, 0, 0),               // Handshake with seq 0
            (0x16, 0x03, 0x03, 0, 1),               // Handshake with seq 1
        ];

        for (i, (record_type, version_major, version_minor, length_adj, seq)) in
            scenarios.iter().enumerate()
        {
            let nonce = compute_nonce(&iv_array, *seq);

            let record_length = (ciphertext.len() as i32 + length_adj) as u16;

            let mut aad = Vec::with_capacity(5);
            aad.push(*record_type);
            aad.push(*version_major);
            aad.push(*version_minor);
            aad.extend_from_slice(&record_length.to_be_bytes());

            println!(
                "[ALT_DECRYPT] Scenario {}: type={:02x}, ver={:02x}{:02x}, len={}, seq={}",
                i, record_type, version_major, version_minor, record_length, seq
            );

            let result = cipher.decrypt(
                GenericArray::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            );

            if let Ok(plaintext) = result {
                println!("[ALT_DECRYPT] ✅ SUCCESS with scenario {}!", i);
                println!("[ALT_DECRYPT] Plaintext length: {}", plaintext.len());
                if !plaintext.is_empty() && plaintext.len() >= 16 {
                    println!(
                        "[ALT_DECRYPT] First 32 bytes: {}",
                        hex::encode(&plaintext[..std::cmp::min(32, plaintext.len())])
                    );
                    println!(
                        "[ALT_DECRYPT] Last 16 bytes: {}",
                        hex::encode(&plaintext[plaintext.len().saturating_sub(16)..])
                    );
                }
                return Ok(plaintext);
            }
        }
    }

    Err(TlsError::DecryptionError(
        "All alternative decryption approaches failed".to_string(),
    ))
}

/// Test decryption with client traffic secret (for debugging)
pub fn decrypt_record_with_client_secret(
    ciphertext: &[u8],
    client_traffic_secret: &[u8],
    sequence_number: u64,
    record_type: u8,
    version_major: u8,
    version_minor: u8,
    record_length: u16,
    cipher_suite: &CipherSuite,
) -> Result<Vec<u8>, TlsError> {
    println!("[CLIENT_SECRET_TEST] Trying with CLIENT handshake traffic secret");
    println!(
        "[CLIENT_SECRET_TEST] Client secret: {}",
        hex::encode(client_traffic_secret)
    );

    // Same logic as main function but with client secret
    let (key, iv) = derive_tls13_aead_key_iv(client_traffic_secret, cipher_suite)?;
    let iv_array: [u8; 12] = iv
        .try_into()
        .map_err(|_| TlsError::DecryptionError("IV must be exactly 12 bytes".to_string()))?;

    let nonce = compute_nonce(&iv_array, sequence_number);

    let mut aad = Vec::with_capacity(5);
    aad.push(record_type);
    aad.push(version_major);
    aad.push(version_minor);
    aad.extend_from_slice(&record_length.to_be_bytes());

    println!("[CLIENT_SECRET_TEST] Key: {}", hex::encode(&key));
    println!("[CLIENT_SECRET_TEST] Nonce: {}", hex::encode(&nonce));
    println!("[CLIENT_SECRET_TEST] AAD: {}", hex::encode(&aad));

    if cipher_suite.id == [0x13, 0x01] {
        let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| {
            TlsError::DecryptionError("Failed to create AES-GCM cipher".to_string())
        })?;

        match cipher.decrypt(
            GenericArray::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        ) {
            Ok(plaintext) => {
                println!("[CLIENT_SECRET_TEST] ✅ SUCCESS with client secret!");
                return Ok(plaintext);
            }
            Err(e) => {
                println!("[CLIENT_SECRET_TEST] ❌ Failed with client secret: {:?}", e);
            }
        }
    }

    Err(TlsError::DecryptionError(
        "Client secret approach failed".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_computation() {
        // Test case 1: sequence number 0
        let iv = [
            0x6c, 0x32, 0x43, 0xc6, 0x6c, 0x8b, 0x67, 0x4c, 0x1b, 0xe1, 0x7d, 0xf7,
        ];
        let nonce = compute_nonce(&iv, 0);
        assert_eq!(nonce, iv); // Should be same as IV for seq 0

        // Test case 2: sequence number 1
        let expected_nonce = [
            0x6c, 0x32, 0x43, 0xc6, 0x6c, 0x8b, 0x67, 0x4c, 0x1b, 0xe1, 0x7d, 0xf6,
        ];
        let nonce = compute_nonce(&iv, 1);
        assert_eq!(nonce, expected_nonce);

        println!("✅ Nonce computation tests passed!");
    }
}
