// TLS 1.3 record layer encryption/decryption
use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys::derive_hkdf_keys;
use crate::services::tls_parser::CipherSuite;
use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit},
};
use chacha20poly1305::ChaCha20Poly1305;

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

    // Use the HKDF function from your keys module
    let key = derive_hkdf_keys(traffic_secret, None, b"tls13 key", key_len)?;
    let iv = derive_hkdf_keys(traffic_secret, None, b"tls13 iv", iv_len)?;

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
    cipher_suite: &CipherSuite,
) -> Result<Vec<u8>, TlsError> {
    println!(
        "[DEBUG]   - traffic_secret length: {}",
        traffic_secret.len()
    );
    println!(
        "[DEBUG]   - traffic_secret (hex): {}",
        hex::encode(traffic_secret)
    );
    println!("[DEBUG]   - sequence_number: {}", sequence_number);
    println!("[DEBUG]   - record_type: {}", record_type);
    println!("[DEBUG]   - version: {}.{}", version_major, version_minor);
    println!(
        "[DEBUG]   - cipher_suite: {:02x}{:02x} ({})",
        cipher_suite.id[0], cipher_suite.id[1], cipher_suite.name
    );

    // 1. Derive key and IV from traffic secret
    let (key, iv) = derive_tls13_aead_key_iv(traffic_secret, cipher_suite)?;
    println!("[DEBUG]   - derived key (hex): {}", hex::encode(&key));
    println!("[DEBUG]   - derived iv (hex): {}", hex::encode(&iv));

    // 2. Construct the nonce: XOR the static IV with the record sequence number
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv);

    // TLS 1.3 spec: "The nonce for the AEAD construction is formed by XORing the
    // sequence number with the client_write_iv or server_write_iv"
    let seq_bytes = sequence_number.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i]; // XOR the last 8 bytes
    }
    println!("[DEBUG]   - final nonce (hex): {}", hex::encode(&nonce));

    // 3. Construct TLS 1.3 AAD (different from TLS 1.2)
    // RFC 8446: "The additional data used in AEAD is:
    //   additional_data = TLSCiphertext.opaque_type ||
    //                     TLSCiphertext.legacy_record_version ||
    //                     TLSCiphertext.length"
    let mut aad = Vec::with_capacity(5);
    aad.push(record_type); // Use the actual record type from the record header
    aad.push(version_major);
    aad.push(version_minor);

    // The length in the AAD is the length of the ciphertext excluding the auth tag (16 bytes)
    if ciphertext.len() < 16 {
        return Err(TlsError::DecryptionError(
            "Ciphertext too short".to_string(),
        ));
    }
    let actual_ciphertext_len = ciphertext.len() - 16;
    aad.extend_from_slice(&(actual_ciphertext_len as u16).to_be_bytes());

    println!("[DEBUG] Encrypted record length: {}", ciphertext.len());
    println!(
        "[DEBUG] Record type: ApplicationData ({}), version: {}.{}",
        record_type, version_major, version_minor
    );
    println!(
        "[DEBUG] Encrypted payload first bytes (hex): {}",
        hex::encode(&ciphertext[..std::cmp::min(64, ciphertext.len())])
    );

    println!("[DEBUG] decrypt_record called with:");
    println!("[DEBUG]   - ciphertext length: {}", ciphertext.len());
    println!(
        "[DEBUG]   - ciphertext (first 32 bytes): {}",
        hex::encode(&ciphertext[..std::cmp::min(32, ciphertext.len())])
    );

    // Separate the auth tag from the ciphertext
    let (actual_ciphertext, auth_tag) = ciphertext.split_at(actual_ciphertext_len);
    println!(
        "[DEBUG] Actual ciphertext length: {}",
        actual_ciphertext.len()
    );
    println!("[DEBUG] Auth tag (16 bytes): {}", hex::encode(auth_tag));
    println!("[DEBUG] AAD for AEAD (hex): {}", hex::encode(&aad));

    // Create a combined ciphertext with auth tag for decryption
    let mut combined = Vec::with_capacity(actual_ciphertext.len() + auth_tag.len());
    combined.extend_from_slice(actual_ciphertext);
    combined.extend_from_slice(auth_tag);

    let plaintext = match cipher_suite.id {
        [0x13, 0x01] => {
            // TLS_AES_128_GCM_SHA256
            println!("[DEBUG] Using AES-128-GCM for decryption");

            // Create AES-GCM cipher
            let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| {
                TlsError::DecryptionError("Failed to create AES-GCM cipher".to_string())
            })?;

            // Try to decrypt using slice-based API
            match cipher.decrypt(&nonce.into(), combined.as_slice()) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    println!("[DEBUG] AES-128-GCM decryption failed: Error");
                    println!(
                        "[DEBUG] Check for authentication tag issues or key derivation problems"
                    );

                    // Try alternative AAD format
                    let mut alt_aad = Vec::with_capacity(5);
                    alt_aad.push(record_type);
                    alt_aad.push(version_major);
                    alt_aad.push(version_minor);
                    alt_aad.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
                    println!("[DEBUG] Trying alternative AAD: {}", hex::encode(&alt_aad));

                    // Try with alternate AAD
                    match cipher.decrypt(&nonce.into(), combined.as_slice()) {
                        Ok(plaintext) => plaintext,
                        Err(_) => {
                            return Err(TlsError::DecryptionError(
                                "AES-128-GCM decryption failed: Error".to_string(),
                            ));
                        }
                    }
                }
            }
        }
        [0x13, 0x02] => {
            // TLS_AES_256_GCM_SHA384
            println!("[DEBUG] Using AES-256-GCM for decryption");

            // Create AES-GCM cipher
            let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
                TlsError::DecryptionError("Failed to create AES-256-GCM cipher".to_string())
            })?;

            // Try to decrypt using slice-based API
            match cipher.decrypt(&nonce.into(), combined.as_slice()) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    return Err(TlsError::DecryptionError(
                        "AES-256-GCM decryption failed: Error".to_string(),
                    ));
                }
            }
        }
        [0x13, 0x03] => {
            // TLS_CHACHA20_POLY1305_SHA256
            println!("[DEBUG] Using ChaCha20-Poly1305 for decryption");

            // Create ChaCha20-Poly1305 cipher
            let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| {
                TlsError::DecryptionError("Failed to create ChaCha20-Poly1305 cipher".to_string())
            })?;

            // Try to decrypt using slice-based API
            match cipher.decrypt(&nonce.into(), combined.as_slice()) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    return Err(TlsError::DecryptionError(
                        "ChaCha20-Poly1305 decryption failed: Error".to_string(),
                    ));
                }
            }
        }
        _ => {
            return Err(TlsError::DecryptionError(format!(
                "Unsupported cipher suite: {:02x}{:02x}",
                cipher_suite.id[0], cipher_suite.id[1]
            )));
        }
    };

    // Print the plaintext if decryption was successful
    if !plaintext.is_empty() {
        println!(
            "[DEBUG] Decryption successful! Plaintext first bytes: {}",
            hex::encode(&plaintext[..std::cmp::min(32, plaintext.len())])
        );
    }

    Ok(plaintext)
}

// (Encryption is not implemented yet)
