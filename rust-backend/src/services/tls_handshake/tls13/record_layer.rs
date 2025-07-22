// TLS 1.3 record layer encryption/decryption

use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys::derive_hkdf_keys;
use aes_gcm::{
    Aes128Gcm, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};

/// Derive AEAD key and IV from a traffic secret (TLS 1.3)
pub fn derive_tls13_aead_key_iv(traffic_secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    // Per RFC 8446, Section 7.3, use HKDF-Expand-Label with labels "key" and "iv"
    let key = derive_hkdf_keys(traffic_secret, None, b"tls13 key", 16)?; // 16 bytes for AES-128
    let iv = derive_hkdf_keys(traffic_secret, None, b"tls13 iv", 12)?; // 12 bytes for AES-GCM IV
    Ok((key, iv))
}

/// Decrypt a TLS 1.3 record using AES-GCM and the derived key/IV
pub fn decrypt_record(
    ciphertext: &[u8],
    traffic_secret: &[u8],
    sequence_number: u64,
) -> Result<Vec<u8>, TlsError> {
    let (key, iv) = derive_tls13_aead_key_iv(traffic_secret)?;
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
    // Build nonce: XOR of IV and sequence number (RFC 8446, 5.3)
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv);
    for (i, b) in sequence_number.to_be_bytes().iter().rev().enumerate() {
        let idx = 11 - i;
        nonce[idx] ^= *b;
    }
    // In TLS 1.3, the AAD is the record header (type, version, length)
    // For now, assume caller provides only the ciphertext (payload), so no AAD
    // (AAD is needed for full compliance)
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&nonce), ciphertext)
        .map_err(|e| TlsError::DecryptionError(format!("AES-GCM decryption failed: {:?}", e)))?;
    Ok(plaintext)
}

// (Encryption is not implemented yet)
