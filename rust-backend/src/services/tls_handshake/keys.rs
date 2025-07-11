// --- External Crates ---
use aes::Aes128;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AesGcm, KeyInit};
use hmac::{Hmac, Mac};
use ring::hkdf::{self, HKDF_SHA256, Prk, Salt};
use sha2::{Digest, Sha256};

use crate::services::errors::TlsError;
use crate::services::tls_parser::{CipherSuite, HashAlgorithm, TlsContentType, TlsVersion};
use typenum::{U12, U16}; // <--- Ensure both U12 and U16 are imported here
// --- TLS PRF Labels ---
const TLS12_PRF_LABEL_MASTER_SECRET: &[u8] = b"master secret";
const TLS12_PRF_LABEL_KEY_EXPANSION: &[u8] = b"key expansion";

/// --- Master Secret ---
pub fn calculate_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<[u8; 48], TlsError> {
    let mut seed = Vec::new();
    seed.extend_from_slice(TLS12_PRF_LABEL_MASTER_SECRET);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);

    let mut master_secret = [0u8; 48];
    prf_tls12(pre_master_secret, &seed, &mut master_secret)
        .map_err(|e| TlsError::KeyDerivationError(format!("PRF error: {}", e)))?;

    Ok(master_secret)
}

/// --- Key Block ---
pub fn calculate_key_block(
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    cipher_suite: &CipherSuite,
) -> Result<Vec<u8>, TlsError> {
    let mut seed = Vec::new();
    seed.extend_from_slice(TLS12_PRF_LABEL_KEY_EXPANSION);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let total_len = 2
        * (cipher_suite.mac_key_length + cipher_suite.key_length + cipher_suite.fixed_iv_length)
            as usize;

    let mut key_block = vec![0u8; total_len];
    prf_tls12(master_secret, &seed, &mut key_block)
        .map_err(|e| TlsError::KeyDerivationError(format!("Key block PRF error: {}", e)))?;

    Ok(key_block)
}

/// --- PRF (TLS 1.2 with SHA256 only) ---
pub fn prf_tls12(secret: &[u8], seed: &[u8], result: &mut [u8]) -> Result<(), String> {
    tls12_prf_p_hash(HashAlgorithm::Sha256, secret, seed, result)
}

fn tls12_prf_p_hash(
    hash_algorithm: HashAlgorithm,
    secret: &[u8],
    seed: &[u8],
    output: &mut [u8],
) -> Result<(), String> {
    let mut a_i = seed.to_vec();
    let mut current_output_len = 0;

    while current_output_len < output.len() {
        let mut mac_a = match hash_algorithm {
            HashAlgorithm::Sha256 => <Hmac<Sha256> as Mac>::new_from_slice(secret)
                .map_err(|_| "HMAC error (A(i))".to_string())?,
        };
        mac_a.update(&a_i);
        a_i = mac_a.finalize().into_bytes().to_vec();

        let mut mac_p = match hash_algorithm {
            HashAlgorithm::Sha256 => <Hmac<Sha256> as Mac>::new_from_slice(secret)
                .map_err(|_| "HMAC error (P_hash)".to_string())?,
        };
        mac_p.update(&a_i);
        mac_p.update(seed);
        let hmac_result = mac_p.finalize().into_bytes();

        let to_copy = std::cmp::min(hmac_result.len(), output.len() - current_output_len);
        output[current_output_len..current_output_len + to_copy]
            .copy_from_slice(&hmac_result[..to_copy]);

        current_output_len += to_copy;
    }

    Ok(())
}

/// --- AEAD Derivation (TLS 1.2 AES-GCM) ---
pub fn derive_aead_keys(
    cipher_suite: &CipherSuite,
    key_block: &[u8],
) -> Result<(AesGcm<Aes128, U12, U16>, AesGcm<Aes128, U12, U16>), TlsError> {
    let mac_len = cipher_suite.mac_key_length as usize;
    let key_len = cipher_suite.key_length as usize;
    let iv_len = cipher_suite.fixed_iv_length as usize;

    let expected_len = 2 * (mac_len + key_len + iv_len);
    if key_block.len() < expected_len {
        return Err(TlsError::KeyDerivationError(format!(
            "Key block too short. Expected {}, got {}",
            expected_len,
            key_block.len()
        )));
    }

    let mut offset = 0;

    let _client_mac = &key_block[offset..offset + mac_len];
    offset += mac_len;

    let _server_mac = &key_block[offset..offset + mac_len];
    offset += mac_len;

    let client_key = &key_block[offset..offset + key_len];
    offset += key_len;

    let server_key = &key_block[offset..offset + key_len];
    offset += key_len;
    let _client_iv = &key_block[offset..offset + iv_len];
    offset += iv_len;

    let _server_iv = &key_block[offset..offset + iv_len];

    // Ensure client_key and server_key slices match the expected length for Aes128 (16 bytes)
    if key_len != 16 {
        return Err(TlsError::KeyDerivationError(format!(
            "Expected key_len of 16 for Aes128, but got {}",
            key_len
        )));
    }

    let client_cipher = AesGcm::<Aes128, U12, U16>::new(GenericArray::from_slice(client_key));
    let server_cipher = AesGcm::<Aes128, U12, U16>::new(GenericArray::from_slice(server_key));
    Ok((client_cipher, server_cipher))
}

/// --- Finished Verify Data ---
pub fn calculate_verify_data(
    master_secret: &[u8],
    handshake_messages: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(handshake_messages);
    let handshake_hash = hasher.finalize();

    let mut seed = Vec::new();
    seed.extend_from_slice(label);
    seed.extend_from_slice(&handshake_hash);

    let mut verify_data = [0u8; 12];
    prf_tls12(&master_secret, &seed, &mut verify_data).map_err(TlsError::KeyDerivationError)?;

    Ok(verify_data.to_vec())
}

/// Like calculate_verify_data, but also returns the handshake_hash for debug logging
pub fn calculate_verify_data_with_hash(
    master_secret: &[u8],
    handshake_messages: &[u8],
    label: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), TlsError> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(handshake_messages);
    let handshake_hash = hasher.finalize();
    let mut handshake_hash_arr = [0u8; 32];
    handshake_hash_arr.copy_from_slice(&handshake_hash);

    let mut seed = Vec::new();
    seed.extend_from_slice(label);
    seed.extend_from_slice(&handshake_hash_arr);

    let mut verify_data = [0u8; 12];
    prf_tls12(&master_secret, &seed, &mut verify_data).map_err(TlsError::KeyDerivationError)?;

    Ok((verify_data.to_vec(), handshake_hash_arr))
}

pub fn encrypt_gcm_message(
    plaintext: &[u8],
    key: &AesGcm<Aes128, U12, U16>,
    fixed_iv: &[u8],
    sequence_number: u64,
    content_type: TlsContentType,
    tls_version: TlsVersion,
) -> Result<Vec<u8>, TlsError> {
    // Nonce: 4 bytes fixed_iv || 8 bytes sequence_number (big-endian)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(fixed_iv);
    nonce_bytes[4..].copy_from_slice(&sequence_number.to_be_bytes());

    // Construct AAD: seq_num (8 bytes) || content_type (1 byte) || version (2 bytes) || length (2 bytes)
    // For the length, we need to estimate it: plaintext length + 16 bytes for GCM tag
    let estimated_encrypted_length = plaintext.len() + 16;
    let mut aad_bytes = Vec::with_capacity(13);
    aad_bytes.extend_from_slice(&sequence_number.to_be_bytes());
    aad_bytes.push(content_type.as_u8());
    let (major, minor) = tls_version.to_u8_pair();
    aad_bytes.push(major);
    aad_bytes.push(minor);
    aad_bytes.extend_from_slice(&(estimated_encrypted_length as u16).to_be_bytes());

    // Enhanced debug print
    println!("=== GCM Encryption Debug ===");
    println!("Plaintext (hex): {}", hex::encode(plaintext));
    println!("Fixed IV (hex): {}", hex::encode(fixed_iv));
    println!("Sequence number: {}", sequence_number);
    println!("Content type: 0x{:02X}", content_type.as_u8());
    println!("TLS version: 0x{:02X}{:02X}", major, minor);
    println!("AEAD nonce (hex): {}", hex::encode(&nonce_bytes));
    println!("AEAD AAD (hex): {}", hex::encode(&aad_bytes));
    println!(
        "Estimated encrypted length: {} (plaintext {} + 16)",
        estimated_encrypted_length,
        plaintext.len()
    );
    println!(
        "AAD length field: 0x{:04X}",
        estimated_encrypted_length as u16
    );

    // Encrypt once with AAD
    let nonce = GenericArray::<u8, U12>::from_slice(&nonce_bytes);
    let ciphertext_with_tag = key
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| TlsError::EncryptionError("AES-GCM encryption failed".into()))?;

    println!(
        "Final ciphertext (hex): {}",
        hex::encode(&ciphertext_with_tag)
    );
    println!("Actual ciphertext length: {}", ciphertext_with_tag.len());
    println!("=== End GCM Encryption Debug ===");

    Ok(ciphertext_with_tag)
}

/// Decrypts a TLS 1.2 GCM message payload.
pub fn decrypt_gcm_message(
    ciphertext_with_tag: &[u8],
    key: &AesGcm<Aes128, U12, U16>,
    fixed_iv: &[u8],
    sequence_number: u64,
    content_type: TlsContentType,
    tls_version: TlsVersion,
) -> Result<Vec<u8>, TlsError> {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(fixed_iv);
    nonce_bytes[4..].copy_from_slice(&sequence_number.to_be_bytes());

    let nonce = GenericArray::<u8, U12>::from_slice(&nonce_bytes);

    let mut aad_bytes = Vec::with_capacity(13);
    aad_bytes.extend_from_slice(&sequence_number.to_be_bytes());
    aad_bytes.push(content_type.as_u8());
    let (major, minor) = tls_version.to_u8_pair();
    aad_bytes.push(major);
    aad_bytes.push(minor);
    aad_bytes.extend_from_slice(&(ciphertext_with_tag.len() as u16 - 16).to_be_bytes());

    let plaintext = key
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext_with_tag,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| TlsError::EncryptionError("AES-GCM decryption failed".into()))?;

    Ok(plaintext)
}

/// --- HKDF (Optional TLS 1.3) ---
#[allow(dead_code)]
pub fn derive_hkdf_keys(
    shared_secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, TlsError> {
    struct OkmLen(usize);
    impl hkdf::KeyType for OkmLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    let salt = Salt::new(HKDF_SHA256, salt.unwrap_or(&[]));
    let prk: Prk = salt.extract(shared_secret);

    let info_ref = [info];

    let okm = prk
        .expand(&info_ref, OkmLen(output_len))
        .map_err(|_| TlsError::KeyDerivationError("HKDF expand error".into()))?;

    let mut output = vec![0u8; output_len];
    okm.fill(&mut output)
        .map_err(|_| TlsError::KeyDerivationError("HKDF fill error".into()))?;

    Ok(output)
}
