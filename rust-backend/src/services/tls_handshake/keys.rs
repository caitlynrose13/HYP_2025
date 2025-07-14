use aes::{Aes128, Aes256};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AesGcm, KeyInit};
use hmac::{Hmac, Mac};
use ring::hkdf::{self, HKDF_SHA256, Prk, Salt};
use sha2::{Digest, Sha256, Sha384};

use crate::services::errors::TlsError;
use crate::services::tls_parser::{CipherSuite, TlsContentType, TlsVersion};
use typenum::{U12, U16};

//  AEAD Cipher Enum
#[derive(Clone)]
pub enum TlsAeadCipher {
    Aes128Gcm(AesGcm<Aes128, U12, U16>),
    Aes256Gcm(AesGcm<Aes256, U12, U16>),
}

impl std::fmt::Debug for TlsAeadCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsAeadCipher::Aes128Gcm(_) => write!(f, "TlsAeadCipher::Aes128Gcm"),
            TlsAeadCipher::Aes256Gcm(_) => write!(f, "TlsAeadCipher::Aes256Gcm"),
        }
    }
}

//
const TLS12_PRF_LABEL_MASTER_SECRET: &[u8] = b"master secret";
const TLS12_PRF_LABEL_KEY_EXPANSION: &[u8] = b"key expansion";

/// master Secret
pub fn calculate_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Result<[u8; 48], TlsError> {
    // The seed for master secret is client_random + server_random
    let mut actual_seed_for_prf = Vec::with_capacity(client_random.len() + server_random.len());
    actual_seed_for_prf.extend_from_slice(client_random);
    actual_seed_for_prf.extend_from_slice(server_random);

    let mut master_secret = [0u8; 48];
    prf_tls12(
        pre_master_secret,
        TLS12_PRF_LABEL_MASTER_SECRET,
        &actual_seed_for_prf,
        &mut master_secret,
        hash_algorithm,
    )
    .map_err(|e| TlsError::KeyDerivationError(format!("PRF error: {}", e)))?;

    Ok(master_secret)
}

/// Key Block
pub fn calculate_key_block(
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    cipher_suite: &CipherSuite,
) -> Result<Vec<u8>, TlsError> {
    // The seed key block is server_random + client_random
    let mut actual_seed_for_prf = Vec::with_capacity(server_random.len() + client_random.len());
    actual_seed_for_prf.extend_from_slice(server_random);
    actual_seed_for_prf.extend_from_slice(client_random);

    let total_len = 2
        * (cipher_suite.mac_key_length + cipher_suite.key_length + cipher_suite.fixed_iv_length)
            as usize;

    let mut key_block = vec![0u8; total_len];
    prf_tls12(
        master_secret,
        TLS12_PRF_LABEL_KEY_EXPANSION,
        &actual_seed_for_prf,
        &mut key_block,
        cipher_suite.hash_algorithm,
    )
    .map_err(|e| TlsError::KeyDerivationError(format!("Key block PRF error: {}", e)))?;

    Ok(key_block)
}

///PRF (TLS 1.2 with SHA256 or SHA384)
pub fn prf_tls12(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    result: &mut [u8],
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Result<(), String> {
    let mut label_and_seed = Vec::with_capacity(label.len() + seed.len());
    label_and_seed.extend_from_slice(label);
    label_and_seed.extend_from_slice(seed);

    tls12_prf_p_hash(hash_algorithm, secret, &label_and_seed, result)
}

fn tls12_prf_p_hash(
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
    secret: &[u8],
    seed: &[u8],
    output: &mut [u8],
) -> Result<(), String> {
    match hash_algorithm {
        crate::services::tls_parser::HashAlgorithm::Sha256 => {
            tls12_prf_p_hash_sha256(secret, seed, output)
        }
        crate::services::tls_parser::HashAlgorithm::Sha384 => {
            tls12_prf_p_hash_sha384(secret, seed, output)
        }
    }
}

fn tls12_prf_p_hash_sha256(secret: &[u8], seed: &[u8], output: &mut [u8]) -> Result<(), String> {
    let mut a_i = seed.to_vec();
    let mut current_output_len = 0;

    while current_output_len < output.len() {
        let mut mac_a = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .map_err(|_| "HMAC error (A(i))".to_string())?;
        mac_a.update(&a_i);
        a_i = mac_a.finalize().into_bytes().to_vec();

        let mut mac_p = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .map_err(|_| "HMAC error (P_hash)".to_string())?;
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

fn tls12_prf_p_hash_sha384(secret: &[u8], seed: &[u8], output: &mut [u8]) -> Result<(), String> {
    let mut a_i = seed.to_vec();
    let mut current_output_len = 0;

    while current_output_len < output.len() {
        let mut mac_a = <Hmac<Sha384> as Mac>::new_from_slice(secret)
            .map_err(|_| "HMAC error (A(i))".to_string())?;
        mac_a.update(&a_i);
        a_i = mac_a.finalize().into_bytes().to_vec();

        let mut mac_p = <Hmac<Sha384> as Mac>::new_from_slice(secret)
            .map_err(|_| "HMAC error (P_hash)".to_string())?;
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

///AEAD Derivation (TLS 1.2 AES-GCM)
pub fn derive_aead_keys(
    cipher_suite: &CipherSuite,
    key_block: &[u8],
) -> Result<(TlsAeadCipher, Vec<u8>, TlsAeadCipher, Vec<u8>), TlsError> {
    let key_len = cipher_suite.key_length as usize; // 16 or 32 for GCM
    let iv_len = cipher_suite.fixed_iv_length as usize; // 4 for GCM
    // mac_key_length is 0 for AEAD ciphersuites, no need to account for it in offset
    let expected_len = 2 * (key_len + iv_len); // Only client_key, server_key, client_iv, server_iv

    if key_block.len() < expected_len {
        return Err(TlsError::KeyDerivationError(format!(
            "Key block too short. Expected {} bytes for AEAD, got {}",
            expected_len,
            key_block.len()
        )));
    }

    let mut offset = 0;
    let client_key = &key_block[offset..offset + key_len];
    offset += key_len;
    let server_key = &key_block[offset..offset + key_len];
    offset += key_len;
    let client_iv = &key_block[offset..offset + iv_len]; // This is the fixed_iv for client
    offset += iv_len;
    let server_iv = &key_block[offset..offset + iv_len]; // This is the fixed_iv for server

    let (client_cipher, server_cipher) = match key_len {
        16 => (
            TlsAeadCipher::Aes128Gcm(AesGcm::<Aes128, U12, U16>::new(GenericArray::from_slice(
                client_key,
            ))),
            TlsAeadCipher::Aes128Gcm(AesGcm::<Aes128, U12, U16>::new(GenericArray::from_slice(
                server_key,
            ))),
        ),
        32 => (
            TlsAeadCipher::Aes256Gcm(AesGcm::<Aes256, U12, U16>::new(GenericArray::from_slice(
                client_key,
            ))),
            TlsAeadCipher::Aes256Gcm(AesGcm::<Aes256, U12, U16>::new(GenericArray::from_slice(
                server_key,
            ))),
        ),
        _ => {
            return Err(TlsError::KeyDerivationError(format!(
                "Unsupported key_len for AEAD: {}",
                key_len
            )));
        }
    };

    Ok((
        client_cipher,
        client_iv.to_vec(),
        server_cipher,
        server_iv.to_vec(),
    ))
}

///Finished Verify Data
pub fn calculate_verify_data(
    master_secret: &[u8],
    handshake_messages: &[u8],
    label: &[u8],
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Result<Vec<u8>, TlsError> {
    let handshake_hash = match hash_algorithm {
        crate::services::tls_parser::HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::default();
            hasher.update(handshake_messages);
            hasher.finalize().to_vec()
        }
        crate::services::tls_parser::HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::default();
            hasher.update(handshake_messages);
            hasher.finalize().to_vec()
        }
    };

    let mut seed = Vec::new();
    seed.extend_from_slice(&handshake_hash);

    let mut verify_data = [0u8; 12];
    prf_tls12(
        master_secret,
        label,
        &seed,
        &mut verify_data,
        hash_algorithm,
    )
    .map_err(|e| TlsError::KeyDerivationError(e))?;

    Ok(verify_data.to_vec())
}

/// Like calculate_verify_data, but also returns the handshake_hash
pub fn calculate_verify_data_with_hash(
    master_secret: &[u8],
    handshake_transcript: &[u8],
    label: &[u8],
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    // Calculate handshake hash
    let handshake_hash = match hash_algorithm {
        crate::services::tls_parser::HashAlgorithm::Sha256 => {
            Sha256::digest(handshake_transcript).to_vec()
        }
        crate::services::tls_parser::HashAlgorithm::Sha384 => {
            Sha384::digest(handshake_transcript).to_vec()
        }
    };

    // Calculate verify_data using PRF
    let mut verify_data = [0u8; 12];
    prf_tls12(
        master_secret,
        label,
        &handshake_hash,
        &mut verify_data,
        hash_algorithm,
    )
    .map_err(|e| TlsError::KeyDerivationError(e))?;

    Ok((verify_data.to_vec(), handshake_hash))
}

pub fn encrypt_gcm_message(
    plaintext: &[u8],
    key: &TlsAeadCipher,
    fixed_iv: &[u8],
    sequence_number: u64,
    content_type: TlsContentType,
    tls_record_version: TlsVersion,
) -> Result<Vec<u8>, TlsError> {
    // Validate fixed_iv length
    if fixed_iv.len() != 4 {
        return Err(TlsError::EncryptionError(format!(
            "Invalid fixed_iv length for encryption. Expected: 4, got: {}",
            fixed_iv.len()
        )));
    }

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(fixed_iv);
    nonce_bytes[4..].copy_from_slice(&sequence_number.to_be_bytes());

    let plaintext_length = plaintext.len();
    let mut aad_bytes = Vec::with_capacity(13);
    aad_bytes.extend_from_slice(&sequence_number.to_be_bytes());
    aad_bytes.push(content_type.as_u8());
    let (major, minor) = tls_record_version.to_u8_pair();
    aad_bytes.push(major);
    aad_bytes.push(minor);
    aad_bytes.extend_from_slice(&(plaintext_length as u16).to_be_bytes());

    let nonce = GenericArray::<u8, U12>::from_slice(&nonce_bytes);

    let ciphertext_with_tag = match key {
        TlsAeadCipher::Aes128Gcm(cipher) => cipher.encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        ),
        TlsAeadCipher::Aes256Gcm(cipher) => cipher.encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        ),
    }
    .map_err(|e| TlsError::EncryptionError(format!("AES-GCM encryption failed: {:?}", e)))?;

    Ok(ciphertext_with_tag)
}

/// Decrypts a TLS 1.2 GCM message payload with explicit nonce.
pub fn decrypt_gcm_message_with_explicit_nonce(
    ciphertext_with_tag: &[u8],
    key: &TlsAeadCipher,
    fixed_iv: &[u8],
    explicit_nonce: &[u8],
    sequence_number: u64,
    content_type: TlsContentType,
    tls_version: TlsVersion,
) -> Result<Vec<u8>, TlsError> {
    // Validate ciphertext length
    if ciphertext_with_tag.len() < 16 {
        return Err(TlsError::EncryptionError(format!(
            "Ciphertext too short for GCM tag. Length: {}, minimum: 16",
            ciphertext_with_tag.len()
        )));
    }

    // Validate fixed_iv length
    if fixed_iv.len() != 4 {
        return Err(TlsError::EncryptionError(format!(
            "Invalid fixed_iv length for decryption. Expected: 4, got: {}",
            fixed_iv.len()
        )));
    }

    // Validate explicit_nonce length
    if explicit_nonce.len() != 8 {
        return Err(TlsError::EncryptionError(format!(
            "Invalid explicit_nonce length for decryption. Expected: 8, got: {}",
            explicit_nonce.len()
        )));
    }

    // Construct nonce as fixed_iv || explicit_nonce (4 + 8 = 12 bytes)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(fixed_iv);
    nonce_bytes[4..].copy_from_slice(explicit_nonce);

    let plaintext_length = ciphertext_with_tag.len() - 16;

    let mut aad_bytes = Vec::with_capacity(13);
    aad_bytes.extend_from_slice(&sequence_number.to_be_bytes());
    aad_bytes.push(content_type.as_u8());
    let (major, minor) = tls_version.to_u8_pair();
    aad_bytes.push(major);
    aad_bytes.push(minor);
    aad_bytes.extend_from_slice(&(plaintext_length as u16).to_be_bytes());

    let nonce = GenericArray::<u8, U12>::from_slice(&nonce_bytes);

    let plaintext = match key {
        TlsAeadCipher::Aes128Gcm(cipher) => cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext_with_tag,
                aad: &aad_bytes,
            },
        ),
        TlsAeadCipher::Aes256Gcm(cipher) => cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext_with_tag,
                aad: &aad_bytes,
            },
        ),
    }
    .map_err(|e| TlsError::EncryptionError(format!("AES-GCM decryption failed: {:?}", e)))?;

    Ok(plaintext)
}

/// HKDF (Optional TLS 1.3)
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
