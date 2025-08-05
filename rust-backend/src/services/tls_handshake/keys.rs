//TLS Key Derivation and Cryptographic Operations
// This module provides  key derivation and cryptographic functions for both
// TLS 1.2 and TLS 1.3 protocols. It handles:
// - HKDF operations (TLS 1.3)
// - PRF operations (TLS 1.2)
// - AEAD cipher management
// - Key schedule implementations
// - Finished message verification

use crate::services::errors::TlsError;
use crate::services::tls_parser::{CipherSuite, TlsContentType, TlsVersion};
use aes::{Aes128, Aes256};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AesGcm, KeyInit};
use hmac::{Hmac, Mac};
use ring::hkdf::{HKDF_SHA256, HKDF_SHA384, KeyType, Prk, Salt};
use sha2::digest::Digest;
use sha2::{Sha256, Sha384};
use typenum::{U12, U16};

#[derive(Clone)]
pub enum TlsAeadCipher {
    /// AES-128-GCM cipher (16-byte key, 12-byte nonce, 16-byte tag)
    Aes128Gcm(AesGcm<Aes128, U12, U16>),
    /// AES-256-GCM cipher (32-byte key, 12-byte nonce, 16-byte tag)
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

/// TLS 1.2 PRF labels as defined in RFC 5246
const TLS12_PRF_LABEL_MASTER_SECRET: &[u8] = b"master secret";
const TLS12_PRF_LABEL_KEY_EXPANSION: &[u8] = b"key expansion";

/// TLS 1.3 label prefix as defined in RFC 8446
const TLS13_LABEL_PREFIX: &[u8] = b"tls13 ";

// =================================
// TLS 1.3 KEY DERIVATION (HKDF-BASED)

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<Prk, TlsError> {
    let salt = Salt::new(HKDF_SHA256, salt);
    let prk = salt.extract(ikm);
    Ok(prk)
}

/// HKDF-Expand-Label for TLS 1.3 (RFC 8446 Section 7.1) - static SHA-256 version
pub fn hkdf_expand_label(
    prk: &Prk,
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, TlsError> {
    // Construct TLS 1.3 label with required prefix
    let mut full_label = TLS13_LABEL_PREFIX.to_vec();
    full_label.extend_from_slice(label);

    // Build HKDFLabel structure per RFC 8446
    let hkdf_label = build_hkdf_label(length as u16, &full_label, context);

    // Expand using the constructed label
    expand_with_info(prk, &hkdf_label, length)
}

/// HKDF-Extract with dynamic hash algorithm selection
///
/// Supports both SHA-256 and SHA-384 based on the cipher suite requirements.
/// Used primarily for TLS 1.3 key schedule operations.
pub fn hkdf_extract_dynamic(salt: &[u8], ikm: &[u8], use_sha384: bool) -> Prk {
    let algorithm = if use_sha384 { HKDF_SHA384 } else { HKDF_SHA256 };
    Salt::new(algorithm, salt).extract(ikm)
}

/// HKDF-Expand-Label with dynamic hash algorithm selection
pub fn hkdf_expand_label_dynamic(
    prk: &Prk,
    label: &[u8],
    context: &[u8],
    length: usize,
    _use_sha384: bool, // Algorithm is already embedded in the PRK
) -> Result<Vec<u8>, TlsError> {
    // Construct full label with TLS 1.3 prefix
    let mut full_label = TLS13_LABEL_PREFIX.to_vec();
    full_label.extend_from_slice(label);

    // Build HKDFLabel structure
    let hkdf_label = build_hkdf_label(length as u16, &full_label, context);

    // Expand using the constructed label
    expand_with_info(prk, &hkdf_label, length)
}

/// TLS 1.3 Key Schedule: Derive handshake traffic secrets (RFC 8446)
pub fn derive_tls13_handshake_traffic_secrets_dynamic(
    shared_secret: &[u8],
    transcript_hash: &[u8],
    use_sha384: bool,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let hash_len = if use_sha384 { 48 } else { 32 };
    let zeroes = vec![0u8; hash_len];

    // RFC 8446: Early-Secret = HKDF-Extract(0, 0)
    let early_secret_prk = hkdf_extract_dynamic(&zeroes, &zeroes, use_sha384);

    // RFC 8446: empty_hash = Hash("")
    let empty_hash = compute_empty_hash(use_sha384);

    // RFC 8446: derived_secret = HKDF-Expand-Label(Early-Secret, "derived", empty_hash, Hash.length)
    let derived_secret = hkdf_expand_label_dynamic(
        &early_secret_prk,
        b"derived",
        &empty_hash,
        hash_len,
        use_sha384,
    )?;

    // RFC 8446: Handshake-Secret = HKDF-Extract(derived_secret, shared_secret)
    let handshake_secret_prk = hkdf_extract_dynamic(&derived_secret, shared_secret, use_sha384);

    // RFC 8446: Derive client and server handshake traffic secrets
    let client_hs_traffic_secret = hkdf_expand_label_dynamic(
        &handshake_secret_prk,
        b"c hs traffic",
        transcript_hash,
        hash_len,
        use_sha384,
    )?;

    let server_hs_traffic_secret = hkdf_expand_label_dynamic(
        &handshake_secret_prk,
        b"s hs traffic",
        transcript_hash,
        hash_len,
        use_sha384,
    )?;

    Ok((client_hs_traffic_secret, server_hs_traffic_secret))
}

// =====================================
// TLS 1.2 KEY DERIVATION (PRF-BASED)

/// Calculates the TLS 1.2 master secret using the PRF
pub fn calculate_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Result<[u8; 48], TlsError> {
    // Construct seed: client_random + server_random
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);

    let mut master_secret = [0u8; 48];
    prf_tls12(
        pre_master_secret,
        TLS12_PRF_LABEL_MASTER_SECRET,
        &seed,
        &mut master_secret,
        hash_algorithm,
    )
    .map_err(|e| TlsError::KeyDerivationError(format!("Master secret PRF error: {}", e)))?;

    Ok(master_secret)
}

/// Calculates the TLS 1.2 key block for deriving encryption keys
pub fn calculate_key_block(
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    cipher_suite: &CipherSuite,
) -> Result<Vec<u8>, TlsError> {
    // Construct seed: server_random + client_random (note the order!)
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    // Calculate total key material needed
    let total_len = 2
        * (cipher_suite.mac_key_length + cipher_suite.key_length + cipher_suite.fixed_iv_length)
            as usize;

    let mut key_block = vec![0u8; total_len];
    prf_tls12(
        master_secret,
        TLS12_PRF_LABEL_KEY_EXPANSION,
        &seed,
        &mut key_block,
        cipher_suite.hash_algorithm,
    )
    .map_err(|e| TlsError::KeyDerivationError(format!("Key block PRF error: {}", e)))?;

    Ok(key_block)
}

/// TLS 1.2 Pseudorandom Function (PRF) implementations.
pub fn prf_tls12(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    result: &mut [u8],
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Result<(), String> {
    // Concatenate label and seed
    let mut label_and_seed = Vec::with_capacity(label.len() + seed.len());
    label_and_seed.extend_from_slice(label);
    label_and_seed.extend_from_slice(seed);

    // Apply P_hash function
    tls12_prf_p_hash(hash_algorithm, secret, &label_and_seed, result)
}

// ===================================
// AEAD OPERATIONS

/// Derives AEAD keys from TLS 1.2 key block
/// Extracts client/server encryption keys and initialization vectors from
/// the key block and creates ready-to-use AEAD cipher instances.
pub fn derive_aead_keys(
    cipher_suite: &CipherSuite,
    key_block: &[u8],
) -> Result<(TlsAeadCipher, Vec<u8>, TlsAeadCipher, Vec<u8>), TlsError> {
    let key_len = cipher_suite.key_length as usize;
    let iv_len = cipher_suite.fixed_iv_length as usize;
    let expected_len = 2 * (key_len + iv_len); // No MAC keys for AEAD

    if key_block.len() < expected_len {
        return Err(TlsError::KeyDerivationError(format!(
            "Key block too short. Expected {} bytes for AEAD, got {}",
            expected_len,
            key_block.len()
        )));
    }

    // Extract keys and IVs in order: client_key, server_key, client_iv, server_iv
    let mut offset = 0;
    let client_key = &key_block[offset..offset + key_len];
    offset += key_len;
    let server_key = &key_block[offset..offset + key_len];
    offset += key_len;
    let client_iv = &key_block[offset..offset + iv_len];
    offset += iv_len;
    let server_iv = &key_block[offset..offset + iv_len];

    // Create AEAD ciphers based on key length
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
                "Unsupported key length for AEAD: {} bytes",
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

/// Encrypts a TLS record using AES-GCM
pub fn encrypt_gcm_message(
    plaintext: &[u8],
    cipher: &TlsAeadCipher,
    fixed_iv: &[u8],
    sequence_number: u64,
    content_type: TlsContentType,
    tls_version: TlsVersion,
) -> Result<Vec<u8>, TlsError> {
    validate_fixed_iv(fixed_iv)?;

    // Construct GCM nonce: fixed_iv (4 bytes) || sequence_number (8 bytes)
    let nonce = build_gcm_nonce(fixed_iv, sequence_number);

    // Build Additional Authenticated Data (AAD)
    let aad = build_aad(sequence_number, content_type, tls_version, plaintext.len())?;

    // Perform AEAD encryption
    let ciphertext_with_tag = match cipher {
        TlsAeadCipher::Aes128Gcm(cipher) => cipher.encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        ),
        TlsAeadCipher::Aes256Gcm(cipher) => cipher.encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        ),
    }
    .map_err(|e| TlsError::EncryptionError(format!("AES-GCM encryption failed: {:?}", e)))?;

    Ok(ciphertext_with_tag)
}

/// Decrypts a TLS 1.2 GCM message with explicit nonce
pub fn decrypt_gcm_message_with_explicit_nonce(
    ciphertext_with_tag: &[u8],
    cipher: &TlsAeadCipher,
    fixed_iv: &[u8],
    explicit_nonce: &[u8],
    sequence_number: u64,
    content_type: TlsContentType,
    tls_version: TlsVersion,
) -> Result<Vec<u8>, TlsError> {
    // Validate inputs
    validate_ciphertext_length(ciphertext_with_tag)?;
    validate_fixed_iv(fixed_iv)?;
    validate_explicit_nonce(explicit_nonce)?;

    // Construct full nonce: fixed_iv || explicit_nonce
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(fixed_iv);
    nonce_bytes[4..].copy_from_slice(explicit_nonce);
    let nonce = GenericArray::<u8, U12>::from_slice(&nonce_bytes);

    // Calculate plaintext length (ciphertext - auth tag)
    let plaintext_length = ciphertext_with_tag.len() - 16;

    // Build AAD for verification
    let aad = build_aad(sequence_number, content_type, tls_version, plaintext_length)?;

    // Perform AEAD decryption
    let plaintext = match cipher {
        TlsAeadCipher::Aes128Gcm(cipher) => cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext_with_tag,
                aad: &aad,
            },
        ),
        TlsAeadCipher::Aes256Gcm(cipher) => cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext_with_tag,
                aad: &aad,
            },
        ),
    }
    .map_err(|e| TlsError::EncryptionError(format!("AES-GCM decryption failed: {:?}", e)))?;

    Ok(plaintext)
}

// ==============================================
// FINISHED MESSAGE VERIFICATION

/// Calculates TLS 1.2 Finished message verify_data]
pub fn calculate_verify_data(
    master_secret: &[u8],
    handshake_messages: &[u8],
    label: &[u8],
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Result<Vec<u8>, TlsError> {
    let handshake_hash = compute_handshake_hash(handshake_messages, hash_algorithm);

    let mut verify_data = [0u8; 12];
    prf_tls12(
        master_secret,
        label,
        &handshake_hash,
        &mut verify_data,
        hash_algorithm,
    )
    .map_err(|e| TlsError::KeyDerivationError(e))?;

    Ok(verify_data.to_vec())
}

/// Calculates verify_data and returns both the data and the handshake hash
/// Useful when both the verify_data and handshake hash are needed separately.
pub fn calculate_verify_data_with_hash(
    master_secret: &[u8],
    handshake_transcript: &[u8],
    label: &[u8],
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let handshake_hash = compute_handshake_hash(handshake_transcript, hash_algorithm);

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

// ========================================
// KEY GENERATION UTILITIES

pub fn generate_p256_keyshare() -> ([u8; 65], p256::ecdh::EphemeralSecret) {
    use p256::{EncodedPoint, ecdh::EphemeralSecret};
    use rand::rngs::OsRng;

    let secret = EphemeralSecret::random(&mut OsRng);
    let public_point = EncodedPoint::from(&secret.public_key());
    let pub_bytes = public_point.to_bytes();

    let mut arr = [0u8; 65];
    arr.copy_from_slice(&pub_bytes);

    (arr, secret)
}

/// Generic HKDF key derivation (optional utility)
///
/// Provides a general-purpose HKDF interface for custom key derivation needs.
#[allow(dead_code)]
pub fn derive_hkdf_keys(
    shared_secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, TlsError> {
    let salt = Salt::new(HKDF_SHA256, salt.unwrap_or(&[]));
    let prk = salt.extract(shared_secret);

    expand_with_info(&prk, info, output_len)
}

// =========================================
// HELPER FUNCTIONS

/// P_hash function for TLS 1.2 PRF with dynamic hash selection
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

/// P_hash implementation using SHA-256
///
/// RFC 5246: P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                                  HMAC_hash(secret, A(2) + seed) + ...
/// where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
fn tls12_prf_p_hash_sha256(secret: &[u8], seed: &[u8], output: &mut [u8]) -> Result<(), String> {
    let mut a_i = seed.to_vec();
    let mut current_output_len = 0;

    while current_output_len < output.len() {
        // Calculate A(i) = HMAC(secret, A(i-1)) - Fix: use Mac::new_from_slice explicitly
        let mut mac_a = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .map_err(|_| "HMAC key error for A(i)".to_string())?;
        mac_a.update(&a_i);
        a_i = mac_a.finalize().into_bytes().to_vec();

        // Calculate P_hash output block = HMAC(secret, A(i) + seed) - Fix: use Mac::new_from_slice explicitly
        let mut mac_p = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .map_err(|_| "HMAC key error for P_hash".to_string())?;
        mac_p.update(&a_i);
        mac_p.update(seed);
        let hmac_result = mac_p.finalize().into_bytes();

        // Copy as much as needed to fill the output
        let to_copy = std::cmp::min(hmac_result.len(), output.len() - current_output_len);
        output[current_output_len..current_output_len + to_copy]
            .copy_from_slice(&hmac_result[..to_copy]);

        current_output_len += to_copy;
    }

    Ok(())
}

/// P_hash implementation using SHA-384
fn tls12_prf_p_hash_sha384(secret: &[u8], seed: &[u8], output: &mut [u8]) -> Result<(), String> {
    let mut a_i = seed.to_vec();
    let mut current_output_len = 0;

    while current_output_len < output.len() {
        // Calculate A(i) = HMAC(secret, A(i-1)) - Fix: use Mac::new_from_slice explicitly
        let mut mac_a = <Hmac<Sha384> as Mac>::new_from_slice(secret)
            .map_err(|_| "HMAC key error for A(i)".to_string())?;
        mac_a.update(&a_i);
        a_i = mac_a.finalize().into_bytes().to_vec();

        // Calculate P_hash output block = HMAC(secret, A(i) + seed) - Fix: use Mac::new_from_slice explicitly
        let mut mac_p = <Hmac<Sha384> as Mac>::new_from_slice(secret)
            .map_err(|_| "HMAC key error for P_hash".to_string())?;
        mac_p.update(&a_i);
        mac_p.update(seed);
        let hmac_result = mac_p.finalize().into_bytes();

        // Copy as much as needed to fill the output
        let to_copy = std::cmp::min(hmac_result.len(), output.len() - current_output_len);
        output[current_output_len..current_output_len + to_copy]
            .copy_from_slice(&hmac_result[..to_copy]);

        current_output_len += to_copy;
    }

    Ok(())
}

/// Builds the HKDFLabel structure for TLS 1.3
///
/// RFC 8446: struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HKDFLabel;
fn build_hkdf_label(length: u16, label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + label.len() + 1 + context.len());

    // Length (2 bytes, big-endian)
    hkdf_label.extend_from_slice(&length.to_be_bytes());

    // Label length and label
    hkdf_label.push(label.len() as u8);
    hkdf_label.extend_from_slice(label);

    // Context length and context
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_label
}

/// Computes empty hash for TLS 1.3 key derivation
fn compute_empty_hash(use_sha384: bool) -> Vec<u8> {
    if use_sha384 {
        Sha384::digest(&[]).to_vec()
    } else {
        Sha256::digest(&[]).to_vec()
    }
}

/// Computes handshake hash for TLS 1.2 finished messages
fn compute_handshake_hash(
    handshake_messages: &[u8],
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Vec<u8> {
    match hash_algorithm {
        crate::services::tls_parser::HashAlgorithm::Sha256 => {
            Sha256::digest(handshake_messages).to_vec()
        }
        crate::services::tls_parser::HashAlgorithm::Sha384 => {
            Sha384::digest(handshake_messages).to_vec()
        }
    }
}

/// Builds GCM nonce from fixed IV and sequence number
fn build_gcm_nonce(fixed_iv: &[u8], sequence_number: u64) -> GenericArray<u8, U12> {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(fixed_iv);
    nonce_bytes[4..].copy_from_slice(&sequence_number.to_be_bytes());
    *GenericArray::<u8, U12>::from_slice(&nonce_bytes)
}

/// Builds Additional Authenticated Data (AAD) for GCM
fn build_aad(
    sequence_number: u64,
    content_type: TlsContentType,
    tls_version: TlsVersion,
    plaintext_length: usize,
) -> Result<Vec<u8>, TlsError> {
    if plaintext_length > u16::MAX as usize {
        return Err(TlsError::EncryptionError(format!(
            "Plaintext length {} exceeds maximum for TLS record",
            plaintext_length
        )));
    }

    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&sequence_number.to_be_bytes());
    aad.push(content_type.as_u8());
    let (major, minor) = tls_version.to_u8_pair();
    aad.push(major);
    aad.push(minor);
    aad.extend_from_slice(&(plaintext_length as u16).to_be_bytes());

    Ok(aad)
}

/// Expands a PRK using provided info parameter
fn expand_with_info(prk: &Prk, info: &[u8], length: usize) -> Result<Vec<u8>, TlsError> {
    struct OkmLen(usize);
    impl KeyType for OkmLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    let info_ref = [info];
    let okm = prk
        .expand(&info_ref, OkmLen(length))
        .map_err(|_| TlsError::KeyDerivationError("HKDF expand error".into()))?;

    let mut output = vec![0u8; length];
    okm.fill(&mut output)
        .map_err(|_| TlsError::KeyDerivationError("HKDF fill error".into()))?;

    Ok(output)
}

// ===================================================
// VALIDATION HELPERS

/// Validates fixed IV length for GCM operations
fn validate_fixed_iv(fixed_iv: &[u8]) -> Result<(), TlsError> {
    if fixed_iv.len() != 4 {
        return Err(TlsError::EncryptionError(format!(
            "Invalid fixed_iv length. Expected: 4, got: {}",
            fixed_iv.len()
        )));
    }
    Ok(())
}

/// Validates explicit nonce length for GCM operations
fn validate_explicit_nonce(explicit_nonce: &[u8]) -> Result<(), TlsError> {
    if explicit_nonce.len() != 8 {
        return Err(TlsError::EncryptionError(format!(
            "Invalid explicit_nonce length. Expected: 8, got: {}",
            explicit_nonce.len()
        )));
    }
    Ok(())
}

/// Validates ciphertext length for GCM operations
fn validate_ciphertext_length(ciphertext: &[u8]) -> Result<(), TlsError> {
    if ciphertext.len() < 16 {
        return Err(TlsError::EncryptionError(format!(
            "Ciphertext too short for GCM tag. Length: {}, minimum: 16",
            ciphertext.len()
        )));
    }
    Ok(())
}
