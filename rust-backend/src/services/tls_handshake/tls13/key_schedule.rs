//! TLS 1.3 Key Schedule Implementation
//!
//! This module implements the TLS 1.3 key derivation schedule as specified in RFC 8446.
//! It provides functions for deriving handshake and application traffic secrets,
//! as well as finished key verification.

use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys::{hkdf_expand_label_dynamic, hkdf_extract_dynamic};
use crate::services::tls_handshake::tls13::transcript::{TranscriptHash, TranscriptHashAlgorithm};
use hmac::{Hmac, Mac};
use ring::hkdf::{KeyType, Prk};
use sha2::{Digest, Sha256, Sha384};

// ============================================================================
// PUBLIC KEY DERIVATION FUNCTIONS
// ============================================================================

/// Derives TLS 1.3 handshake traffic secrets from shared secret and transcript
///
/// RFC 8446 Section 7.1: Handshake traffic secrets are derived from the handshake secret,
/// which is computed by extracting the shared secret with the early secret's derived value.
pub fn derive_tls13_handshake_traffic_secrets_dynamic(
    shared_secret: &[u8],
    transcript: &TranscriptHash,
    hash_alg: TranscriptHashAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let (use_sha384, hash_len, zeroes) = get_hash_params(hash_alg);

    // RFC 8446: Early-Secret = HKDF-Extract(salt=0, IKM=0)
    let early_secret_prk = hkdf_extract_dynamic(&zeroes, &zeroes, use_sha384);

    // Get empty hash for this algorithm
    let empty_hash = compute_empty_hash(hash_alg);

    // Derive intermediate secret for handshake
    let derived_secret = hkdf_expand_label_dynamic(
        &early_secret_prk,
        b"derived",
        &empty_hash,
        hash_len,
        use_sha384,
    )?;

    // Extract handshake secret from shared secret
    let handshake_secret_prk = hkdf_extract_dynamic(&derived_secret, shared_secret, use_sha384);

    // Get current transcript hash
    let transcript_hash = transcript
        .clone_hash()
        .map_err(|e| TlsError::KeyDerivationError(e.to_string()))?;

    // Derive client and server handshake traffic secrets
    let client_hs_traffic_secret = hkdf_expand_label_dynamic(
        &handshake_secret_prk,
        b"c hs traffic",
        &transcript_hash,
        hash_len,
        use_sha384,
    )?;

    let server_hs_traffic_secret = hkdf_expand_label_dynamic(
        &handshake_secret_prk,
        b"s hs traffic",
        &transcript_hash,
        hash_len,
        use_sha384,
    )?;

    Ok((client_hs_traffic_secret, server_hs_traffic_secret))
}

/// Derives TLS 1.3 application traffic secrets from shared secret and transcript
///
/// RFC 8446 Section 7.1: Application traffic secrets are derived from the master secret,
/// which is computed by extracting zero with the handshake secret's derived value.
pub fn derive_tls13_application_traffic_secrets(
    shared_secret: &[u8],
    transcript: &TranscriptHash,
    hash_alg: TranscriptHashAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let (use_sha384, hash_len, zeroes) = get_hash_params(hash_alg);

    // RFC 8446: Early-Secret = HKDF-Extract(salt=0, IKM=0)
    let early_secret_prk = hkdf_extract_dynamic(&zeroes, &zeroes, use_sha384);
    let empty_hash = compute_empty_hash(hash_alg);

    // Derive to handshake secret (same as handshake derivation)
    let derived_secret = hkdf_expand_label_dynamic(
        &early_secret_prk,
        b"derived",
        &empty_hash,
        hash_len,
        use_sha384,
    )?;

    let handshake_secret_prk = hkdf_extract_dynamic(&derived_secret, shared_secret, use_sha384);

    // Derive to master secret (RFC 8446: master_secret = HKDF-Extract(derived, 0))
    let derived_for_main = hkdf_expand_label_dynamic(
        &handshake_secret_prk,
        b"derived",
        &empty_hash,
        hash_len,
        use_sha384,
    )?;

    let zeroes_main = vec![0u8; hash_len]; // Fix: create variable to avoid temporary reference
    let main_secret_prk = hkdf_extract_dynamic(&derived_for_main, &zeroes_main, use_sha384);

    // Get current transcript hash
    let transcript_hash = transcript
        .clone_hash()
        .map_err(|e| TlsError::KeyDerivationError(e.to_string()))?;

    // Derive client and server application traffic secrets
    let client_app_traffic_secret = hkdf_expand_label_dynamic(
        &main_secret_prk,
        b"c ap traffic",
        &transcript_hash,
        hash_len,
        use_sha384,
    )?;

    let server_app_traffic_secret = hkdf_expand_label_dynamic(
        &main_secret_prk,
        b"s ap traffic",
        &transcript_hash,
        hash_len,
        use_sha384,
    )?;

    Ok((client_app_traffic_secret, server_app_traffic_secret))
}

/// Derives TLS 1.3 finished key and verifies the Finished message
///
/// RFC 8446 Section 4.4.4:
/// - finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
/// - verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
pub fn derive_tls13_finished_key_and_verify(
    traffic_secret: &[u8],
    transcript_hash: &[u8],
    hash_alg: TranscriptHashAlgorithm,
    received_verify_data: &[u8],
) -> Result<bool, TlsError> {
    let hash_len = get_hash_length(hash_alg);

    // Create PRK from traffic secret
    let prk = create_prk_from_secret(traffic_secret, hash_alg);

    // Derive finished key using HKDF-Expand-Label
    let finished_key =
        crate::services::tls_handshake::keys::hkdf_expand_label(&prk, b"finished", &[], hash_len)?;

    // Compute expected verify data using HMAC
    let expected_verify_data = compute_hmac_verify_data(&finished_key, transcript_hash, hash_alg)?;

    // Compare received and expected verify data
    Ok(received_verify_data == expected_verify_data)
}

/// Derives keys using TLS 1.3 HKDF-Expand-Label with custom label and context
///
/// This function formats the info parameter as an HKDFLabel structure per RFC 8446.
pub fn derive_tls13_hkdf_label_key(
    prk: &Prk,
    label_str: &[u8], // e.g., b"tls13 key", b"tls13 iv"
    context: &[u8],   // usually empty for traffic keys, or transcript hash
    output_len: usize,
) -> Result<Vec<u8>, TlsError> {
    let hkdf_label = build_hkdf_label(output_len as u16, label_str, context);
    let info_ref: &[&[u8]] = &[&hkdf_label];

    let okm = prk
        .expand(info_ref, OkmLen(output_len))
        .map_err(|_| TlsError::KeyDerivationError("HKDF expand error".into()))?;

    let mut output = vec![0u8; output_len];
    okm.fill(&mut output)
        .map_err(|_| TlsError::KeyDerivationError("HKDF fill error".into()))?;

    Ok(output)
}

// ==================================================
// HELPER FUNCTIONS

/// Gets hash algorithm parameters (use_sha384, hash_length, zero_bytes)
fn get_hash_params(hash_alg: TranscriptHashAlgorithm) -> (bool, usize, Vec<u8>) {
    match hash_alg {
        TranscriptHashAlgorithm::Sha256 => (false, 32, vec![0u8; 32]),
        TranscriptHashAlgorithm::Sha384 => (true, 48, vec![0u8; 48]),
    }
}

/// Gets the hash output length for the given algorithm
fn get_hash_length(hash_alg: TranscriptHashAlgorithm) -> usize {
    match hash_alg {
        TranscriptHashAlgorithm::Sha256 => 32,
        TranscriptHashAlgorithm::Sha384 => 48,
    }
}

/// Computes the empty hash (Hash("")) for the given algorithm
fn compute_empty_hash(hash_alg: TranscriptHashAlgorithm) -> Vec<u8> {
    match hash_alg {
        TranscriptHashAlgorithm::Sha256 => {
            let mut h = Sha256::new();
            h.update(&[]);
            h.finalize().to_vec()
        }
        TranscriptHashAlgorithm::Sha384 => {
            let mut h = Sha384::new();
            h.update(&[]);
            h.finalize().to_vec()
        }
    }
}

/// Creates an HKDF PRK from a traffic secret using the appropriate hash algorithm
fn create_prk_from_secret(traffic_secret: &[u8], hash_alg: TranscriptHashAlgorithm) -> Prk {
    match hash_alg {
        TranscriptHashAlgorithm::Sha256 => {
            ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, traffic_secret)
        }
        TranscriptHashAlgorithm::Sha384 => {
            ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA384, traffic_secret)
        }
    }
}

/// Computes HMAC verify data for the given finished key and transcript hash
fn compute_hmac_verify_data(
    finished_key: &[u8],
    transcript_hash: &[u8],
    hash_alg: TranscriptHashAlgorithm,
) -> Result<Vec<u8>, TlsError> {
    match hash_alg {
        TranscriptHashAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(finished_key)
                .map_err(|_| TlsError::KeyDerivationError("Invalid HMAC key length".into()))?;
            mac.update(transcript_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        TranscriptHashAlgorithm::Sha384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(finished_key)
                .map_err(|_| TlsError::KeyDerivationError("Invalid HMAC key length".into()))?;
            mac.update(transcript_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Constructs the TLS 1.3 HKDFLabel structure per RFC 8446
///
/// HKDFLabel Structure:
/// - length: u16 (2 bytes)
/// - label_length: u8 (1 byte)  
/// - label: [u8] (variable length)
/// - context_length: u8 (1 byte)
/// - context: [u8] (variable length)
fn build_hkdf_label(length: u16, label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + label.len() + 1 + context.len());

    // Length (2 bytes, big-endian)
    hkdf_label.extend_from_slice(&length.to_be_bytes());

    // Label length and label bytes
    hkdf_label.push(label.len() as u8);
    hkdf_label.extend_from_slice(label);

    // Context length and context bytes
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_label
}

// ================================================
// UTILITY TYPES

/// Helper struct implementing KeyType for HKDF output key material length
struct OkmLen(usize);

impl KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}
