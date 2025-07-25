use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys::{hkdf_expand_label_dynamic, hkdf_extract_dynamic};
use crate::services::tls_handshake::tls13::transcript::{TranscriptHash, TranscriptHashAlgorithm};
use hmac::{Hmac, Mac};
use ring::hkdf::Prk;
use sha2::Digest;
use sha2::{Sha256, Sha384};

/// Implements the TLS 1.3 key schedule for handshake traffic secrets.
/// See RFC 8446, Section 7.1 and 7.2.
/// use_sha384: true for TLS_AES_256_GCM_SHA384, false for others

/// Refactored: Accepts TranscriptHashAlgorithm, uses correct hash/HKDF for handshake secrets
pub fn derive_tls13_handshake_traffic_secrets_dynamic(
    shared_secret: &[u8],
    transcript: &TranscriptHash,
    hash_alg: TranscriptHashAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let use_sha384 = matches!(hash_alg, TranscriptHashAlgorithm::Sha384);
    let zeroes = if use_sha384 {
        vec![0u8; 48]
    } else {
        vec![0u8; 32]
    };
    // RFC 8446: Early-Secret = HKDF-Extract(salt=0, IKM=0)
    let early_secret_prk = hkdf_extract_dynamic(&zeroes, &zeroes, use_sha384);
    // RFC: empty_hash = Hash("")
    let empty_hash = match hash_alg {
        TranscriptHashAlgorithm::Sha256 => {
            let mut h = sha2::Sha256::new();
            h.update(&[]);
            h.finalize().to_vec()
        }
        TranscriptHashAlgorithm::Sha384 => {
            let mut h = sha2::Sha384::new();
            h.update(&[]);
            h.finalize().to_vec()
        }
    };
    let hash_len = if use_sha384 { 48 } else { 32 };
    let derived_secret = hkdf_expand_label_dynamic(
        &early_secret_prk,
        b"derived",
        &empty_hash,
        hash_len,
        use_sha384,
    )?;
    let handshake_secret_prk = hkdf_extract_dynamic(&derived_secret, shared_secret, use_sha384);
    let transcript_hash = transcript
        .clone_hash()
        .map_err(|e| TlsError::KeyDerivationError(e.to_string()))?;
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

/// Derive TLS 1.3 application traffic secrets from handshake secret and final transcript
/// This follows the same pattern as handshake traffic secrets but uses "application" labels
/// and the final transcript hash (including all handshake messages up to Finished)

/// Refactored: Accepts TranscriptHash, uses correct hash/HKDF for application secrets
pub fn derive_tls13_application_traffic_secrets(
    shared_secret: &[u8],
    transcript: &TranscriptHash,
    hash_alg: TranscriptHashAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let use_sha384 = matches!(hash_alg, TranscriptHashAlgorithm::Sha384);
    let zeroes = if use_sha384 {
        vec![0u8; 48]
    } else {
        vec![0u8; 32]
    };
    // RFC 8446: Early-Secret = HKDF-Extract(salt=0, IKM=0)
    let early_secret_prk = hkdf_extract_dynamic(&zeroes, &zeroes, use_sha384);
    let empty_hash = match hash_alg {
        TranscriptHashAlgorithm::Sha256 => {
            let mut h = sha2::Sha256::new();
            h.update(&[]);
            h.finalize().to_vec()
        }
        TranscriptHashAlgorithm::Sha384 => {
            let mut h = sha2::Sha384::new();
            h.update(&[]);
            h.finalize().to_vec()
        }
    };
    let hash_len = if use_sha384 { 48 } else { 32 };
    let derived_secret = hkdf_expand_label_dynamic(
        &early_secret_prk,
        b"derived",
        &empty_hash,
        hash_len,
        use_sha384,
    )?;
    let handshake_secret_prk = hkdf_extract_dynamic(&derived_secret, shared_secret, use_sha384);
    // Main secret (RFC 8446: master_secret = HKDF-Extract(derived, 0))
    let derived_for_main = hkdf_expand_label_dynamic(
        &handshake_secret_prk,
        b"derived",
        &empty_hash,
        hash_len,
        use_sha384,
    )?;
    let main_secret_prk = hkdf_extract_dynamic(&derived_for_main, &vec![0u8; hash_len], use_sha384);
    let transcript_hash = transcript
        .clone_hash()
        .map_err(|e| TlsError::KeyDerivationError(e.to_string()))?;
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

/// Derive TLS 1.3 finished key from handshake traffic secret and verify Finished message
/// RFC 8446 Section 4.4.4: finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
/// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
pub fn derive_tls13_finished_key_and_verify(
    traffic_secret: &[u8],
    transcript_hash: &[u8],

    hash_alg: TranscriptHashAlgorithm,
    received_verify_data: &[u8],
) -> Result<bool, TlsError> {
    let hash_len = match hash_alg {
        TranscriptHashAlgorithm::Sha256 => 32,
        TranscriptHashAlgorithm::Sha384 => 48,
    };

    let prk = match hash_alg {
        TranscriptHashAlgorithm::Sha256 => {
            ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, traffic_secret)
        }
        TranscriptHashAlgorithm::Sha384 => {
            ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA384, traffic_secret)
        }
    };

    let finished_key =
        crate::services::tls_handshake::keys::hkdf_expand_label(&prk, b"finished", &[], hash_len)?;

    let expected_verify_data = match hash_alg {
        TranscriptHashAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(&finished_key)
                .map_err(|_| TlsError::KeyDerivationError("Invalid HMAC length".into()))?;
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        }
        TranscriptHashAlgorithm::Sha384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(&finished_key)
                .map_err(|_| TlsError::KeyDerivationError("Invalid HMAC length".into()))?;
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        }
    };

    Ok(received_verify_data == expected_verify_data)
}

/// Helper to construct the TLS 1.3 HKDFLabel structure
/// length: u16, label: &[u8], context: &[u8]
fn build_hkdf_label(length: u16, label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&length.to_be_bytes()); // 2 bytes for length
    hkdf_label.push(label.len() as u8); // 1 byte for label length
    hkdf_label.extend_from_slice(label); // label bytes
    hkdf_label.push(context.len() as u8); // 1 byte for context length
    hkdf_label.extend_from_slice(context); // context bytes
    hkdf_label
}

/// Derive keys using TLS 1.3 HKDF-Expand-Label
/// This is specifically for TLS 1.3 traffic key derivation where
/// the info parameter needs to be formatted as an HKDFLabel.
pub fn derive_tls13_hkdf_label_key(
    prk: &Prk,
    label_str: &[u8], // e.g., b"tls13 key", b"tls13 iv"
    context: &[u8],   // for traffic keys, this is usually empty, or a transcript hash
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

// Struct for hkdf::KeyType
struct OkmLen(usize);
impl ring::hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}
