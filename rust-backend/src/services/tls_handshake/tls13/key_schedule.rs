use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys::hkdf_extract;
use ring::hkdf::{HKDF_SHA256, Prk, Salt};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Perform X25519 key exchange to derive shared secret (TLS 1.3)
pub fn perform_x25519_key_exchange(
    client_secret: EphemeralSecret,
    server_public: &[u8; 32],
) -> [u8; 32] {
    let server_pub = PublicKey::from(*server_public);
    let shared = client_secret.diffie_hellman(&server_pub);
    shared.to_bytes()
}

/// Implements the TLS 1.3 key schedule for handshake traffic secrets.
/// See RFC 8446, Section 7.1 and 7.2.
pub fn derive_tls13_handshake_traffic_secrets(
    shared_secret: &[u8],   // output of X25519
    transcript_hash: &[u8], // hash of all handshake messages so far
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    // 1. Early Secret (for non-PSK, this is HKDF-Extract with salt=0, IKM=empty)
    let zeroes = [0u8; 32];
    let early_secret_prk = hkdf_extract(&zeroes, &[])?;

    // 2. Derive-Secret for handshake
    // RFC 8446: For "derived" secret, we need to hash an empty string with SHA256
    let empty_hash = {
        use sha2::{Digest, Sha256};
        let hasher = Sha256::new();
        let result = hasher.finalize();
        result.to_vec()
    };

    let derived_secret = {
        // Use the corrected hkdf_expand_label function from keys.rs which includes "tls13" prefix
        crate::services::tls_handshake::keys::hkdf_expand_label(
            &early_secret_prk,
            b"derived",
            &empty_hash,
            32,
        )?
    };

    // 3. Handshake Secret (HKDF-Extract with salt=derived_secret, IKM=shared_secret)
    let handshake_salt = Salt::new(HKDF_SHA256, &derived_secret);
    let handshake_secret_prk = handshake_salt.extract(shared_secret);

    // 4. Derive client/server handshake traffic secrets using HKDF-Expand-Label
    // RFC 8446: "c hs traffic" and "s hs traffic" - use the corrected function
    let client_hs_traffic_secret = crate::services::tls_handshake::keys::hkdf_expand_label(
        &handshake_secret_prk,
        b"c hs traffic",
        transcript_hash,
        32,
    )?;
    let server_hs_traffic_secret = crate::services::tls_handshake::keys::hkdf_expand_label(
        &handshake_secret_prk,
        b"s hs traffic",
        transcript_hash,
        32,
    )?;

    Ok((client_hs_traffic_secret, server_hs_traffic_secret))
}

/// Derive TLS 1.3 application traffic secrets from handshake secret and final transcript
/// This follows the same pattern as handshake traffic secrets but uses "application" labels
/// and the final transcript hash (including all handshake messages up to Finished)
pub fn derive_tls13_application_traffic_secrets(
    shared_secret: &[u8],         // Same as handshake derivation
    final_transcript_hash: &[u8], // hash including all handshake messages up to and including Finished
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    // First, we need to derive the handshake secret again (or pass it in)
    // For now, let's derive it again following the same process as handshake traffic secrets
    let zeroes = [0u8; 32];
    let early_secret_prk = hkdf_extract(&zeroes, &[])?;

    let empty_hash = {
        use sha2::{Digest, Sha256};
        let hasher = Sha256::new();
        let result = hasher.finalize();
        result.to_vec()
    };

    let derived_secret = crate::services::tls_handshake::keys::hkdf_expand_label(
        &early_secret_prk,
        b"derived",
        &empty_hash,
        32,
    )?;

    let handshake_salt = Salt::new(HKDF_SHA256, &derived_secret);
    let handshake_secret_prk = handshake_salt.extract(shared_secret);

    // Now derive the main secret from handshake secret
    let empty_hash_for_main = {
        use sha2::{Digest, Sha256};
        let hasher = Sha256::new();
        let result = hasher.finalize();
        result.to_vec()
    };

    let derived_for_main = crate::services::tls_handshake::keys::hkdf_expand_label(
        &handshake_secret_prk,
        b"derived",
        &empty_hash_for_main,
        32,
    )?;

    // Main Secret = HKDF-Extract(derived_for_main, 0)
    let main_secret_salt = Salt::new(HKDF_SHA256, &derived_for_main);
    let main_secret_prk = main_secret_salt.extract(&[0u8; 32]);

    // 2. Derive application traffic secrets using HKDF-Expand-Label
    // RFC 8446: "c ap traffic" and "s ap traffic"
    let client_app_traffic_secret = crate::services::tls_handshake::keys::hkdf_expand_label(
        &main_secret_prk,
        b"c ap traffic",
        final_transcript_hash,
        32,
    )?;
    let server_app_traffic_secret = crate::services::tls_handshake::keys::hkdf_expand_label(
        &main_secret_prk,
        b"s ap traffic",
        final_transcript_hash,
        32,
    )?;

    Ok((client_app_traffic_secret, server_app_traffic_secret))
}

/// Derive TLS 1.3 finished key from handshake traffic secret and verify Finished message
/// RFC 8446 Section 4.4.4: finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
/// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
pub fn derive_tls13_finished_key_and_verify(
    traffic_secret: &[u8],
    transcript_hash: &[u8],
    received_verify_data: &[u8],
) -> Result<bool, TlsError> {
    // 1. Derive the finished key from the traffic secret
    let prk = ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, traffic_secret);
    let finished_key = crate::services::tls_handshake::keys::hkdf_expand_label(
        &prk,
        b"finished",
        &[], // Empty context for finished key
        32,  // SHA256 hash length
    )?;

    // 2. Calculate the expected verify_data using HMAC
    let expected_verify_data = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(&finished_key)
            .map_err(|_| TlsError::KeyDerivationError("Invalid finished key length".to_string()))?;
        mac.update(transcript_hash);
        mac.finalize().into_bytes().to_vec()
    };

    // 3. Compare the received and expected verify_data
    let is_valid = received_verify_data == expected_verify_data;

    if is_valid {
        println!("[TLS13_FINISHED] ✅ Finished message MAC verification PASSED");
    } else {
        println!("[TLS13_FINISHED] ❌ Finished message MAC verification FAILED");
        println!(
            "[TLS13_FINISHED] Expected: {}",
            hex::encode(&expected_verify_data)
        );
        println!(
            "[TLS13_FINISHED] Received: {}",
            hex::encode(received_verify_data)
        );
    }

    Ok(is_valid)
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
