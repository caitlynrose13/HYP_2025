// TLS 1.3 key schedule and secret derivation

use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys::{hkdf_expand_label, hkdf_extract};

/// Implements the TLS 1.3 key schedule for handshake traffic secrets.
/// See RFC 8446, Section 7.1 and 7.2.
pub fn derive_tls13_handshake_traffic_secrets(
    shared_secret: &[u8],   // output of X25519
    transcript_hash: &[u8], // hash of all handshake messages so far
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    use ring::hkdf::{HKDF_SHA256, Salt};
    // 1. Early Secret (for non-PSK, this is HKDF-Extract with salt=0, IKM=empty)
    let zeroes = [0u8; 32];
    let early_secret_prk = hkdf_extract(&zeroes, &[])?;
    let early_secret_bytes = {
        let mut buf = [0u8; 32];
        early_secret_prk
            .expand(&[b""], ring::hkdf::HKDF_SHA256)
            .map_err(|_| TlsError::KeyDerivationError("HKDF expand error for early secret".into()))?
            .fill(&mut buf)
            .map_err(|_| TlsError::KeyDerivationError("HKDF fill error for early secret".into()))?;
        buf
    };

    // 2. Handshake Secret (HKDF-Extract with salt=early_secret_bytes, IKM=shared_secret)
    let handshake_salt = Salt::new(HKDF_SHA256, &early_secret_bytes);
    let handshake_secret_prk = handshake_salt.extract(shared_secret);

    // 3. Derive client/server handshake traffic secrets using HKDF-Expand-Label
    // RFC 8446: "c hs traffic" and "s hs traffic"
    let client_hs_traffic_secret =
        hkdf_expand_label(&handshake_secret_prk, b"c hs traffic", transcript_hash, 32)?;
    let server_hs_traffic_secret =
        hkdf_expand_label(&handshake_secret_prk, b"s hs traffic", transcript_hash, 32)?;

    Ok((client_hs_traffic_secret, server_hs_traffic_secret))
}
