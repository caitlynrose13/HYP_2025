// TLS 1.3 key schedule and secret derivation

use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys::derive_hkdf_keys;

/// Derive TLS 1.3 handshake traffic secrets (simplified)
pub fn derive_tls13_handshake_traffic_secrets(
    handshake_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    // In real TLS 1.3, the info parameter is structured per spec. We'll use labels for now.
    let client_label = b"client hs traffic";
    let server_label = b"server hs traffic";
    let client_secret = derive_hkdf_keys(
        handshake_secret,
        None,
        &[client_label, transcript_hash].concat(),
        32,
    )?;
    let server_secret = derive_hkdf_keys(
        handshake_secret,
        None,
        &[server_label, transcript_hash].concat(),
        32,
    )?;
    Ok((client_secret, server_secret))
}
