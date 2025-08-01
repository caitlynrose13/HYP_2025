// TLS 1.3 handshake message helpers
use crate::services::tls_parser::{
    EXTENSION_TYPE_KEY_SHARE, EXTENSION_TYPE_SERVER_NAME, EXTENSION_TYPE_SIGNATURE_ALGORITHMS,
    EXTENSION_TYPE_SUPPORTED_GROUPS, EXTENSION_TYPE_SUPPORTED_VERSIONS, Extension,
    HandshakeMessageType, NamedGroup, SNI_HOSTNAME_TYPE, TlsContentType, TlsVersion,
};

pub fn handshake_message_with_header(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() as u32;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.push(msg_type);
    out.extend_from_slice(&length.to_be_bytes()[1..]);
    out.extend_from_slice(payload);
    out
}

/// Build the raw ClientHello handshake message (not wrapped in TLS record)
pub fn build_raw_client_hello_handshake(
    domain: &str,
    client_random: &[u8; 32],
    x25519_pubkey: &[u8],
) -> Vec<u8> {
    let mut client_hello_payload = Vec::new();

    // Legacy version (TLS 1.2) for compatibility
    client_hello_payload.extend_from_slice(&[0x03, 0x03]);

    // Client random
    client_hello_payload.extend_from_slice(client_random);

    // Session ID - Use 32-byte session ID like OpenSSL
    let session_id_len = 32u8;
    client_hello_payload.push(session_id_len);
    // Generate random session ID
    let mut session_id = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut session_id);
    client_hello_payload.extend_from_slice(&session_id); // Cipher suites - TLS 1.3 cipher suites for maximum compatibility
    let cipher_suites: Vec<[u8; 2]> = vec![
        // Standard TLS 1.3 cipher suites (mandatory/recommended)
        [0x13, 0x01], // TLS_AES_128_GCM_SHA256 (mandatory)
        [0x13, 0x02], // TLS_AES_256_GCM_SHA384
        [0x13, 0x03], // TLS_CHACHA20_POLY1305_SHA256
        // Additional TLS 1.3 cipher suites for broader compatibility
        [0x13, 0x04], // TLS_AES_128_CCM_SHA256 (for constrained environments)
        [0x13, 0x05], // TLS_AES_128_CCM_8_SHA256 (IoT/embedded devices)
    ];
    let mut cipher_suites_bytes = Vec::new();
    for cs in &cipher_suites {
        cipher_suites_bytes.extend_from_slice(cs);
    }
    client_hello_payload.extend_from_slice(&(cipher_suites_bytes.len() as u16).to_be_bytes());
    client_hello_payload.extend_from_slice(&cipher_suites_bytes);

    // Compression methods - null compression only
    client_hello_payload.push(1u8);
    client_hello_payload.push(0u8);

    // Extensions in RFC-compliant order
    let mut extensions_bytes = Vec::new();

    // 1. Server Name Indication (SNI) - Extension type 0x0000
    let sni_hostname = domain.as_bytes();
    let mut sni_payload = Vec::new();
    sni_payload.extend_from_slice(&((sni_hostname.len() + 3) as u16).to_be_bytes()); // SNI list length
    sni_payload.push(SNI_HOSTNAME_TYPE); // name type: host_name
    sni_payload.extend_from_slice(&(sni_hostname.len() as u16).to_be_bytes());
    sni_payload.extend_from_slice(sni_hostname);
    extensions_bytes
        .extend_from_slice(&Extension::new(EXTENSION_TYPE_SERVER_NAME, &sni_payload).to_bytes());

    // 2. Supported Groups - Extension type 0x000A - Conservative list for better compatibility
    let groups: [[u8; 2]; 4] = [
        NamedGroup::X25519.as_bytes(), // x25519 (most common, should be first)
        NamedGroup::P256.as_bytes(),   // secp256r1 (widely supported)
        [0x00, 0x18],                  // secp384r1 (enterprise)
        [0x00, 0x19],                  // secp521r1 (high security)
    ];
    let mut supported_groups = Vec::new();
    supported_groups.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for g in &groups {
        supported_groups.extend_from_slice(g);
    }
    extensions_bytes.extend_from_slice(
        &Extension::new(EXTENSION_TYPE_SUPPORTED_GROUPS, &supported_groups).to_bytes(),
    );

    // 3. Signature Algorithms - Extension type 0x000D - Match OpenSSL format
    let sig_algs: [[u8; 2]; 12] = [
        [0x04, 0x03], // ecdsa_secp256r1_sha256
        [0x08, 0x07], // ed25519
        [0x08, 0x08], // ed448
        [0x08, 0x09], // rsa_pss_pss_sha256
        [0x08, 0x0a], // rsa_pss_pss_sha384
        [0x08, 0x0b], // rsa_pss_pss_sha512
        [0x08, 0x04], // rsa_pss_rsae_sha256
        [0x08, 0x05], // rsa_pss_rsae_sha384
        [0x08, 0x06], // rsa_pss_rsae_sha512
        [0x04, 0x01], // rsa_pkcs1_sha256
        [0x05, 0x01], // rsa_pkcs1_sha384
        [0x06, 0x01], // rsa_pkcs1_sha512
    ];
    let mut sig_algs_content = Vec::new();
    sig_algs_content.extend_from_slice(&((sig_algs.len() * 2) as u16).to_be_bytes());
    for alg in &sig_algs {
        sig_algs_content.extend_from_slice(alg);
    }
    extensions_bytes.extend_from_slice(
        &Extension::new(EXTENSION_TYPE_SIGNATURE_ALGORITHMS, &sig_algs_content).to_bytes(),
    );

    // 4. Supported Versions - Extension type 0x002B (MUST be present for TLS 1.3)
    let supported_versions = [2u8, 0x03, 0x04]; // length=2, TLS 1.3 only
    extensions_bytes.extend_from_slice(
        &Extension::new(EXTENSION_TYPE_SUPPORTED_VERSIONS, &supported_versions).to_bytes(),
    );

    // 5. Key Share - Extension type 0x0033 (MUST be present for TLS 1.3)
    let mut key_share = Vec::new();
    key_share.extend_from_slice(&NamedGroup::X25519.as_bytes());
    key_share.extend_from_slice(&(x25519_pubkey.len() as u16).to_be_bytes());
    key_share.extend_from_slice(x25519_pubkey);
    let mut key_share_list = Vec::new();
    key_share_list.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    key_share_list.extend_from_slice(&key_share);
    extensions_bytes
        .extend_from_slice(&Extension::new(EXTENSION_TYPE_KEY_SHARE, &key_share_list).to_bytes());

    // 6. PSK Key Exchange Modes - Extension type 0x002D (required for TLS 1.3)
    extensions_bytes.extend_from_slice(&Extension::new(0x002d, &[0x01, 0x01]).to_bytes());

    // Add Extensions Length
    client_hello_payload.extend_from_slice(&(extensions_bytes.len() as u16).to_be_bytes());
    client_hello_payload.extend_from_slice(&extensions_bytes);

    // Build the raw ClientHello handshake message
    let mut raw_client_hello_handshake_message = Vec::new();
    raw_client_hello_handshake_message.push(HandshakeMessageType::ClientHello.as_u8());
    let handshake_len_bytes = (client_hello_payload.len() as u32).to_be_bytes();
    raw_client_hello_handshake_message.extend_from_slice(&handshake_len_bytes[1..4]);
    raw_client_hello_handshake_message.extend_from_slice(&client_hello_payload);
    raw_client_hello_handshake_message
}

/// Build the full TLS record containing the ClientHello handshake message
pub fn build_client_hello(domain: &str, client_random: &[u8; 32], x25519_pubkey: &[u8]) -> Vec<u8> {
    let raw_client_hello_handshake_message =
        build_raw_client_hello_handshake(domain, client_random, x25519_pubkey);
    let mut record = Vec::new();
    record.push(TlsContentType::Handshake as u8);
    let (major, minor) = TlsVersion::TLS1_2.to_u8_pair(); // legacy version for record layer
    record.push(major);
    record.push(minor);
    record.extend_from_slice(&(raw_client_hello_handshake_message.len() as u16).to_be_bytes());
    record.extend_from_slice(&raw_client_hello_handshake_message);
    record
}
