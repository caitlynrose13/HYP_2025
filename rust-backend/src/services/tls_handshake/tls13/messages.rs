// src/services/tls_handshake/tls13/messages.rs

// TLS 1.3 handshake message builders and parsers
use crate::services::tls_parser::{
    EXTENSION_TYPE_KEY_SHARE,
    EXTENSION_TYPE_SERVER_NAME,
    EXTENSION_TYPE_SIGNATURE_ALGORITHMS,
    EXTENSION_TYPE_SUPPORTED_GROUPS,
    EXTENSION_TYPE_SUPPORTED_VERSIONS,
    Extension, // This is fine, used by Extension::new(...)
    HandshakeMessageType,
    NamedGroup,
    SNI_HOSTNAME_TYPE,
    TlsContentType,
    // REMOVED: ServerHelloParsed, parse_tls_extension, TlsParserError (not needed here)
    TlsVersion,
};
use rand::RngCore; // This is used by rand::thread_rng().fill_bytes


// REMOVED: use std::io::Write; // Not directly used in this file's functions (build_client_hello).

// ... (Your existing build_client_hello function - no changes needed here, it's correct for building)
pub fn build_client_hello(domain: &str, client_random: &[u8; 32], x25519_pubkey: &[u8]) -> Vec<u8> {
    // ... (content of your build_client_hello - this part is fine)
    let mut client_hello_payload = Vec::new();

    // Legacy version (TLS 1.2) for compatibility
    client_hello_payload.extend_from_slice(&[0x03, 0x03]);
    // Client random
    client_hello_payload.extend_from_slice(client_random);
    // Session ID (random 32 bytes)
    let mut session_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut session_id);
    client_hello_payload.push(session_id.len() as u8);
    client_hello_payload.extend_from_slice(&session_id);
    // Cipher Suites (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256)
    let cipher_suites: Vec<[u8; 2]> = vec![
        [0x13, 0x01], // TLS_AES_128_GCM_SHA256
        [0x13, 0x02], // TLS_AES_256_GCM_SHA384
        [0x13, 0x03], // TLS_CHACHA20_POLY1305_SHA256
    ];
    let mut cipher_suites_bytes = Vec::new();
    for cs in &cipher_suites {
        cipher_suites_bytes.extend_from_slice(cs);
    }
    client_hello_payload.extend_from_slice(&(cipher_suites_bytes.len() as u16).to_be_bytes());
    client_hello_payload.extend_from_slice(&cipher_suites_bytes);
    // Compression methods (1, null)
    client_hello_payload.push(1u8);
    client_hello_payload.push(0u8);

    // --- Extensions ---
    let mut extensions_bytes = Vec::new();
    // SNI
    let sni_hostname = domain.as_bytes();
    let mut sni_payload = Vec::new();
    sni_payload.extend_from_slice(&((sni_hostname.len() + 3) as u16).to_be_bytes()); // SNI list length (corrected)
    sni_payload.push(SNI_HOSTNAME_TYPE); // name type: host_name
    sni_payload.extend_from_slice(&(sni_hostname.len() as u16).to_be_bytes());
    sni_payload.extend_from_slice(sni_hostname);
    extensions_bytes
        .extend_from_slice(&Extension::new(EXTENSION_TYPE_SERVER_NAME, &sni_payload).to_bytes());
    // Supported Versions (TLS 1.3 and 1.2, as vector of u16)
    let supported_versions = [4u8, 0x03, 0x04, 0x03, 0x03]; // length=4, TLS 1.3, TLS 1.2
    extensions_bytes.extend_from_slice(
        &Extension::new(EXTENSION_TYPE_SUPPORTED_VERSIONS, &supported_versions).to_bytes(),
    );
    // Supported Groups (X25519, secp256r1)
    let mut supported_groups = Vec::new();
    let groups: [[u8; 2]; 2] = [NamedGroup::X25519.as_bytes(), NamedGroup::P256.as_bytes()];
    supported_groups.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for g in &groups {
        supported_groups.extend_from_slice(g);
    }
    extensions_bytes.extend_from_slice(
        &Extension::new(EXTENSION_TYPE_SUPPORTED_GROUPS, &supported_groups).to_bytes(),
    );
    // Signature Algorithms (ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256)
    let sig_algs: [[u8; 2]; 3] = [
        [0x04, 0x03], // ecdsa_secp256r1_sha256
        [0x08, 0x04], // rsa_pss_rsae_sha256
        [0x04, 0x01], // rsa_pkcs1_sha256
    ];
    let mut sig_algs_content = Vec::new();
    sig_algs_content.extend_from_slice(&((sig_algs.len() * 2) as u16).to_be_bytes());
    for alg in &sig_algs {
        sig_algs_content.extend_from_slice(alg);
    }
    extensions_bytes.extend_from_slice(
        &Extension::new(EXTENSION_TYPE_SIGNATURE_ALGORITHMS, &sig_algs_content).to_bytes(),
    );
    // Key Share (X25519)
    let mut key_share = Vec::new();
    key_share.extend_from_slice(&NamedGroup::X25519.as_bytes());
    key_share.extend_from_slice(&(x25519_pubkey.len() as u16).to_be_bytes());
    key_share.extend_from_slice(x25519_pubkey);
    let mut key_share_list = Vec::new();
    key_share_list.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    key_share_list.extend_from_slice(&key_share);
    extensions_bytes
        .extend_from_slice(&Extension::new(EXTENSION_TYPE_KEY_SHARE, &key_share_list).to_bytes());
    // Add Extensions Length
    client_hello_payload.extend_from_slice(&(extensions_bytes.len() as u16).to_be_bytes());
    client_hello_payload.extend_from_slice(&extensions_bytes);

    // Build the raw ClientHello handshake message (type + length + payload)
    let mut raw_client_hello_handshake_message = Vec::new();
    raw_client_hello_handshake_message.push(HandshakeMessageType::ClientHello.as_u8());
    let handshake_len_bytes = (client_hello_payload.len() as u32).to_be_bytes();
    raw_client_hello_handshake_message.extend_from_slice(&handshake_len_bytes[1..4]);
    raw_client_hello_handshake_message.extend_from_slice(&client_hello_payload);

    // Build the full TLS record
    let mut record = Vec::new();
    record.push(TlsContentType::Handshake as u8);
    let (major, minor) = TlsVersion::TLS1_2.to_u8_pair(); // legacy version for record layer
    record.push(major);
    record.push(minor);
    record.extend_from_slice(&(raw_client_hello_handshake_message.len() as u16).to_be_bytes());
    record.extend_from_slice(&raw_client_hello_handshake_message);
    record
}

#[cfg(test)]
pub fn test_print_client_hello() {
    use rand::RngCore;
    use rand::thread_rng;
    // REMOVED: use hex; // Not allowed if avoiding external crates for *any* purpose

    let mut rng = thread_rng();
    let mut client_random = [0u8; 32];
    rng.fill_bytes(&mut client_random);
    let mut x25519_pubkey = [0u8; 32];
    rng.fill_bytes(&mut x25519_pubkey);
    let record = build_client_hello("google.com", &client_random, &x25519_pubkey);
    println!(
        "ClientHello record (debug print, {} bytes): {:?}",
        record.len(),
        &record
    ); // Use {:?}
}

// REMOVED: pub fn parse_tls13_server_hello_payload(...) - This function is MOVED to tls_parser.rs
// REMOVED: pub fn parse_server_hello(_data: &[u8]) - This function is MOVED/integrated into tls_parser.rs
