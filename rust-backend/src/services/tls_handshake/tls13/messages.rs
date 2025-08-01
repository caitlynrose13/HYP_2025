//! TLS 1.3 Message Construction
//!
//! This module provides functions for building TLS 1.3 handshake messages,
//! particularly ClientHello messages with proper extension ordering and
//! RFC 8446 compliance.

use crate::services::tls_parser::{
    EXTENSION_TYPE_KEY_SHARE, EXTENSION_TYPE_SERVER_NAME, EXTENSION_TYPE_SIGNATURE_ALGORITHMS,
    EXTENSION_TYPE_SUPPORTED_GROUPS, EXTENSION_TYPE_SUPPORTED_VERSIONS, Extension,
    HandshakeMessageType, NamedGroup, SNI_HOSTNAME_TYPE, TlsContentType, TlsVersion,
};
use rand::RngCore;

// ============================================================================
// CONSTANTS
// ============================================================================

/// PSK Key Exchange Modes extension type (RFC 8446)
const EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES: u16 = 0x002D;

/// TLS 1.3 mandatory cipher suites for maximum compatibility
const TLS13_CIPHER_SUITES: &[[u8; 2]] = &[
    [0x13, 0x01], // TLS_AES_128_GCM_SHA256 (mandatory)
    [0x13, 0x02], // TLS_AES_256_GCM_SHA384
    [0x13, 0x03], // TLS_CHACHA20_POLY1305_SHA256
    [0x13, 0x04], // TLS_AES_128_CCM_SHA256 (for constrained environments)
    [0x13, 0x05], // TLS_AES_128_CCM_8_SHA256 (IoT/embedded devices)
];

/// Supported elliptic curve groups in order of preference
const SUPPORTED_GROUPS: &[[u8; 2]] = &[
    [0x00, 0x1D], // X25519 (most common, should be first)
    [0x00, 0x17], // secp256r1 (widely supported)
    [0x00, 0x18], // secp384r1 (enterprise)
    [0x00, 0x19], // secp521r1 (high security)
];

/// Signature algorithms in order of preference (matching OpenSSL format)
const SIGNATURE_ALGORITHMS: &[[u8; 2]] = &[
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

// ============================================================================
// PUBLIC API FUNCTIONS
// ============================================================================

/// Builds a complete TLS record containing a ClientHello handshake message
///
/// This function creates a TLS 1.3 ClientHello message wrapped in a TLS record
/// with the legacy version (TLS 1.2) for compatibility with middleboxes.
pub fn build_client_hello(domain: &str, client_random: &[u8; 32], x25519_pubkey: &[u8]) -> Vec<u8> {
    let raw_client_hello_handshake_message =
        build_raw_client_hello_handshake(domain, client_random, x25519_pubkey);

    let mut record = Vec::with_capacity(5 + raw_client_hello_handshake_message.len());

    // TLS Record Header
    record.push(TlsContentType::Handshake as u8);
    let (major, minor) = TlsVersion::TLS1_2.to_u8_pair(); // Legacy version for record layer
    record.push(major);
    record.push(minor);
    record.extend_from_slice(&(raw_client_hello_handshake_message.len() as u16).to_be_bytes());

    // Handshake Message
    record.extend_from_slice(&raw_client_hello_handshake_message);

    record
}

/// Builds the raw ClientHello handshake message (without TLS record wrapper)
///
/// Creates a TLS 1.3 ClientHello message according to RFC 8446 with:
/// - Proper extension ordering
/// - Maximum compatibility cipher suites
/// - Required TLS 1.3 extensions
pub fn build_raw_client_hello_handshake(
    domain: &str,
    client_random: &[u8; 32],
    x25519_pubkey: &[u8],
) -> Vec<u8> {
    let mut client_hello_payload = Vec::new();

    // Build ClientHello payload
    add_protocol_version(&mut client_hello_payload);
    add_client_random(&mut client_hello_payload, client_random);
    add_session_id(&mut client_hello_payload);
    add_cipher_suites(&mut client_hello_payload);
    add_compression_methods(&mut client_hello_payload);
    add_extensions(&mut client_hello_payload, domain, x25519_pubkey);

    // Wrap in handshake message header
    create_handshake_message_with_header(HandshakeMessageType::ClientHello, &client_hello_payload)
}

/// Creates a handshake message with proper header formatting
///
/// Formats a handshake message with:
/// - Message type (1 byte)
/// - Message length (3 bytes, big-endian)
/// - Message payload
pub fn handshake_message_with_header(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    create_handshake_message_with_header_from_type(msg_type, payload)
}

// =====================================
// PAYLOAD CONSTRUCTION FUNCTIONS

/// Adds the protocol version to the ClientHello payload
/// Uses legacy version (TLS 1.2) for compatibility
fn add_protocol_version(payload: &mut Vec<u8>) {
    payload.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 for compatibility
}

/// Adds the client random to the ClientHello payload
fn add_client_random(payload: &mut Vec<u8>, client_random: &[u8; 32]) {
    payload.extend_from_slice(client_random);
}

/// Adds a random session ID to the ClientHello payload
/// Uses 32-byte session ID like OpenSSL for better compatibility
fn add_session_id(payload: &mut Vec<u8>) {
    const SESSION_ID_LENGTH: u8 = 32;

    payload.push(SESSION_ID_LENGTH);

    let mut session_id = [0u8; SESSION_ID_LENGTH as usize];
    rand::thread_rng().fill_bytes(&mut session_id);
    payload.extend_from_slice(&session_id);
}

/// Adds TLS 1.3 cipher suites to the ClientHello payload
fn add_cipher_suites(payload: &mut Vec<u8>) {
    let cipher_suites_bytes = flatten_cipher_suites(TLS13_CIPHER_SUITES);

    payload.extend_from_slice(&(cipher_suites_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(&cipher_suites_bytes);
}

/// Adds compression methods to the ClientHello payload
/// Only null compression is supported in TLS 1.3
fn add_compression_methods(payload: &mut Vec<u8>) {
    payload.push(1u8); // Number of compression methods
    payload.push(0u8); // Null compression
}

/// Adds all required extensions to the ClientHello payload
/// Extensions are added in RFC-compliant order for maximum compatibility
fn add_extensions(payload: &mut Vec<u8>, domain: &str, x25519_pubkey: &[u8]) {
    let mut extensions_bytes = Vec::new();

    // Add extensions in proper order
    add_server_name_indication(&mut extensions_bytes, domain);
    add_supported_groups_extension(&mut extensions_bytes);
    add_signature_algorithms_extension(&mut extensions_bytes);
    add_supported_versions_extension(&mut extensions_bytes);
    add_key_share_extension(&mut extensions_bytes, x25519_pubkey);
    add_psk_key_exchange_modes_extension(&mut extensions_bytes);

    // Add extensions length prefix
    payload.extend_from_slice(&(extensions_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(&extensions_bytes);
}

// ============================================================================
// EXTENSION CONSTRUCTION FUNCTIONS

/// Adds Server Name Indication (SNI) extension
fn add_server_name_indication(extensions: &mut Vec<u8>, domain: &str) {
    let sni_hostname = domain.as_bytes();
    let mut sni_payload = Vec::with_capacity(5 + sni_hostname.len());

    // SNI list length
    sni_payload.extend_from_slice(&((sni_hostname.len() + 3) as u16).to_be_bytes());

    // Name type: host_name
    sni_payload.push(SNI_HOSTNAME_TYPE);

    // Hostname length and hostname
    sni_payload.extend_from_slice(&(sni_hostname.len() as u16).to_be_bytes());
    sni_payload.extend_from_slice(sni_hostname);

    let extension = Extension::new(EXTENSION_TYPE_SERVER_NAME, &sni_payload);
    extensions.extend_from_slice(&extension.to_bytes());
}

/// Adds Supported Groups extension with conservative group list
fn add_supported_groups_extension(extensions: &mut Vec<u8>) {
    let mut supported_groups = Vec::with_capacity(2 + SUPPORTED_GROUPS.len() * 2);

    // Groups list length
    supported_groups.extend_from_slice(&((SUPPORTED_GROUPS.len() * 2) as u16).to_be_bytes());

    // Add each group
    for group in SUPPORTED_GROUPS {
        supported_groups.extend_from_slice(group);
    }

    let extension = Extension::new(EXTENSION_TYPE_SUPPORTED_GROUPS, &supported_groups);
    extensions.extend_from_slice(&extension.to_bytes());
}

/// Adds Signature Algorithms extension matching OpenSSL format
fn add_signature_algorithms_extension(extensions: &mut Vec<u8>) {
    let mut sig_algs_content = Vec::with_capacity(2 + SIGNATURE_ALGORITHMS.len() * 2);

    // Signature algorithms list length
    sig_algs_content.extend_from_slice(&((SIGNATURE_ALGORITHMS.len() * 2) as u16).to_be_bytes());

    // Add each signature algorithm
    for alg in SIGNATURE_ALGORITHMS {
        sig_algs_content.extend_from_slice(alg);
    }

    let extension = Extension::new(EXTENSION_TYPE_SIGNATURE_ALGORITHMS, &sig_algs_content);
    extensions.extend_from_slice(&extension.to_bytes());
}

/// Adds Supported Versions extension (MUST be present for TLS 1.3)
fn add_supported_versions_extension(extensions: &mut Vec<u8>) {
    // Only advertise TLS 1.3 support
    let supported_versions = [2u8, 0x03, 0x04]; // length=2, TLS 1.3 only

    let extension = Extension::new(EXTENSION_TYPE_SUPPORTED_VERSIONS, &supported_versions);
    extensions.extend_from_slice(&extension.to_bytes());
}

/// Adds Key Share extension with X25519 public key (MUST be present for TLS 1.3)
fn add_key_share_extension(extensions: &mut Vec<u8>, x25519_pubkey: &[u8]) {
    let mut key_share = Vec::with_capacity(4 + x25519_pubkey.len());

    // Named group (X25519)
    key_share.extend_from_slice(&NamedGroup::X25519.as_bytes());

    // Key exchange data length and data
    key_share.extend_from_slice(&(x25519_pubkey.len() as u16).to_be_bytes());
    key_share.extend_from_slice(x25519_pubkey);

    // Key share list with length prefix
    let mut key_share_list = Vec::with_capacity(2 + key_share.len());
    key_share_list.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    key_share_list.extend_from_slice(&key_share);

    let extension = Extension::new(EXTENSION_TYPE_KEY_SHARE, &key_share_list);
    extensions.extend_from_slice(&extension.to_bytes());
}

/// Adds PSK Key Exchange Modes extension (required for TLS 1.3)
fn add_psk_key_exchange_modes_extension(extensions: &mut Vec<u8>) {
    // Support PSK with (EC)DHE key establishment
    let psk_modes = [0x01, 0x01]; // length=1, psk_dhe_ke=1

    let extension = Extension::new(EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES, &psk_modes);
    extensions.extend_from_slice(&extension.to_bytes());
}

// =========================================
// UTILITY FUNCTIONS

/// Creates a handshake message with proper header from HandshakeMessageType
fn create_handshake_message_with_header(msg_type: HandshakeMessageType, payload: &[u8]) -> Vec<u8> {
    create_handshake_message_with_header_from_type(msg_type.as_u8(), payload)
}

/// Creates a handshake message with proper header from raw message type
fn create_handshake_message_with_header_from_type(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + payload.len());

    // Message type (1 byte)
    message.push(msg_type);

    // Message length (3 bytes, big-endian)
    let length_bytes = (payload.len() as u32).to_be_bytes();
    message.extend_from_slice(&length_bytes[1..4]);

    // Message payload
    message.extend_from_slice(payload);

    message
}

/// Flattens a slice of cipher suite arrays into a single byte vector
fn flatten_cipher_suites(cipher_suites: &[[u8; 2]]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(cipher_suites.len() * 2);

    for cs in cipher_suites {
        bytes.extend_from_slice(cs);
    }

    bytes
}
