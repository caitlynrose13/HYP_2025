use rand::RngCore;
use std::io::Write;
use std::net::TcpStream;

use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys::generate_x25519_keypair;
use crate::services::tls_handshake::tls13::handshake_processor::{
    process_encrypted_handshake_records, read_tls_record,
};
use crate::services::tls_handshake::tls13::key_schedule::{
    derive_tls13_handshake_traffic_secrets, perform_x25519_key_exchange,
};
use crate::services::tls_handshake::tls13::messages::build_client_hello;
use crate::services::tls_handshake::tls13::transcript::TranscriptHash;
use crate::services::tls_parser::CipherSuite;
use crate::services::tls_parser::{
    HandshakeMessageType, parse_handshake_messages, parse_tls13_server_hello_payload,
};

#[allow(dead_code)]
pub struct Tls13ConnectionState {
    pub client_secret: Option<x25519_dalek::EphemeralSecret>, // Option so we can take ownership
    pub client_public: [u8; 32],
    pub server_public: [u8; 32],
    pub shared_secret: [u8; 32],
    pub client_hs_traffic_secret: Vec<u8>,
    pub server_hs_traffic_secret: Vec<u8>,
    pub negotiated_cipher_suite: [u8; 2],
    pub server_random: [u8; 32],
    pub client_random: [u8; 32],
    pub transcript_hash: [u8; 32],
}

/// Perform X25519 key exchange and derive handshake secret using HKDF (TLS 1.3)
/// This function has been moved to key_schedule.rs as perform_x25519_key_exchange
#[deprecated(note = "Use key_schedule::perform_x25519_key_exchange instead")]
pub fn derive_tls13_handshake_secret(
    client_secret: x25519_dalek::EphemeralSecret,
    server_public: &[u8; 32],
) -> [u8; 32] {
    perform_x25519_key_exchange(client_secret, server_public)
}

/// Perform a minimal TLS 1.3 handshake to derive traffic secrets.
/// This function sends a ClientHello, processes the ServerHello, and handles encrypted handshake messages.
pub fn perform_tls13_handshake_minimal(domain: &str) -> Result<Tls13ConnectionState, TlsError> {
    // 1. Generate client random and X25519 keypair
    let mut client_random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_random);
    let (client_secret, client_public) = generate_x25519_keypair();

    // 2. Build and send ClientHello
    let client_hello = build_client_hello(domain, &client_random, &client_public);
    println!(
        "[DEBUG] Sending ClientHello ({} bytes): {}",
        client_hello.len(),
        hex::encode(&client_hello)
    );
    let mut stream =
        TcpStream::connect((domain, 443)).map_err(|e| TlsError::ConnectionFailed(e.to_string()))?;
    stream
        .write_all(&client_hello)
        .map_err(|e| TlsError::IoError(e))?;

    // 3. Read ServerHello using the modular function
    let server_hello_record = read_tls_record(&mut stream)?;

    if server_hello_record.content_type != crate::services::tls_parser::TlsContentType::Handshake {
        return Err(TlsError::HandshakeError(
            "Expected Handshake record from server".to_string(),
        ));
    }

    let handshake_messages = parse_handshake_messages(&server_hello_record.payload)?;
    let server_hello_msg = handshake_messages
        .get(0)
        .ok_or_else(|| TlsError::HandshakeError("No handshake message in record".to_string()))?;

    if server_hello_msg.msg_type != HandshakeMessageType::ServerHello {
        return Err(TlsError::HandshakeError(
            "Expected ServerHello as first handshake message".to_string(),
        ));
    }

    let sh = parse_tls13_server_hello_payload(&server_hello_msg.payload)?;
    let server_random = sh.server_random;
    let negotiated_cipher_suite = sh.chosen_cipher_suite;
    let server_public = sh
        .server_key_share_public
        .ok_or_else(|| TlsError::KeyDerivationError("No server key share".to_string()))?;
    let server_public: [u8; 32] = server_public
        .try_into()
        .map_err(|_| TlsError::KeyDerivationError("Invalid server key length".to_string()))?;

    // 4. Update transcript and derive secrets using proper TLS 1.3 key schedule
    let mut transcript = TranscriptHash::new();

    let client_hello_hs_msg = crate::services::tls_parser::TlsHandshakeMessage {
        msg_type: HandshakeMessageType::ClientHello,
        length: (client_hello.len() - 9) as u32,
        payload: client_hello[9..].to_vec(),
        raw_bytes: client_hello[5..].to_vec(),
    };

    // Debug: Show ClientHello raw_bytes
    println!(
        "[TRANSCRIPT_DEBUG] ClientHello raw_bytes (first 20): {:02x?}",
        &client_hello_hs_msg.raw_bytes[..20.min(client_hello_hs_msg.raw_bytes.len())]
    );
    println!(
        "[TRANSCRIPT_DEBUG] ClientHello raw_bytes length: {}",
        client_hello_hs_msg.raw_bytes.len()
    );

    // After adding ClientHello
    transcript.update(&client_hello_hs_msg.raw_bytes);
    println!(
        "[TRANSCRIPT_DEBUG] After ClientHello hash: {:02x?}",
        transcript.clone_hash()
    );

    // Debug: Show ServerHello raw_bytes
    println!(
        "[TRANSCRIPT_DEBUG] ServerHello raw_bytes (first 20): {:02x?}",
        &server_hello_msg.raw_bytes[..20.min(server_hello_msg.raw_bytes.len())]
    );
    println!(
        "[TRANSCRIPT_DEBUG] ServerHello raw_bytes length: {}",
        server_hello_msg.raw_bytes.len()
    );

    // After adding ServerHello
    transcript.update(&server_hello_msg.raw_bytes);
    println!(
        "[TRANSCRIPT_DEBUG] After ServerHello hash: {:02x?}",
        transcript.clone_hash()
    );

    // Use the modular key exchange function
    let shared_secret = perform_x25519_key_exchange(client_secret, &server_public);
    let transcript_hash = transcript.clone_hash();

    println!("[DEBUG] Shared secret: {}", hex::encode(&shared_secret));
    println!("[DEBUG] Transcript hash: {}", hex::encode(&transcript_hash));

    // Use the correct TLS 1.3 key derivation function
    let (client_hs_traffic_secret, server_hs_traffic_secret) =
        derive_tls13_handshake_traffic_secrets(&shared_secret, &transcript_hash)?;

    println!(
        "[DEBUG] Client HS traffic secret: {}",
        hex::encode(&client_hs_traffic_secret)
    );
    println!(
        "[DEBUG] Server HS traffic secret: {}",
        hex::encode(&server_hs_traffic_secret)
    );

    // 5. Process encrypted handshake records using the modular function
    let cipher_suite_obj = CipherSuite::new(negotiated_cipher_suite[0], negotiated_cipher_suite[1]);
    let _decrypted_records = process_encrypted_handshake_records(
        &mut stream,
        &server_hs_traffic_secret,
        &cipher_suite_obj,
    )?;

    println!("[TLS13_HANDSHAKE] ✅ Handshake processing completed successfully!");

    Ok(Tls13ConnectionState {
        client_secret: None, // Consumed during key exchange
        client_public,
        server_public,
        shared_secret,
        client_hs_traffic_secret,
        server_hs_traffic_secret,
        negotiated_cipher_suite,
        server_random,
        client_random,
        transcript_hash,
    })
}

/// Test function to demonstrate the modular TLS 1.3 client
pub fn test_tls13_client() -> Result<(), TlsError> {
    println!("🚀 Testing modular TLS 1.3 client...");

    // Test with a real TLS 1.3 server
    let domain = "www.google.com";
    let connection_state = perform_tls13_handshake_minimal(domain)?;

    println!("✅ TLS 1.3 handshake completed successfully!");
    println!(
        "Negotiated cipher suite: {:02x}{:02x}",
        connection_state.negotiated_cipher_suite[0], connection_state.negotiated_cipher_suite[1]
    );

    Ok(())
}
