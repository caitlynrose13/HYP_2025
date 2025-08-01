use crate::services::errors::TlsError;
use crate::services::tls_handshake::tls13::handshake_processor::{
    process_encrypted_handshake_records, read_tls_record,
};
use crate::services::tls_handshake::tls13::key_schedule::derive_tls13_handshake_traffic_secrets_dynamic;
use crate::services::tls_handshake::tls13::messages::build_client_hello;
use crate::services::tls_handshake::tls13::transcript::{TranscriptHash, TranscriptHashAlgorithm};
use crate::services::tls_parser::CipherSuite;
use crate::services::tls_parser::{
    HandshakeMessageType, parse_handshake_messages, parse_tls13_server_hello_payload,
};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::io::Write;
use std::net::TcpStream;

#[allow(dead_code)]
pub struct Tls13ConnectionState {
    pub client_secret: Option<[u8; 32]>, // Option so we can take ownership
    pub client_public: [u8; 32],
    pub server_public: [u8; 32],
    pub shared_secret: [u8; 32],
    pub client_hs_traffic_secret: Vec<u8>,
    pub server_hs_traffic_secret: Vec<u8>,
    pub negotiated_cipher_suite: [u8; 2],
    pub server_random: [u8; 32],
    pub client_random: [u8; 32],
    pub transcript_hash: Vec<u8>,
}

/// Perform a full TLS 1.3 handshake and return connection state only
pub fn perform_tls13_handshake_full(domain: &str) -> Result<Tls13ConnectionState, TlsError> {
    perform_tls13_handshake_full_with_cert(domain).map(|(state, _)| state)
}

/// Perform a full TLS 1.3 handshake and return both connection state and certificate
pub fn perform_tls13_handshake_full_with_cert(
    domain: &str,
) -> Result<(Tls13ConnectionState, Option<Vec<u8>>), TlsError> {
    let rng = SystemRandom::new();
    let mut client_random = [0u8; 32];
    rng.fill(&mut client_random).map_err(|e| {
        TlsError::KeyExchangeError(format!("Failed to generate client random: {:?}", e))
    })?;

    // Add timestamp to first 4 bytes to ensure each connection is unique
    // This prevents any potential session caching or 0-RTT issues with Google
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    client_random[0..4].copy_from_slice(&timestamp.to_be_bytes());

    // Generate X25519 keypair using ring
    let client_private = EphemeralPrivateKey::generate(&X25519, &rng).map_err(|e| {
        TlsError::KeyExchangeError(format!("Failed to generate X25519 private key: {:?}", e))
    })?;
    let client_public_bytes: [u8; 32] = {
        let pk = client_private.compute_public_key().unwrap();
        let pk_bytes = pk.as_ref();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pk_bytes);
        arr
    };

    let client_hello = build_client_hello(domain, &client_random, &client_public_bytes);
    let mut stream =
        TcpStream::connect((domain, 443)).map_err(|e| TlsError::ConnectionFailed(e.to_string()))?;
    stream
        .write_all(&client_hello)
        .map_err(|e| TlsError::IoError(e))?;

    // Read ServerHello using the modular function
    let server_hello_record = read_tls_record(&mut stream)?;

    if server_hello_record.content_type != crate::services::tls_parser::TlsContentType::Handshake {
        return Err(TlsError::HandshakeError(format!(
            "Expected Handshake record from server, got {:?} with length {}",
            server_hello_record.content_type, server_hello_record.length
        )));
    }

    // Parse handshake messages to find the Certificate message
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
        .map_err(|_| TlsError::KeyExchangeError("Invalid server key length".to_string()))?;

    let cipher_suite_obj = CipherSuite::new(negotiated_cipher_suite[0], negotiated_cipher_suite[1]);
    if cipher_suite_obj.id == [0x00, 0x00] {
        return Err(TlsError::UnsupportedCipherSuite(format!(
            "Cipher suite {:02x}{:02x} not supported",
            negotiated_cipher_suite[0], negotiated_cipher_suite[1]
        )));
    }
    let hash_alg = match cipher_suite_obj.hash_algorithm {
        crate::services::tls_parser::HashAlgorithm::Sha256 => TranscriptHashAlgorithm::Sha256,
        crate::services::tls_parser::HashAlgorithm::Sha384 => TranscriptHashAlgorithm::Sha384,
    };
    let mut transcript = TranscriptHash::new(hash_alg.clone());

    transcript.update(&client_hello[5..]);
    transcript.update(&server_hello_msg.raw_bytes);

    // Use ring to perform X25519 key exchange
    let shared_secret: [u8; 32] = ring::agreement::agree_ephemeral(
        client_private,
        &UnparsedPublicKey::new(&X25519, &server_public),
        |secret| {
            let mut out = [0u8; 32];
            out.copy_from_slice(secret);
            out
        },
    )
    .map_err(|_| TlsError::KeyExchangeError("Failed to derive shared secret".to_string()))?;

    // Use the correct TLS 1.3 key derivation function
    let (client_hs_traffic_secret, server_hs_traffic_secret) =
        derive_tls13_handshake_traffic_secrets_dynamic(
            &shared_secret,
            &transcript,
            hash_alg.clone(),
        )?;

    let dummy_app_secret = vec![0u8; server_hs_traffic_secret.len()];

    let decrypted_records = process_encrypted_handshake_records(
        &mut stream,
        &server_hs_traffic_secret,
        &dummy_app_secret,
        &cipher_suite_obj,
        &mut transcript,
    )?;

    // Extract certificate bytes from the DECRYPTED handshake records
    let mut server_certificate: Option<Vec<u8>> = None;
    for record in decrypted_records.iter() {
        if let Ok(msgs) = parse_handshake_messages(&record.payload) {
            for msg in msgs.iter() {
                if msg.msg_type == HandshakeMessageType::Certificate {
                    if let Some(cert) = extract_tls13_certificate(&msg.raw_bytes) {
                        server_certificate = Some(cert);
                        break;
                    }
                }
            }
            if server_certificate.is_some() {
                break;
            }
        }
    }

    Ok((
        Tls13ConnectionState {
            client_secret: None, // ring does not expose private key bytes
            client_public: client_public_bytes,
            server_public,
            shared_secret,
            client_hs_traffic_secret,
            server_hs_traffic_secret,
            negotiated_cipher_suite,
            server_random,
            client_random,
            transcript_hash: transcript
                .clone_hash()
                .map_err(|e| TlsError::HandshakeError(e.to_string()))?,
        },
        server_certificate,
    ))
}

/// Extract the first certificate from a TLS 1.3 Certificate handshake message
fn extract_tls13_certificate(certificate_msg: &[u8]) -> Option<Vec<u8>> {
    // TLS 1.3 Certificate message structure:
    // Handshake header (4 bytes) + Certificate request context + Certificate list

    if certificate_msg.len() <= 5 {
        return None;
    }

    let context_len = certificate_msg[4] as usize;
    let cert_list_start = 4 + 1 + context_len; // Skip handshake header + context length + context

    if certificate_msg.len() <= cert_list_start + 3 {
        return None;
    }

    // Certificate list length (3 bytes)
    let cert_data_start = cert_list_start + 3;

    if certificate_msg.len() <= cert_data_start + 3 {
        return None;
    }

    // First certificate length (3 bytes)
    let first_cert_len = u32::from_be_bytes([
        0,
        certificate_msg[cert_data_start],
        certificate_msg[cert_data_start + 1],
        certificate_msg[cert_data_start + 2],
    ]) as usize;

    let first_cert_start = cert_data_start + 3;
    let first_cert_end = first_cert_start + first_cert_len;

    if certificate_msg.len() >= first_cert_end {
        Some(certificate_msg[first_cert_start..first_cert_end].to_vec())
    } else {
        None
    }
}

/// Clean test function to perform a TLS 1.3 handshake with any domain
/// Returns certificate if handshake succeeds, Err(TlsError) otherwise
pub fn test_tls13(domain: &str) -> Result<Option<Vec<u8>>, TlsError> {
    perform_tls13_handshake_full_with_cert(domain).map(|(_state, cert)| cert)
}
