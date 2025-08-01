use crate::services::errors::TlsError;
use crate::services::tls_handshake::tls13::handshake_processor::{
    process_encrypted_handshake_records, read_tls_record,
};
use crate::services::tls_handshake::tls13::key_schedule::derive_tls13_handshake_traffic_secrets_dynamic;
use crate::services::tls_handshake::tls13::messages::build_client_hello;
use crate::services::tls_handshake::tls13::transcript::{TranscriptHash, TranscriptHashAlgorithm};
use crate::services::tls_parser::{
    CipherSuite, HandshakeMessageType, parse_handshake_messages, parse_tls13_server_hello_payload,
};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::{SecureRandom, SystemRandom};
use std::io::Write;
use std::net::TcpStream;

// ============================================================================
// CONNECTION STATE

#[allow(dead_code)]
pub struct Tls13ConnectionState {
    pub client_secret: Option<[u8; 32]>,
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

// ============================================================================
// PUBLIC API
// ============================================================================

pub fn perform_tls13_handshake_full(domain: &str) -> Result<Tls13ConnectionState, TlsError> {
    perform_tls13_handshake_full_with_cert(domain).map(|(state, _)| state)
}

pub fn test_tls13(domain: &str) -> Result<Option<Vec<u8>>, TlsError> {
    perform_tls13_handshake_full_with_cert(domain).map(|(_state, cert)| cert)
}

// ============================================================================
// CORE HANDSHAKE IMPLEMENTATION
// ============================================================================

pub fn perform_tls13_handshake_full_with_cert(
    domain: &str,
) -> Result<(Tls13ConnectionState, Option<Vec<u8>>), TlsError> {
    let (client_random, client_private, client_public_bytes) = generate_client_keys()?;
    let client_hello = build_client_hello(domain, &client_random, &client_public_bytes);

    let mut stream =
        TcpStream::connect((domain, 443)).map_err(|e| TlsError::ConnectionFailed(e.to_string()))?;

    stream.write_all(&client_hello).map_err(TlsError::IoError)?;

    let (server_hello_msg, server_random, negotiated_cipher_suite, server_public) =
        process_server_hello(&mut stream)?;

    let cipher_suite_obj = validate_cipher_suite(negotiated_cipher_suite)?;
    let hash_alg = get_hash_algorithm(&cipher_suite_obj);
    let mut transcript = create_transcript(&hash_alg, &client_hello, &server_hello_msg);

    let shared_secret = perform_key_exchange(client_private, &server_public)?;

    let (client_hs_traffic_secret, server_hs_traffic_secret) =
        derive_tls13_handshake_traffic_secrets_dynamic(&shared_secret, &transcript, hash_alg)?;

    let server_certificate = process_encrypted_handshake(
        &mut stream,
        &server_hs_traffic_secret,
        &cipher_suite_obj,
        &mut transcript,
    )?;

    let connection_state = Tls13ConnectionState {
        client_secret: None,
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
    };

    Ok((connection_state, server_certificate))
}

// ======================================
// HELPER FUNCTIONS

fn generate_client_keys() -> Result<([u8; 32], EphemeralPrivateKey, [u8; 32]), TlsError> {
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

    Ok((client_random, client_private, client_public_bytes))
}

fn process_server_hello(
    stream: &mut TcpStream,
) -> Result<(Vec<u8>, [u8; 32], [u8; 2], [u8; 32]), TlsError> {
    let server_hello_record = read_tls_record(stream)?;

    if server_hello_record.content_type != crate::services::tls_parser::TlsContentType::Handshake {
        return Err(TlsError::HandshakeError(format!(
            "Expected Handshake record, got {:?} with length {}",
            server_hello_record.content_type, server_hello_record.length
        )));
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
    let server_public = sh
        .server_key_share_public
        .ok_or_else(|| TlsError::KeyDerivationError("No server key share".to_string()))?
        .try_into()
        .map_err(|_| TlsError::KeyExchangeError("Invalid server key length".to_string()))?;

    Ok((
        server_hello_msg.raw_bytes.clone(),
        sh.server_random,
        sh.chosen_cipher_suite,
        server_public,
    ))
}

fn validate_cipher_suite(negotiated_cipher_suite: [u8; 2]) -> Result<CipherSuite, TlsError> {
    let cipher_suite_obj = CipherSuite::new(negotiated_cipher_suite[0], negotiated_cipher_suite[1]);
    if cipher_suite_obj.id == [0x00, 0x00] {
        return Err(TlsError::UnsupportedCipherSuite(format!(
            "Cipher suite {:02x}{:02x} not supported",
            negotiated_cipher_suite[0], negotiated_cipher_suite[1]
        )));
    }
    Ok(cipher_suite_obj)
}

fn get_hash_algorithm(cipher_suite: &CipherSuite) -> TranscriptHashAlgorithm {
    match cipher_suite.hash_algorithm {
        crate::services::tls_parser::HashAlgorithm::Sha256 => TranscriptHashAlgorithm::Sha256,
        crate::services::tls_parser::HashAlgorithm::Sha384 => TranscriptHashAlgorithm::Sha384,
    }
}

fn create_transcript(
    hash_alg: &TranscriptHashAlgorithm,
    client_hello: &[u8],
    server_hello_msg: &[u8],
) -> TranscriptHash {
    let mut transcript = TranscriptHash::new(hash_alg.clone());
    transcript.update(&client_hello[5..]);
    transcript.update(server_hello_msg);
    transcript
}

fn perform_key_exchange(
    client_private: EphemeralPrivateKey,
    server_public: &[u8; 32],
) -> Result<[u8; 32], TlsError> {
    ring::agreement::agree_ephemeral(
        client_private,
        &UnparsedPublicKey::new(&X25519, server_public),
        |secret| {
            let mut out = [0u8; 32];
            out.copy_from_slice(secret);
            out
        },
    )
    .map_err(|_| TlsError::KeyExchangeError("Failed to derive shared secret".to_string()))
}

fn process_encrypted_handshake(
    stream: &mut TcpStream,
    server_hs_traffic_secret: &[u8],
    cipher_suite_obj: &CipherSuite,
    transcript: &mut TranscriptHash,
) -> Result<Option<Vec<u8>>, TlsError> {
    let dummy_app_secret = vec![0u8; server_hs_traffic_secret.len()];

    let decrypted_records = process_encrypted_handshake_records(
        stream,
        server_hs_traffic_secret,
        &dummy_app_secret,
        cipher_suite_obj,
        transcript,
    )?;

    for record in decrypted_records.iter() {
        if let Ok(msgs) = parse_handshake_messages(&record.payload) {
            for msg in msgs.iter() {
                if msg.msg_type == HandshakeMessageType::Certificate {
                    if let Some(cert) = extract_tls13_certificate(&msg.raw_bytes) {
                        return Ok(Some(cert));
                    }
                }
            }
        }
    }

    Ok(None)
}

// ================================
// CERTIFICATE EXTRACTION

fn extract_tls13_certificate(certificate_msg: &[u8]) -> Option<Vec<u8>> {
    if certificate_msg.len() <= 5 {
        return None;
    }

    let context_len = certificate_msg[4] as usize;
    let cert_list_start = 4 + 1 + context_len;

    if certificate_msg.len() <= cert_list_start + 3 {
        return None;
    }

    let cert_data_start = cert_list_start + 3;

    if certificate_msg.len() <= cert_data_start + 3 {
        return None;
    }

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
