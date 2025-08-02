//! TLS 1.2 Client Handshake Implementation
//!
//! This module provides a complete TLS 1.2 client handshake implementation with support for:
//! - ECDHE key exchange
//! - AES-GCM cipher suites
//! - Certificate validation
//! - Handshake message parsing and verification

use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys;
use crate::services::tls_handshake::keys::TlsAeadCipher;
use crate::services::tls_handshake::messages;
use crate::services::tls_handshake::messages::HandshakeMessage;
use crate::services::tls_handshake::validation;
use crate::services::tls_parser::{
    CipherSuite, HandshakeMessageType, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TlsContentType, TlsHandshakeMessage, TlsParserError,
    TlsRecord, TlsVersion,
};

use elliptic_curve::sec1::ToEncodedPoint;
use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey};
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

// ======================
// TYPES AND STRUCTURES

/// TLS security level classification
#[derive(Debug, Clone, PartialEq)]
pub enum TlsSecurityLevel {
    Modern,     // Supports TLS 1.2 or 1.3
    Deprecated, // Only supports TLS 1.0 or 1.1
    Unknown,    // Couldn't determine
}

/// Complete TLS connection state after successful handshake
pub struct TlsConnectionState {
    pub master_secret: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_fixed_iv: Vec<u8>,
    pub server_fixed_iv: Vec<u8>,
    pub client_sequence_number: u64,
    pub server_sequence_number: u64,
    pub negotiated_cipher_suite: CipherSuite,
    pub negotiated_tls_version: TlsVersion,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub handshake_hash: [u8; 32],
}

/// Tracks received handshake messages and negotiated parameters
#[derive(Debug, Default)]
struct HandshakeState {
    server_hello: bool,
    certificate: bool,
    server_key_exchange: bool,
    server_hello_done: bool,
    chosen_cipher_suite: Option<[u8; 2]>,
}

// ===========
// HANDSHAKE STATE IMPLEMENTATION

impl HandshakeState {
    /// Updates handshake state based on received message type
    fn update(&mut self, msg_type: &HandshakeMessageType, payload: &[u8]) {
        use HandshakeMessageType::*;

        match msg_type {
            ServerHello => {
                self.server_hello = true;
                // Parse and store the chosen cipher suite
                if payload.len() > 4 {
                    if let Ok(parsed) =
                        crate::services::tls_parser::parse_server_hello_content(&payload[4..])
                    {
                        self.chosen_cipher_suite = Some(parsed.chosen_cipher_suite);
                    }
                }
            }
            Certificate => self.certificate = true,
            ServerKeyExchange => self.server_key_exchange = true,
            ServerHelloDone => self.server_hello_done = true,
            _ => {}
        }
    }

    /// Checks if all required handshake messages have been received
    fn all_required_received(&self) -> bool {
        if let Some(cs_id) = self.chosen_cipher_suite {
            // ECDHE suites require additional ServerKeyExchange message
            if cs_id == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.id
                || cs_id == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.id
            {
                self.server_hello
                    && self.certificate
                    && self.server_key_exchange
                    && self.server_hello_done
            } else {
                // Static RSA suites only need ServerHello, Certificate, ServerHelloDone
                self.server_hello && self.certificate && self.server_hello_done
            }
        } else {
            false
        }
    }
}

// ==========================================================
// PUBLIC API FUNCTIONS

/// Performs a complete TLS 1.2 handshake with the specified domain
///
/// Returns the connection state on success, or a TLS error on failure.
pub fn perform_tls_handshake_full(
    domain: &str,
    tls_version: TlsVersion,
) -> Result<TlsConnectionState, TlsError> {
    perform_tls_handshake_full_with_cert(domain, tls_version).map(|(state, _)| state)
}

/// Performs a complete TLS 1.2 handshake and returns both connection state and server certificate
///
/// Returns a tuple of (TlsConnectionState, Option<certificate_der_bytes>) on success.
pub fn perform_tls_handshake_full_with_cert(
    domain: &str,
    tls_version: TlsVersion,
) -> Result<(TlsConnectionState, Option<Vec<u8>>), TlsError> {
    // Establish TCP connection
    let mut stream = establish_tcp_connection(domain, 443)?;

    // Generate client random and ephemeral key pair
    let mut client_random = [0u8; 32];
    thread_rng().fill(&mut client_random);

    let mut rng = thread_rng();
    let client_ephemeral_secret = EphemeralSecret::random(&mut rng);
    let client_ephemeral_public_encoded =
        client_ephemeral_secret.public_key().to_encoded_point(false);
    let client_ephemeral_public_bytes = client_ephemeral_public_encoded.as_bytes();

    // Send Client Hello
    let mut handshake_transcript = Vec::new();
    let (client_hello_record, raw_client_hello_handshake) =
        HandshakeMessage::build_client_hello_with_random_and_key_share(
            domain,
            tls_version,
            &client_random,
            client_ephemeral_public_bytes,
        )?;

    stream.write_all(&client_hello_record)?;
    handshake_transcript.extend_from_slice(&raw_client_hello_handshake);

    // Receive and process server handshake messages
    let (handshake_messages, server_hello_parsed, server_key_exchange, certificates) =
        receive_server_handshake(&mut stream, &mut handshake_transcript, tls_version)?;

    // Validate server's chosen cipher suite
    let chosen_cipher_suite = validate_cipher_suite(&server_hello_parsed.chosen_cipher_suite)?;

    // Verify server key exchange signature
    validation::verify_server_key_exchange_signature(
        &server_key_exchange,
        &client_random,
        &server_hello_parsed.server_random,
        &certificates,
    )?;

    // Perform ECDHE key exchange
    let pre_master_secret =
        perform_ecdhe_key_exchange(&client_ephemeral_secret, &server_key_exchange.public_key)?;

    // Derive master secret and encryption keys
    let master_secret = keys::calculate_master_secret(
        &pre_master_secret,
        &client_random,
        &server_hello_parsed.server_random,
        chosen_cipher_suite.hash_algorithm,
    )?;

    let key_block = keys::calculate_key_block(
        &master_secret,
        &server_hello_parsed.server_random,
        &client_random,
        &chosen_cipher_suite,
    )?;

    // Derive AEAD encryption keys for TLS 1.2
    let (
        client_write_key,
        server_write_key,
        client_fixed_iv,
        server_fixed_iv,
        client_cipher,
        server_cipher,
    ) = derive_tls12_keys(&chosen_cipher_suite, &key_block)?;

    // Complete client-side handshake
    complete_client_handshake(
        &mut stream,
        &mut handshake_transcript,
        &master_secret,
        &client_cipher,
        &client_fixed_iv,
        client_ephemeral_public_bytes,
        chosen_cipher_suite.hash_algorithm,
    )?;

    // Verify server finished message
    verify_server_finished(
        &mut stream,
        &handshake_transcript,
        &master_secret,
        &server_cipher,
        &server_fixed_iv,
        tls_version,
        chosen_cipher_suite.hash_algorithm,
    )?;

    // Build final connection state
    let handshake_hash = Sha256::digest(&handshake_transcript);
    let first_cert = certificates.get(0).cloned();

    Ok((
        TlsConnectionState {
            master_secret: master_secret.to_vec(),
            client_write_key,
            server_write_key,
            client_fixed_iv,
            server_fixed_iv,
            client_sequence_number: 1,
            server_sequence_number: 1,
            negotiated_cipher_suite: chosen_cipher_suite.clone(),
            negotiated_tls_version: TlsVersion::TLS1_2,
            client_random,
            server_random: server_hello_parsed.server_random,
            handshake_hash: handshake_hash.into(),
        },
        first_cert,
    ))
}

///
/// Returns Ok(()) if handshake succeeds, Err(TlsError) otherwise.
pub fn test_tls12(domain: &str) -> Result<(), TlsError> {
    perform_tls_handshake_full(domain, TlsVersion::TLS1_2).map(|_| ())
}

////////////////////
// HELPER FUNCTIONS

/// Establishes a TCP connection to the specified domain and port
fn establish_tcp_connection(domain: &str, port: u16) -> Result<TcpStream, TlsError> {
    let addr_str = format!("{}:{}", domain, port);
    let mut addrs_iter = addr_str
        .to_socket_addrs()
        .map_err(|e| TlsError::InvalidAddress(format!("Couldn't resolve address: {}", e)))?;

    let addr = addrs_iter
        .next()
        .ok_or_else(|| TlsError::ConnectionFailed(format!("No address found for {}", domain)))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| TlsError::ConnectionFailed(format!("TCP connect failed: {}", e)))?;

    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    Ok(stream)
}

/// Receives and processes all required server handshake messages
fn receive_server_handshake(
    stream: &mut TcpStream,
    handshake_transcript: &mut Vec<u8>,
    tls_version: TlsVersion,
) -> Result<
    (
        Vec<TlsHandshakeMessage>,
        crate::services::tls_parser::ServerHelloParsed,
        crate::services::tls_parser::ServerKeyExchangeParsed,
        Vec<Vec<u8>>,
    ),
    TlsError,
> {
    let handshake_transcript_len = handshake_transcript.len();
    let mut handshake_messages = Vec::new();
    let mut handshake_state = HandshakeState::default();

    // Read all handshake records until complete
    while !handshake_state.all_required_received() {
        let server_response = messages::read_tls_record(stream, tls_version)?;
        let msgs = crate::services::tls_parser::parse_handshake_messages(&server_response.payload)?;

        for msg in msgs.iter() {
            handshake_state.update(&msg.msg_type, &msg.raw_bytes);
            handshake_transcript.extend_from_slice(&msg.raw_bytes);
        }
        handshake_messages.extend(msgs);
    }

    // Trim transcript to exact handshake length
    handshake_transcript.truncate(
        handshake_transcript_len
            + handshake_messages
                .iter()
                .map(|m| m.raw_bytes.len())
                .sum::<usize>(),
    );

    // Parse required messages
    let server_hello_msg =
        find_handshake_message(&handshake_messages, HandshakeMessageType::ServerHello)?;
    let server_hello_parsed =
        crate::services::tls_parser::parse_server_hello_content(&server_hello_msg.raw_bytes[4..])?;

    let server_key_exchange_msg =
        find_handshake_message(&handshake_messages, HandshakeMessageType::ServerKeyExchange)?;
    let server_key_exchange = crate::services::tls_parser::parse_server_key_exchange_content(
        &server_key_exchange_msg.raw_bytes[4..],
    )?;

    let certificate_msg =
        find_handshake_message(&handshake_messages, HandshakeMessageType::Certificate)?;
    let certificates =
        crate::services::tls_parser::parse_certificate_list(&certificate_msg.raw_bytes[4..])?;

    Ok((
        handshake_messages,
        server_hello_parsed,
        server_key_exchange,
        certificates,
    ))
}

/// Finds a specific handshake message type in the received messages
fn find_handshake_message(
    messages: &[TlsHandshakeMessage],
    msg_type: HandshakeMessageType,
) -> Result<&TlsHandshakeMessage, TlsError> {
    messages
        .iter()
        .find(|m| m.msg_type == msg_type)
        .ok_or_else(|| {
            TlsError::HandshakeFailed(format!("{:?} not found in handshake messages", msg_type))
        })
}

/// Validates the server's chosen cipher suite
fn validate_cipher_suite(chosen_cipher_suite: &[u8; 2]) -> Result<CipherSuite, TlsError> {
    crate::services::tls_parser::get_cipher_suite_by_id(chosen_cipher_suite).ok_or_else(|| {
        TlsError::HandshakeFailed(format!(
            "Server chose unsupported cipher suite: {:02X}{:02X}",
            chosen_cipher_suite[0], chosen_cipher_suite[1]
        ))
    })
}

/// Performs ECDHE key exchange to derive the pre-master secret
fn perform_ecdhe_key_exchange(
    client_ephemeral_secret: &EphemeralSecret,
    server_public_key_bytes: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let server_ephemeral_point =
        EncodedPoint::from_bytes(server_public_key_bytes).map_err(|_| {
            TlsError::KeyDerivationError("Invalid server ephemeral public key format".to_string())
        })?;

    let server_public_key =
        PublicKey::from_sec1_bytes(server_ephemeral_point.as_bytes()).map_err(|e| {
            TlsError::KeyDerivationError(format!(
                "Failed to create PublicKey from encoded point: {:?}",
                e
            ))
        })?;

    let shared_secret = client_ephemeral_secret.diffie_hellman(&server_public_key);
    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Derives TLS 1.2 encryption keys and ciphers from the key block
fn derive_tls12_keys(
    cipher_suite: &CipherSuite,
    key_block: &[u8],
) -> Result<
    (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        TlsAeadCipher,
        TlsAeadCipher,
    ),
    TlsError,
> {
    let (client_cipher, client_iv, server_cipher, server_iv) =
        keys::derive_aead_keys(cipher_suite, key_block)?;

    // Extract raw keys from the key block using correct TLS 1.2 AEAD layout
    let key_len = cipher_suite.key_length as usize;
    let _iv_len = cipher_suite.fixed_iv_length as usize;

    // TLS 1.2 AEAD key block layout: client_key | server_key | client_iv | server_iv
    let client_key = key_block[0..key_len].to_vec();
    let server_key = key_block[key_len..key_len * 2].to_vec();
    // IVs are already extracted correctly by derive_aead_keys()

    Ok((
        client_key,
        server_key,
        client_iv,
        server_iv,
        client_cipher,
        server_cipher,
    ))
}

/// Completes the client-side handshake by sending ClientKeyExchange, ChangeCipherSpec, and Finished
fn complete_client_handshake(
    stream: &mut TcpStream,
    handshake_transcript: &mut Vec<u8>,
    master_secret: &[u8],
    client_cipher: &TlsAeadCipher,
    client_fixed_iv: &[u8],
    client_ephemeral_public_bytes: &[u8],
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Result<(), TlsError> {
    // Send ClientKeyExchange
    let (client_key_exchange_record, raw_client_key_exchange_handshake) =
        HandshakeMessage::create_client_key_exchange(client_ephemeral_public_bytes)?;
    stream.write_all(&client_key_exchange_record)?;
    handshake_transcript.extend_from_slice(&raw_client_key_exchange_handshake);

    // Send ChangeCipherSpec
    let change_cipher_spec_record = HandshakeMessage::create_change_cipher_spec();
    stream.write_all(&change_cipher_spec_record)?;

    // Send encrypted Finished message
    let (client_verify_data, _) = keys::calculate_verify_data_with_hash(
        master_secret,
        handshake_transcript,
        b"client finished",
        hash_algorithm,
    )?;

    let mut finished_message_plaintext = Vec::new();
    finished_message_plaintext.push(HandshakeMessageType::Finished as u8);
    finished_message_plaintext.extend_from_slice(&(12u32.to_be_bytes()[1..]));
    finished_message_plaintext.extend_from_slice(&client_verify_data);

    let encrypted_finished_payload = keys::encrypt_gcm_message(
        &finished_message_plaintext,
        client_cipher,
        client_fixed_iv,
        0, // client sequence number starts at 0
        TlsContentType::Handshake,
        TlsVersion::TLS1_2,
    )?;

    let finished_record = build_tls12_gcm_record_with_explicit_nonce(
        TlsContentType::Handshake,
        TlsVersion::TLS1_2,
        &encrypted_finished_payload,
        0, // sequence number
    );
    stream.write_all(&finished_record)?;

    handshake_transcript.extend_from_slice(&finished_message_plaintext);
    Ok(())
}

/// Verifies the server's encrypted Finished message
fn verify_server_finished(
    stream: &mut TcpStream,
    handshake_transcript: &[u8],
    master_secret: &[u8],
    server_cipher: &TlsAeadCipher,
    server_fixed_iv: &[u8],
    tls_version: TlsVersion,
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Result<(), TlsError> {
    // Read server ChangeCipherSpec
    let server_ccs_record = messages::read_tls_record(stream, tls_version)?;
    if server_ccs_record.content_type != TlsContentType::ChangeCipherSpec {
        return Err(TlsError::HandshakeFailed(format!(
            "Expected Server ChangeCipherSpec, got {:?}",
            server_ccs_record.content_type
        )));
    }

    // Read and decrypt server Finished message
    let record = messages::read_tls_record(stream, tls_version)?;
    if record.payload.len() < 8 + 16 {
        return Err(TlsError::EncryptionError(
            "Server Finished record too short".into(),
        ));
    }

    let explicit_nonce = &record.payload[0..8];
    let ciphertext = &record.payload[8..];

    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(server_fixed_iv);
    nonce[4..].copy_from_slice(explicit_nonce);

    let plaintext_length = ciphertext.len() - 16;
    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&0u64.to_be_bytes()); // server sequence number starts at 0
    aad.push(TlsContentType::Handshake as u8);
    let (major, minor) = tls_version.to_u8_pair();
    aad.push(major);
    aad.push(minor);
    aad.extend_from_slice(&(plaintext_length as u16).to_be_bytes());

    // Decrypt the finished message
    let plaintext = match server_cipher {
        TlsAeadCipher::Aes128Gcm(cipher) => {
            use aes_gcm::aead::{Aead, Payload};
            cipher.decrypt(
                &nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
        }
        TlsAeadCipher::Aes256Gcm(cipher) => {
            use aes_gcm::aead::{Aead, Payload};
            cipher.decrypt(
                &nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
        }
    }
    .map_err(|e| TlsError::EncryptionError(format!("AES-GCM decryption failed: {:?}", e)))?;

    // Verify the finished message content
    verify_finished_message_content(
        &plaintext,
        handshake_transcript,
        master_secret,
        hash_algorithm,
    )?;

    Ok(())
}

/// Verifies the content of a decrypted Finished message
fn verify_finished_message_content(
    plaintext: &[u8],
    handshake_transcript: &[u8],
    master_secret: &[u8],
    hash_algorithm: crate::services::tls_parser::HashAlgorithm,
) -> Result<(), TlsError> {
    if plaintext.len() < 4 + 12 {
        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
            "Server Finished payload too short".to_string(),
        )));
    }

    if plaintext[0] != HandshakeMessageType::Finished as u8 {
        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
            "Decrypted payload is not Finished message".to_string(),
        )));
    }

    let message_length = u32::from_be_bytes([0, plaintext[1], plaintext[2], plaintext[3]]) as usize;
    let server_verify_data_received = &plaintext[4..4 + message_length];

    let (expected_verify_data, _) = keys::calculate_verify_data_with_hash(
        master_secret,
        handshake_transcript,
        b"server finished",
        hash_algorithm,
    )?;

    if server_verify_data_received != expected_verify_data {
        return Err(TlsError::HandshakeFailed(
            "Server Finished verify_data mismatch".into(),
        ));
    }

    Ok(())
}

/// Builds a TLS 1.2 GCM record with explicit nonce
fn build_tls12_gcm_record_with_explicit_nonce(
    content_type: TlsContentType,
    tls_version: TlsVersion,
    ciphertext_with_tag: &[u8],
    sequence_number: u64,
) -> Vec<u8> {
    // Create payload: [ExplicitNonce (8 bytes) | Ciphertext + AuthTag]
    let mut payload = Vec::with_capacity(8 + ciphertext_with_tag.len());
    payload.extend_from_slice(&sequence_number.to_be_bytes());
    payload.extend_from_slice(ciphertext_with_tag);

    // Build TLS record: [ContentType | VersionMajor | VersionMinor | Length | Payload]
    let mut record = Vec::new();
    record.push(content_type.as_u8());
    let (major, minor) = tls_version.to_u8_pair();
    record.push(major);
    record.push(minor);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(&payload);
    record
}

/// Reads a single TLS record from a TCP stream
pub fn read_tls_record<R: Read>(
    reader: &mut R,
    _tls_version: TlsVersion,
) -> Result<TlsRecord, TlsError> {
    use std::io::{self, ErrorKind};

    // Read 5-byte TLS record header
    let mut header = [0u8; 5];
    let mut bytes_read = 0;

    while bytes_read < 5 {
        match reader.read(&mut header[bytes_read..]) {
            Ok(0) => {
                return Err(TlsError::IoError(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "Failed to read full TLS record header",
                )));
            }
            Ok(n) => bytes_read += n,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(TlsError::IoError(e)),
        }
    }

    // Parse header
    let content_type = header[0];
    let version = (header[1], header[2]);
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;

    // Validate record length
    if length > 16384 {
        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
            format!("TLS record length {} exceeds max allowed (16384)", length),
        )));
    }

    // Read payload
    let mut payload = vec![0u8; length];
    bytes_read = 0;

    while bytes_read < length {
        match reader.read(&mut payload[bytes_read..]) {
            Ok(0) => {
                return Err(TlsError::IoError(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "Failed to read full TLS record payload",
                )));
            }
            Ok(n) => bytes_read += n,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(TlsError::IoError(e)),
        }
    }

    Ok(TlsRecord {
        content_type: TlsContentType::from(content_type),
        version_major: version.0,
        version_minor: version.1,
        length: length as u16,
        payload,
    })
}
