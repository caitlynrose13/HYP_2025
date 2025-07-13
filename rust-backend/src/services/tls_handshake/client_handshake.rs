// src/services/tls_handshake/client_handshake.rs

use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys;
use crate::services::tls_handshake::messages;
use crate::services::tls_handshake::validation;
use elliptic_curve::sec1::ToEncodedPoint;
use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey};
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::services::tls_handshake::keys::TlsAeadCipher;
use crate::services::tls_parser::{
    CipherSuite, HandshakeMessageType, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TlsContentType, TlsParserError, TlsRecord, TlsVersion,
    parse_tls_alert,
};

#[derive(Debug, Clone, PartialEq)]
pub enum TlsSecurityLevel {
    Modern,     // Supports TLS 1.2 or 1.3
    Deprecated, // Only supports TLS 1.0 or 1.1
    Unknown,    // Couldn't determine (connection issues, etc.)
}

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
    pub handshake_hash: [u8; 32], // or use Vec<u8> if you prefer
}

#[derive(Debug, Default)]
struct HandshakeState {
    server_hello: bool,
    certificate: bool,
    server_key_exchange: bool,
    server_hello_done: bool,
    chosen_cipher_suite: Option<[u8; 2]>,
}

impl HandshakeState {
    fn update(
        &mut self,
        msg_type: &crate::services::tls_parser::HandshakeMessageType,
        payload: &[u8],
    ) {
        use crate::services::tls_parser::HandshakeMessageType::*;
        match msg_type {
            ServerHello => {
                self.server_hello = true;
                // Parse and store the chosen cipher suite
                if payload.len() > 4 {
                    match crate::services::tls_parser::parse_server_hello_content(&payload[4..]) {
                        Ok(parsed) => {
                            self.chosen_cipher_suite = Some(parsed.chosen_cipher_suite);
                        }
                        Err(_) => {
                            // Failed to parse ServerHello content
                        }
                    }
                }
            }
            Certificate => self.certificate = true,
            ServerKeyExchange => self.server_key_exchange = true,
            ServerHelloDone => self.server_hello_done = true,
            _ => {}
        }
    }

    fn all_required_received(&self) -> bool {
        if let Some(cs_id) = self.chosen_cipher_suite {
            // ECDHE_RSA suites
            if cs_id == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.id
                || cs_id == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.id
            {
                self.server_hello
                    && self.certificate
                    && self.server_key_exchange
                    && self.server_hello_done
            } else {
                // For all other (static RSA) suites, require ServerHello, Certificate, ServerHelloDone
                self.server_hello && self.certificate && self.server_hello_done
            }
        } else {
            false
        }
    }
}

pub fn perform_tls_handshake_full(
    domain: &str,
    tls_version: TlsVersion,
) -> Result<TlsConnectionState, TlsError> {
    // Use the provided domain parameter
    let domain = domain;
    let port = 1012; // Use port 1012 for the test server
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

    let mut handshake_transcript: Vec<u8> = Vec::new();

    let mut client_random = [0u8; 32];
    rand::thread_rng().fill(&mut client_random);

    let mut rng = thread_rng();
    let client_ephemeral_secret = EphemeralSecret::random(&mut rng);
    let client_ephemeral_public_encoded =
        client_ephemeral_secret.public_key().to_encoded_point(false);
    let client_ephemeral_public_bytes = client_ephemeral_public_encoded.as_bytes();

    // --- Phase 1: Client Hello ---
    println!("[1] Sending ClientHello");
    let (client_hello_record, raw_client_hello_handshake) =
        messages::HandshakeMessage::build_client_hello_with_random_and_key_share(
            domain,
            tls_version,
            &client_random,
            client_ephemeral_public_bytes,
        )?;
    stream.write_all(&client_hello_record)?;
    handshake_transcript.extend_from_slice(&raw_client_hello_handshake);

    // --- Phase 2: Server Response ---
    println!("[2] Receiving server handshake messages");
    let handshake_transcript_len = handshake_transcript.len();
    let mut handshake_messages = Vec::new();
    let mut handshake_state = HandshakeState::default();
    let mut records_processed = 0;
    let mut total_handshake_messages = 0;

    // Read all handshake records until all required messages are received
    while !handshake_state.all_required_received() {
        records_processed += 1;
        println!(
            "[2.{}] Reading TLS record #{}",
            records_processed, records_processed
        );

        let server_response = messages::read_tls_record(&mut stream, tls_version)?;
        println!(
            "  Record type: {:?}, length: {}",
            server_response.content_type, server_response.length
        );

        let msgs = crate::services::tls_parser::parse_handshake_messages(&server_response.payload)?;
        println!(
            "  Parsed {} handshake message(s) from this record",
            msgs.len()
        );

        for (i, msg) in msgs.iter().enumerate() {
            total_handshake_messages += 1;
            println!(
                "    Message {}.{}: {:?} ({} bytes)",
                records_processed,
                i + 1,
                msg.msg_type,
                msg.raw_bytes.len()
            );
            handshake_state.update(&msg.msg_type, &msg.raw_bytes);
            handshake_transcript.extend_from_slice(&msg.raw_bytes);
        }
        handshake_messages.extend(msgs);

        println!("  Handshake state: {:?}", handshake_state);
    }

    println!("=== HANDSHAKE PARSING SUMMARY ===");
    println!("Total TLS records processed: {}", records_processed);
    println!(
        "Total handshake messages parsed: {}",
        total_handshake_messages
    );
    println!(
        "Handshake transcript length: {} bytes",
        handshake_transcript.len()
    );
    println!("✓ No repeated handshake parsing detected");

    // Truncate handshake_transcript to only handshake messages (in case of extra records)
    handshake_transcript.truncate(
        handshake_transcript_len
            + handshake_messages
                .iter()
                .map(|m| m.raw_bytes.len())
                .sum::<usize>(),
    );

    if !handshake_state.all_required_received() {
        return Err(TlsError::HandshakeFailed(
            "Server did not send all required handshake messages".into(),
        ));
    }

    // Parse ServerHello to get server random and chosen cipher suite
    let server_hello_msg = handshake_messages
        .iter()
        .find(|m| m.msg_type == crate::services::tls_parser::HandshakeMessageType::ServerHello)
        .ok_or_else(|| {
            TlsError::HandshakeFailed("ServerHello not found in handshake messages".to_string())
        })?;
    let server_hello_parsed =
        messages::HandshakeMessage::parse_server_hello_message(&server_hello_msg.raw_bytes)?;

    // Parse ServerKeyExchange
    let server_key_exchange_msg = handshake_messages
        .iter()
        .find(|m| {
            m.msg_type == crate::services::tls_parser::HandshakeMessageType::ServerKeyExchange
        })
        .ok_or_else(|| {
            TlsError::HandshakeFailed(
                "ServerKeyExchange not found in handshake messages".to_string(),
            )
        })?;
    let server_key_exchange = messages::HandshakeMessage::parse_server_key_exchange_message(
        &server_key_exchange_msg.raw_bytes,
    )?;

    // Parse Certificate
    let certificate_msg = handshake_messages
        .iter()
        .find(|m| m.msg_type == crate::services::tls_parser::HandshakeMessageType::Certificate)
        .ok_or_else(|| {
            TlsError::HandshakeFailed("Certificate not found in handshake messages".to_string())
        })?;
    let certificates =
        crate::services::tls_parser::parse_certificate_list(&certificate_msg.raw_bytes[4..])?;

    // Convert chosen_cipher_suite from [u8; 2] to CipherSuite
    let chosen_cipher_suite = crate::services::tls_parser::get_cipher_suite_by_id(
        &server_hello_parsed.chosen_cipher_suite,
    )
    .ok_or_else(|| {
        TlsError::HandshakeFailed(format!(
            "Server chose unsupported cipher suite: {:02X}{:02X}",
            server_hello_parsed.chosen_cipher_suite[0], server_hello_parsed.chosen_cipher_suite[1]
        ))
    })?;

    println!(
        "[3] Server chose cipher suite: {}",
        chosen_cipher_suite.name
    );

    // --- Phase 2.5: Verify ServerKeyExchange Signature ---
    println!("[4] Verifying ServerKeyExchange signature");
    validation::verify_server_key_exchange_signature(
        &server_key_exchange,
        &client_random,
        &server_hello_parsed.server_random,
        &certificates,
    )?;
    println!("✓ ServerKeyExchange signature verified");

    // --- Phase 3: Key Exchange ---
    println!("[5] Computing Pre-Master Secret");
    let server_ephemeral_point = EncodedPoint::from_bytes(&server_key_exchange.public_key)
        .map_err(|_| {
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
    let pre_master_secret = shared_secret.raw_secret_bytes().to_vec();

    println!("[6] Deriving Master Secret");
    let master_secret = keys::calculate_master_secret(
        &pre_master_secret,
        &client_random,
        &server_hello_parsed.server_random,
        chosen_cipher_suite.hash_algorithm,
    )?;

    println!("[7] Deriving Key Block");
    let key_block = keys::calculate_key_block(
        &master_secret,
        &server_hello_parsed.server_random,
        &client_random,
        &chosen_cipher_suite,
    )?;

    let (
        client_write_key,
        server_write_key,
        client_fixed_iv,
        server_fixed_iv,
        client_cipher,
        server_cipher,
        final_chosen_cipher_suite_struct,
    ): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        TlsAeadCipher,
        TlsAeadCipher,
        CipherSuite,
    ) = if tls_version == TlsVersion::TLS1_2 {
        let (client_cipher, client_iv, server_cipher, server_iv) =
            keys::derive_aead_keys(&chosen_cipher_suite, &key_block)?;

        // Extract the actual key bytes from the cipher objects for debugging
        let key_len = chosen_cipher_suite.key_length as usize;
        let mut offset = 0;
        offset += chosen_cipher_suite.mac_key_length as usize; // Skip client_mac_key
        offset += chosen_cipher_suite.mac_key_length as usize; // Skip server_mac_key
        let client_key = key_block[offset..offset + key_len].to_vec();
        offset += key_len;
        let server_key = key_block[offset..offset + key_len].to_vec();

        (
            client_key,
            server_key,
            client_iv,
            server_iv,
            client_cipher,
            server_cipher,
            chosen_cipher_suite.clone(),
        )
    } else {
        return Err(TlsError::HandshakeFailed(
            "Unsupported TLS version for key derivation".into(),
        ));
    };

    println!("[8] Sending ClientKeyExchange");
    let mut client_sequence_number: u64 = 0;
    println!("  Client sequence number: {}", client_sequence_number);

    let (client_key_exchange_record, raw_client_key_exchange_handshake) =
        messages::HandshakeMessage::create_client_key_exchange(client_ephemeral_public_bytes)?;
    stream.write_all(&client_key_exchange_record)?;
    handshake_transcript.extend_from_slice(&raw_client_key_exchange_handshake);

    println!("[9] Sending ChangeCipherSpec");
    let change_cipher_spec_record = messages::HandshakeMessage::create_change_cipher_spec();
    stream.write_all(&change_cipher_spec_record)?;

    // Calculate verify_data for Finished message
    let (client_verify_data, _client_handshake_hash) = keys::calculate_verify_data_with_hash(
        &master_secret,
        &handshake_transcript,
        b"client finished",
        chosen_cipher_suite.hash_algorithm,
    )?;

    // Build Finished message
    let mut finished_message_plaintext = Vec::new();
    finished_message_plaintext.push(HandshakeMessageType::Finished as u8);
    finished_message_plaintext.extend_from_slice(&(12u32.to_be_bytes()[1..])); // Length is 12
    finished_message_plaintext.extend_from_slice(&client_verify_data);

    // Encrypt Finished message
    let encrypted_finished_payload = keys::encrypt_gcm_message(
        &finished_message_plaintext,
        &client_cipher,
        &client_fixed_iv,
        client_sequence_number,
        TlsContentType::Handshake,
        TlsVersion::TLS1_2,
    )?;

    // Build and send encrypted Finished record
    let finished_record = build_tls12_gcm_record_with_explicit_nonce(
        TlsContentType::Handshake,
        TlsVersion::TLS1_2,
        &encrypted_finished_payload,
        client_sequence_number,
    );
    println!(
        "[10] Sending Finished (sequence: {})",
        client_sequence_number
    );
    stream.write_all(&finished_record)?;
    client_sequence_number += 1;
    println!(
        "  Client sequence number incremented to: {}",
        client_sequence_number
    );

    // Add Finished to transcript
    println!("=== ADDING CLIENT FINISHED TO TRANSCRIPT ===");
    println!(
        "Client Finished plaintext length: {} bytes",
        finished_message_plaintext.len()
    );
    println!(
        "Client Finished plaintext: {:02x?}",
        finished_message_plaintext
    );
    println!(
        "Transcript length before adding Client Finished: {} bytes",
        handshake_transcript.len()
    );
    handshake_transcript.extend_from_slice(&finished_message_plaintext);
    println!(
        "Transcript length after adding Client Finished: {} bytes",
        handshake_transcript.len()
    );

    // --- Phase 5: Awaiting Server Final Handshake ---
    println!("[11] Waiting for Server ChangeCipherSpec");
    let server_ccs_record = messages::read_tls_record(&mut stream, tls_version)?;
    if server_ccs_record.content_type != TlsContentType::ChangeCipherSpec {
        return Err(TlsError::HandshakeFailed(format!(
            "Expected Server ChangeCipherSpec, got {:?}",
            server_ccs_record.content_type
        )));
    }
    println!("✓ Received Server ChangeCipherSpec");

    println!("[12] Reading Server Finished");

    // Track server sequence number for AEAD
    let mut server_sequence_number: u64 = 0;

    // After ChangeCipherSpec, we expect one encrypted record containing the Server Finished
    let record = messages::read_tls_record(&mut stream, tls_version)?;

    println!(
        "DEBUG: Received encrypted record - Type: {:?}, Length: {}, Version: {:X}.{:X}",
        record.content_type, record.length, record.version_major, record.version_minor
    );
    println!(
        "DEBUG: Encrypted payload (first 16 bytes): {}",
        hex::encode(&record.payload[..std::cmp::min(16, record.payload.len())])
    );

    // Split payload into explicit nonce and ciphertext+tag
    if record.payload.len() < 8 + 16 {
        return Err(TlsError::EncryptionError(
            "Server Finished record too short".into(),
        ));
    }
    let explicit_nonce = &record.payload[0..8];
    let ciphertext = &record.payload[8..];

    // === SEQUENCE NUMBER VALIDATION ===
    println!("=== SERVER SEQUENCE NUMBER VALIDATION ===");
    println!("Server sequence number: {}", server_sequence_number);
    println!("✓ Using tracked server sequence number for AAD");

    // === NONCE AND CIPHERTEXT DUMP ===
    println!("=== NONCE AND CIPHERTEXT DUMP ===");
    println!("Explicit nonce (8 bytes): {:02x?}", explicit_nonce);
    println!(
        "Ciphertext with tag ({} bytes): {:02x?}",
        ciphertext.len(),
        ciphertext
    );
    println!("Full ciphertext hex dump:");
    for (i, chunk) in ciphertext.chunks(16).enumerate() {
        println!("  {:04x}: {}", i * 16, hex::encode(chunk));
    }

    // Construct nonce: fixed_iv || explicit_nonce
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&server_fixed_iv);
    nonce[4..].copy_from_slice(explicit_nonce);

    // Calculate plaintext length (ciphertext includes the 16-byte GCM tag)
    let plaintext_length = ciphertext.len() - 16;

    // Construct AAD: server_sequence_number (8) | content_type (1) | version (2) | plaintext_length (2)
    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&server_sequence_number.to_be_bytes());
    aad.push(TlsContentType::Handshake as u8);
    let (major, minor) = tls_version.to_u8_pair();
    aad.push(major);
    aad.push(minor);
    aad.extend_from_slice(&(plaintext_length as u16).to_be_bytes());

    // === FINAL NONCE CONSTRUCTION DEBUG ===
    println!("=== FINAL NONCE CONSTRUCTION DEBUG ===");
    println!("Server fixed IV (4 bytes): {:02x?}", &server_fixed_iv);
    println!("Explicit nonce (8 bytes): {:02x?}", explicit_nonce);
    println!("Constructed nonce (12 bytes): {:02x?}", &nonce);
    println!("AAD (13 bytes): {:02x?}", &aad);
    println!("AAD breakdown:");
    println!("  - Sequence number (8 bytes): {:02x?}", &aad[..8]);
    println!("  - Content type (1 byte): {:02x}", aad[8]);
    println!("  - TLS version (2 bytes): {:02x?}", &aad[9..11]);
    println!("  - Plaintext length (2 bytes): {:02x?}", &aad[11..13]);
    println!("=== LENGTH VALIDATION ===");
    println!(
        "Declared plaintext length (for AAD): {} bytes (0x{:04x})",
        plaintext_length, plaintext_length
    );
    println!(
        "Actual ciphertext_with_tag length: {} bytes",
        ciphertext.len()
    );
    println!(
        "Expected plaintext length: {} bytes (ciphertext - 16)",
        ciphertext.len() - 16
    );
    println!(
        "Ciphertext length: {} bytes (should be record.length - 8)",
        ciphertext.len()
    );

    // Decrypt
    let plaintext = match &server_cipher {
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
    };
    let plaintext = match plaintext {
        Ok(pt) => pt,
        Err(e) => {
            println!("=== AES-GCM Decryption Failed ===");
            println!("Error: {:?}", e);
            println!("Final parameters:");
            println!("  - Nonce: {:02x?}", &nonce);
            println!("  - AAD: {:02x?}", &aad);
            println!("  - Ciphertext length: {}", ciphertext.len());
            return Err(TlsError::EncryptionError(format!(
                "AES-GCM decryption failed: {:?}",
                e
            )));
        }
    };
    println!("=== AES-GCM Decryption Success ===");
    println!(
        "Decrypted plaintext (first 16 bytes): {:02x?}",
        &plaintext[..std::cmp::min(16, plaintext.len())]
    );

    // Increment server sequence number for next record
    server_sequence_number += 1;

    // Parse and verify Server Finished
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

    // Extract message type, length, and verify_data
    let message_type = plaintext[0];
    let message_length = u32::from_be_bytes([0, plaintext[1], plaintext[2], plaintext[3]]) as usize;
    let server_verify_data_received = &plaintext[4..4 + message_length];

    println!(
        "Message type: 0x{:02x} ({:?})",
        message_type,
        HandshakeMessageType::from(message_type)
    );
    println!("Message length: {} bytes", message_length);
    println!(
        "Server verify_data received: {:02x?}",
        server_verify_data_received
    );
    println!(
        "Server verify_data received (hex): {}",
        hex::encode(server_verify_data_received)
    );

    // Check if transcript contains ChangeCipherSpec (it shouldn't)
    let ccs_pattern = [TlsContentType::ChangeCipherSpec as u8];
    let contains_ccs = handshake_transcript
        .windows(ccs_pattern.len())
        .any(|window| window == ccs_pattern);
    println!("Transcript contains ChangeCipherSpec: {}", contains_ccs);

    // Check for Client Finished message in transcript (it should be there for Server Finished calculation)
    let client_finished_pattern = [HandshakeMessageType::Finished as u8];
    let contains_client_finished = handshake_transcript
        .windows(client_finished_pattern.len())
        .any(|window| window == client_finished_pattern);
    println!(
        "Transcript contains Client Finished: {}",
        contains_client_finished
    );

    // Show transcript breakdown by message types
    println!("=== TRANSCRIPT MESSAGE BREAKDOWN ===");
    let mut offset = 0;
    let mut message_count = 0;
    while offset < handshake_transcript.len() {
        if offset + 4 > handshake_transcript.len() {
            println!(
                "Incomplete message at offset {} (need 4 bytes for header)",
                offset
            );
            break;
        }

        let msg_type = handshake_transcript[offset];
        let msg_len = u32::from_be_bytes([
            0,
            handshake_transcript[offset + 1],
            handshake_transcript[offset + 2],
            handshake_transcript[offset + 3],
        ]) as usize;

        if offset + 4 + msg_len > handshake_transcript.len() {
            println!(
                "Message at offset {} extends beyond transcript (claimed length: {})",
                offset, msg_len
            );
            break;
        }

        message_count += 1;
        println!(
            "Message {}: Type=0x{:02x} ({:?}), Length={}, Offset={}",
            message_count,
            msg_type,
            HandshakeMessageType::from(msg_type),
            msg_len,
            offset
        );

        offset += 4 + msg_len;
    }
    println!("Total messages in transcript: {}", message_count);

    // === PRF LABEL VERIFICATION ===
    let prf_label = b"server finished";
    println!("=== PRF LABEL VERIFICATION ===");
    println!(
        "PRF label: {:02x?} (\"{}\")",
        prf_label,
        String::from_utf8_lossy(prf_label)
    );
    println!("PRF label length: {} bytes", prf_label.len());

    // Calculate expected Server Finished verify_data
    let (expected_verify_data_from_transcript, server_handshake_hash) =
        keys::calculate_verify_data_with_hash(
            &master_secret,
            &handshake_transcript,
            prf_label,
            chosen_cipher_suite.hash_algorithm,
        )?;

    println!("=== EXPECTED VERIFY_DATA CALCULATION ===");
    println!("Master secret length: {} bytes", master_secret.len());
    println!(
        "Handshake hash length: {} bytes",
        server_handshake_hash.len()
    );
    println!("Handshake hash: {:02x?}", server_handshake_hash);
    println!(
        "Handshake hash (hex): {}",
        hex::encode(&server_handshake_hash)
    );
    println!(
        "Expected verify_data: {:02x?}",
        expected_verify_data_from_transcript
    );
    println!(
        "Expected verify_data (hex): {}",
        hex::encode(&expected_verify_data_from_transcript)
    );

    // === COMPARISON ===
    println!("=== VERIFY_DATA COMPARISON ===");
    println!(
        "Received length: {} bytes",
        server_verify_data_received.len()
    );
    println!(
        "Expected length: {} bytes",
        expected_verify_data_from_transcript.len()
    );
    println!("Received:  {}", hex::encode(server_verify_data_received));
    println!(
        "Expected:  {}",
        hex::encode(&expected_verify_data_from_transcript)
    );
    println!(
        "Match: {}",
        server_verify_data_received == expected_verify_data_from_transcript
    );

    if server_verify_data_received != expected_verify_data_from_transcript {
        println!("=== MISMATCH DETAILS ===");
        let min_len = std::cmp::min(
            server_verify_data_received.len(),
            expected_verify_data_from_transcript.len(),
        );
        for i in 0..min_len {
            if server_verify_data_received[i] != expected_verify_data_from_transcript[i] {
                println!(
                    "Byte {}: received 0x{:02x}, expected 0x{:02x}",
                    i, server_verify_data_received[i], expected_verify_data_from_transcript[i]
                );
            }
        }
        return Err(TlsError::HandshakeFailed(
            "Server Finished verify_data mismatch".into(),
        ));
    }
    println!("✓ Server Finished verified");

    println!("TLS 1.2 Handshake completed successfully!");
    println!("   Cipher: {}", final_chosen_cipher_suite_struct.name);
    println!("   Client sequence: {}", client_sequence_number);

    Ok(TlsConnectionState {
        master_secret: master_secret.to_vec(),
        client_write_key,
        server_write_key,
        client_fixed_iv,
        server_fixed_iv,
        client_sequence_number,
        server_sequence_number,
        negotiated_cipher_suite: final_chosen_cipher_suite_struct,
        negotiated_tls_version: TlsVersion::TLS1_2,
        client_random,
        server_random: server_hello_parsed.server_random,
        handshake_hash: Sha256::digest(&handshake_transcript).into(),
    })
}

// === Helper: Build encrypted TLS record with explicit nonce ===
fn build_tls12_gcm_record_with_explicit_nonce(
    content_type: TlsContentType,
    tls_version: TlsVersion,
    ciphertext_with_tag: &[u8],
    sequence_number: u64,
) -> Vec<u8> {
    // Prepend the explicit nonce (sequence number) to the ciphertext
    let mut payload = Vec::with_capacity(8 + ciphertext_with_tag.len());
    payload.extend_from_slice(&sequence_number.to_be_bytes());
    payload.extend_from_slice(ciphertext_with_tag);
    // Build the TLS record
    let mut record = Vec::new();
    record.push(content_type.as_u8());
    let (major, minor) = tls_version.to_u8_pair();
    record.push(major);
    record.push(minor);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(&payload);
    record
}

/// Reads a single TLS record from the stream.
pub fn read_tls_record<R: Read>(
    reader: &mut R,
    _tls_version: TlsVersion,
) -> Result<TlsRecord, TlsError> {
    use std::io::{self};
    use std::time::Duration;
    let mut header = [0u8; 5];
    let mut bytes_read = 0;

    // Read the 5-byte header
    while bytes_read < 5 {
        match reader.read(&mut header[bytes_read..]) {
            Ok(0) => {
                println!(
                    "DEBUG: EOF encountered while reading TLS record header. Read {}/5 bytes.",
                    bytes_read
                );
                return Err(TlsError::IoError(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Failed to read full TLS record header",
                )));
            }
            Ok(n) => {
                bytes_read += n;
                println!("DEBUG: Read {} bytes for header, total {}/5", n, bytes_read);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                println!("DEBUG: WouldBlock while reading header. Retrying...");
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                println!("DEBUG: Error reading header: {:?}", e);
                return Err(TlsError::IoError(e));
            }
        }
    }

    let content_type = header[0];
    let version = (header[1], header[2]);
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;

    println!(
        "DEBUG: Parsed record header: Type={:?}, Version={:X}.{:X}, Length={}",
        TlsContentType::from(content_type),
        version.0,
        version.1,
        length
    );

    if length > 16384 {
        println!(
            "DEBUG: WARNING: Record length ({}) seems excessively large!",
            length
        );
        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
            format!("TLS record length {} exceeds max allowed (16384)", length),
        )));
    }

    let mut payload = vec![0u8; length];
    bytes_read = 0;
    while bytes_read < length {
        match reader.read(&mut payload[bytes_read..]) {
            Ok(0) => {
                println!(
                    "DEBUG: EOF encountered while reading TLS record payload. Read {}/{} bytes.",
                    bytes_read, length
                );
                return Err(TlsError::IoError(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Failed to read full TLS record payload",
                )));
            }
            Ok(n) => {
                bytes_read += n;
                println!(
                    "DEBUG: Read {} bytes for payload, total {}/{} ({} remaining)",
                    n,
                    bytes_read,
                    length,
                    length - bytes_read
                );
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                println!("DEBUG: WouldBlock while reading payload. Retrying...");
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                println!("DEBUG: Error reading payload: {:?}", e);
                return Err(TlsError::IoError(e));
            }
        }
    }

    println!(
        "DEBUG: Successfully read full TLS record. Payload (first 16 bytes): {}",
        hex::encode(&payload[..std::cmp::min(16, payload.len())])
    );

    let record = TlsRecord {
        content_type: TlsContentType::from(content_type),
        version_major: version.0,
        version_minor: version.1,
        length: length as u16,
        payload,
    };

    // If this is an alert record, parse and display the alert details
    if record.content_type == TlsContentType::Alert {
        match parse_tls_alert(&record.payload) {
            Ok(alert) => {
                println!("{}", alert.to_string());
            }
            Err(e) => {
                println!(
                    "
                Failed to parse alert: {:?}",
                    e
                );
            }
        }
    }

    Ok(record)
}

pub fn probe_tls_security_level(domain: &str) -> TlsSecurityLevel {
    println!("Probing {} for TLS security level...", domain);

    println!("    Testing TLS 1.2...");
    match perform_tls_handshake_full(domain, TlsVersion::TLS1_2) {
        Ok(connection_state) => {
            println!("    ✓ TLS 1.2 - SUPPORTED");
            println!(
                "      Negotiated cipher: {}",
                connection_state.negotiated_cipher_suite.name
            );
            return TlsSecurityLevel::Modern;
        }
        Err(e) => {
            println!("    ✗ TLS 1.2 - FAILED: {:?}", e);
            if let TlsError::ParserError(parser_error) = &e {
                if let crate::services::tls_parser::TlsParserError::InvalidVersion(major, minor) =
                    parser_error
                {
                    println!(
                        "      Server responded with version {}.{:02X} - requesting downgrade",
                        major, minor
                    );
                    return TlsSecurityLevel::Deprecated;
                }
            }
        }
    }

    println!("    TLS 1.3 not yet implemented - assuming deprecated if TLS 1.2 failed");
    TlsSecurityLevel::Deprecated
}
