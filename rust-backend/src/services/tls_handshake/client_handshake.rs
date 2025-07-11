// src/services/tls_handshake/client_handshake.rs

use crate::services::tls_handshake::keys;
use crate::services::tls_handshake::messages;
use crate::services::tls_handshake::validation;
use elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::services::tls_parser::TlsParserError;
use crate::services::tls_parser::{
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};
use crate::{
    services::errors::TlsError,
    services::tls_parser::TlsRecord,
    services::tls_parser::{self, CipherSuite, HandshakeMessageType, TlsContentType, TlsVersion},
};

type AeadCipherInstance = aes_gcm::AesGcm<aes::Aes128, typenum::U12, typenum::U16>;

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

#[derive(Default)]
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
                if let Ok(parsed) = crate::services::tls_parser::parse_server_hello_content(payload)
                {
                    self.chosen_cipher_suite = Some(parsed.chosen_cipher_suite);
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
    let addr_str = format!("{}:443", domain);
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

    // --- MODIFIED LINE ---
    let (client_hello_record, raw_client_hello_handshake) =
        messages::HandshakeMessage::build_client_hello_with_random_and_key_share(
            domain,
            tls_version,
            &client_random,
            client_ephemeral_public_bytes,
        )?;
    // Use the raw handshake message for the transcript
    handshake_transcript.extend_from_slice(&raw_client_hello_handshake);

    // Print Client Random (32 bytes, hex)
    println!("[DEBUG] Client Random: {}", hex::encode(&client_random));

    // Print ClientHello record and handshake message (hex)
    println!(
        "ClientHello record bytes: {}",
        hex::encode(&client_hello_record)
    );
    println!(
        "ClientHello handshake message for transcript: {}",
        hex::encode(&raw_client_hello_handshake)
    );

    stream.write_all(&client_hello_record)?; // Send the full record
    println!("Sent ClientHello ({} bytes)", client_hello_record.len());

    // Print transcript after ClientHello
    println!(
        "[DEBUG] Transcript after ClientHello: {}",
        hex::encode(&handshake_transcript)
    );

    // Server Hello Flight - Read and process records incrementally
    let mut server_response_buffer = Vec::new();
    let mut temp_buffer = [0; 4096];
    let mut handshake_messages_collected = Vec::new();
    let mut handshake_state = HandshakeState::default();
    let mut handshake_complete = false;

    while !handshake_complete {
        match stream.read(&mut temp_buffer) {
            Ok(0) => {
                println!("Server closed connection or EOF reached during handshake read.");
                break;
            }
            Ok(n) => {
                server_response_buffer.extend_from_slice(&temp_buffer[..n]);
                println!(
                    "Received {} bytes. Total received: {}",
                    n,
                    server_response_buffer.len()
                );
                let mut cursor = std::io::Cursor::new(server_response_buffer.as_slice());
                while let Ok(Some(record)) =
                    crate::services::tls_parser::parse_tls_record(&mut cursor)
                {
                    if record.content_type == crate::services::tls_parser::TlsContentType::Handshake
                    {
                        if let Ok(handshake_messages) =
                            crate::services::tls_parser::parse_handshake_messages(&record.payload)
                        {
                            for msg in handshake_messages {
                                handshake_state.update(&msg.msg_type, &msg.payload);
                                handshake_messages_collected.push(msg);
                            }
                        }
                    }
                }
                if handshake_state.all_required_received() {
                    handshake_complete = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                println!("Read WouldBlock, assuming no more data for now from handshake flight.");
                break;
            }
            Err(e) => return Err(TlsError::IoError(e)),
        }
    }

    if handshake_messages_collected.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "No handshake messages received from server.".to_string(),
        ));
    }

    // Extract required handshake messages from collected messages
    let mut server_hello_parsed: Option<tls_parser::ServerHelloParsed> = None;
    let mut certificates: Option<Vec<Vec<u8>>> = None;
    let mut server_key_exchange_parsed: Option<tls_parser::ServerKeyExchangeParsed> = None;
    let mut server_hello_done_found = false;

    for msg in &handshake_messages_collected {
        match msg.msg_type {
            HandshakeMessageType::ServerHello => {
                server_hello_parsed = Some(tls_parser::parse_server_hello_content(&msg.payload)?);
            }
            HandshakeMessageType::Certificate => {
                certificates = Some(tls_parser::parse_certificate_list(&msg.payload)?);
            }
            HandshakeMessageType::ServerKeyExchange => {
                server_key_exchange_parsed =
                    Some(tls_parser::parse_server_key_exchange_content(&msg.payload)?);
            }
            HandshakeMessageType::ServerHelloDone => {
                server_hello_done_found = true;
            }
            _ => {}
        }
    }

    let server_hello_parsed = server_hello_parsed.ok_or(TlsError::HandshakeFailed(
        "ServerHello not received".to_string(),
    ))?;
    let certificates = certificates.unwrap_or_else(|| Vec::new());
    if !server_hello_done_found {
        println!("Warning: ServerHelloDone not received, but continuing with handshake");
    }

    // Print Server Random (32 bytes, hex)
    println!(
        "[DEBUG] Server Random: {}",
        hex::encode(&server_hello_parsed.server_random)
    );

    // 1. Check negotiated TLS version
    if server_hello_parsed.negotiated_tls_version != (0x03, 0x03) {
        return Err(TlsError::HandshakeFailed(format!(
            "Server negotiated unsupported TLS version: {:X}.{:X}",
            server_hello_parsed.negotiated_tls_version.0,
            server_hello_parsed.negotiated_tls_version.1
        )));
    }

    // 2. Get chosen cipher suite struct
    let chosen_cipher_suite_struct_temp = tls_parser::get_cipher_suite_by_id(
        &server_hello_parsed.chosen_cipher_suite,
    )
    .ok_or_else(|| {
        TlsError::HandshakeFailed(format!(
            "Server chose unsupported cipher suite: {:02X}{:02X}",
            server_hello_parsed.chosen_cipher_suite[0], server_hello_parsed.chosen_cipher_suite[1]
        ))
    })?;

    let (
        master_secret,
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
        Vec<u8>,
        AeadCipherInstance,
        AeadCipherInstance,
        CipherSuite,
    ) = if tls_version == TlsVersion::TLS1_2 {
        let ske = server_key_exchange_parsed.ok_or_else(|| {
            TlsError::HandshakeFailed(
                "ServerKeyExchange expected but not received for TLS 1.2 ECDHE cipher suite."
                    .to_string(),
            )
        })?;

        println!("--- Phase 2.5: Verifying ServerKeyExchange Signature ---");
        validation::verify_server_key_exchange_signature(
            &ske,
            &client_random,
            &server_hello_parsed.server_random,
            &certificates,
        )?;
        println!("✓ ServerKeyExchange signature verified.");

        println!("--- Phase 3.1: Computing Pre-Master Secret ---");

        let server_ephemeral_point = EncodedPoint::from_bytes(&ske.public_key).map_err(|_| {
            TlsError::KeyDerivationError("Invalid server ephemeral public key format".to_string())
        })?;

        let server_public_key = PublicKey::from_sec1_bytes(server_ephemeral_point.as_bytes())
            .map_err(|e| {
                TlsError::KeyDerivationError(format!(
                    "Failed to create PublicKey from encoded point: {:?}",
                    e
                ))
            })?;

        let shared_secret = client_ephemeral_secret.diffie_hellman(&server_public_key);
        let pre_master_secret_val = shared_secret.raw_secret_bytes().to_vec();

        // Print Pre-Master Secret (hex)
        println!(
            "[DEBUG] Pre-Master Secret: {}",
            hex::encode(&pre_master_secret_val)
        );

        println!("--- Phase 3.2: Deriving Master Secret ---");
        let master_secret_val = keys::calculate_master_secret(
            &pre_master_secret_val,
            &client_random,
            &server_hello_parsed.server_random,
        )?
        .to_vec();
        // Print Master Secret (hex)
        println!("[DEBUG] Master Secret: {}", hex::encode(&master_secret_val));

        println!("--- Phase 3.3: Deriving Key Block ---");

        let key_block = keys::calculate_key_block(
            &master_secret_val,
            &server_hello_parsed.server_random,
            &client_random,
            chosen_cipher_suite_struct_temp,
        )?;
        // Print Key Block (hex)
        println!("Key Block derived (hex): {}", hex::encode(&key_block));

        // Debug print for cipher suite parameters
        println!(
            "CipherSuite: {} (id: {:02X}{:02X})",
            chosen_cipher_suite_struct_temp.name,
            chosen_cipher_suite_struct_temp.id[0],
            chosen_cipher_suite_struct_temp.id[1]
        );
        println!(
            "  mac_key_length: {}\n  key_length: {}\n  fixed_iv_length: {}",
            chosen_cipher_suite_struct_temp.mac_key_length,
            chosen_cipher_suite_struct_temp.key_length,
            chosen_cipher_suite_struct_temp.fixed_iv_length
        );

        let key_len = chosen_cipher_suite_struct_temp.key_length as usize;
        let fixed_iv_len = chosen_cipher_suite_struct_temp.fixed_iv_length as usize;
        let mac_key_len = chosen_cipher_suite_struct_temp.mac_key_length as usize;

        let mut current_offset = 0;

        let client_mac_key = &key_block[current_offset..(current_offset + mac_key_len)];
        current_offset += mac_key_len;
        let server_mac_key = &key_block[current_offset..(current_offset + mac_key_len)];
        current_offset += mac_key_len;

        let client_write_key_val = key_block[current_offset..(current_offset + key_len)].to_vec();
        // Print client/server write keys and IVs (hex)
        println!("client_write_key: {}", hex::encode(&client_write_key_val));
        current_offset += key_len;

        let server_write_key_val = key_block[current_offset..(current_offset + key_len)].to_vec();
        // Print client/server write keys and IVs (hex)
        println!("server_write_key: {}", hex::encode(&server_write_key_val));
        current_offset += key_len;

        let client_fixed_iv_val =
            key_block[current_offset..(current_offset + fixed_iv_len)].to_vec();
        // Print client/server write keys and IVs (hex)
        println!("client_fixed_iv: {}", hex::encode(&client_fixed_iv_val));
        current_offset += fixed_iv_len;

        let server_fixed_iv_val =
            key_block[current_offset..(current_offset + fixed_iv_len)].to_vec();
        // Print client/server write keys and IVs (hex)
        println!("server_fixed_iv: {}", hex::encode(&server_fixed_iv_val));

        // Print MAC keys for completeness (should be empty for AEAD)
        println!("  client_mac_key: {}", hex::encode(client_mac_key));
        println!("  server_mac_key: {}", hex::encode(server_mac_key));

        let (c_cipher, s_cipher) =
            keys::derive_aead_keys(chosen_cipher_suite_struct_temp, &key_block)?;

        println!("✓ Derived AEAD cipher instances from Key Block.");

        Ok::<
            (
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                AeadCipherInstance,
                AeadCipherInstance,
                CipherSuite,
            ),
            TlsError,
        >((
            master_secret_val,
            client_write_key_val,
            server_write_key_val,
            client_fixed_iv_val,
            server_fixed_iv_val,
            c_cipher,
            s_cipher,
            chosen_cipher_suite_struct_temp.clone(),
        ))
    } else if tls_version == TlsVersion::TLS1_3 {
        return Err(TlsError::HandshakeFailed(
            "TLS 1.3 key exchange not yet implemented.".to_string(),
        ));
    } else {
        return Err(TlsError::HandshakeFailed(
            "Unsupported TLS version or key exchange type.".to_string(),
        ));
    }?;

    // --- Phase 4: Client Sending Final Handshake ---
    println!("--- Phase 4: Client Sending Final Handshake ---");
    // Build and send ClientKeyExchange
    let (client_key_exchange_record, raw_client_key_exchange_handshake) =
        messages::HandshakeMessage::create_client_key_exchange(
            client_ephemeral_public_bytes,
            tls_version,
        )?;
    stream.write_all(&client_key_exchange_record)?; // Send the full record
    println!("Sent ClientKeyExchange.");

    // Add ClientKeyExchange to handshake transcript (the raw handshake message part)
    println!(
        "Adding ClientKeyExchange to handshake transcript: {}",
        hex::encode(&raw_client_key_exchange_handshake)
    );
    handshake_transcript.extend_from_slice(&raw_client_key_exchange_handshake);
    println!(
        "Handshake transcript length: {} bytes",
        handshake_transcript.len()
    );
    println!(
        "Handshake transcript (hex): {}",
        hex::encode(&handshake_transcript)
    );

    // Print transcript after ClientKeyExchange
    println!(
        "[DEBUG] Transcript after ClientKeyExchange: {}",
        hex::encode(&handshake_transcript)
    );

    // Prepare the Client Finished message payload (type + length + verify_data)
    // Calculate verify_data BEFORE adding Client Finished to transcript
    let (client_verify_data, client_handshake_hash) = keys::calculate_verify_data_with_hash(
        &master_secret,
        &handshake_transcript,
        b"client finished",
    )?;
    println!(
        "[DEBUG] Client Finished handshake_hash: {}",
        hex::encode(&client_handshake_hash)
    );
    println!(
        "✓ Computed Finished verify_data: {}",
        hex::encode(&client_verify_data)
    );

    let mut finished_message_plaintext = Vec::new();
    finished_message_plaintext.push(HandshakeMessageType::Finished as u8);
    // The length of verify_data is always 12 bytes for Finished
    finished_message_plaintext.extend_from_slice(&(12u32.to_be_bytes()[1..])); // Length is 12
    finished_message_plaintext.extend_from_slice(&client_verify_data);
    println!(
        "Finished message plaintext (hex): {}",
        hex::encode(&finished_message_plaintext)
    );

    // Add the *plaintext* Client Finished message (type + length + verify_data) to the transcript *before encryption*
    println!(
        "Adding Client Finished (plaintext) to handshake transcript: {}",
        hex::encode(&finished_message_plaintext)
    );
    handshake_transcript.extend_from_slice(&finished_message_plaintext);
    println!(
        "Handshake transcript length: {} bytes",
        handshake_transcript.len()
    );
    println!(
        "Handshake transcript (hex): {}",
        hex::encode(&handshake_transcript)
    );

    // Print transcript after Client Finished
    println!(
        "[DEBUG] Transcript after Client Finished: {}",
        hex::encode(&handshake_transcript)
    );

    let change_cipher_spec = messages::HandshakeMessage::create_change_cipher_spec();
    stream.write_all(&change_cipher_spec)?;
    println!("Sent ChangeCipherSpec.");

    let encrypted_finished_payload = keys::encrypt_gcm_message(
        &finished_message_plaintext,
        &client_cipher,
        &client_fixed_iv,
        0, // Client's sequence number starts at 0 for its first encrypted record
        TlsContentType::Handshake,
        tls_version,
    )?;
    println!(
        "✓ Encrypted Finished message payload generated ({} bytes).",
        encrypted_finished_payload.len()
    );

    let mut encrypted_finished_record = Vec::new();
    encrypted_finished_record.push(TlsContentType::Handshake.as_u8());
    let (major, minor) = tls_version.to_u8_pair();
    encrypted_finished_record.push(major);
    encrypted_finished_record.push(minor);
    encrypted_finished_record
        .extend_from_slice(&(encrypted_finished_payload.len() as u16).to_be_bytes());
    encrypted_finished_record.extend_from_slice(&encrypted_finished_payload);
    println!(
        "Encrypted Finished record (hex): {}",
        hex::encode(&encrypted_finished_record)
    );
    println!(
        "Encrypted Finished record length: {}",
        encrypted_finished_record.len()
    );
    stream.write_all(&encrypted_finished_record)?;
    stream.flush()?;
    println!(
        "Sent Encrypted Finished record ({} bytes).",
        encrypted_finished_record.len()
    );

    println!("--- Phase 5: Awaiting Server Final Handshake ---");
    let client_current_sequence_number = 1; // Client's first encrypted record was at 0, next is 1
    println!(
        "Waiting for Server ChangeCipherSpec... (expecting type 0x14, version 0x0303, length 0x0001, payload 0x01)"
    );
    let server_ccs_record = messages::read_tls_record(&mut stream, tls_version)?;
    println!(
        "Received Server CCS record (raw): Type={}, Version={:X}.{:X}, Length={}, Payload={}",
        server_ccs_record.content_type.as_u8(),
        server_ccs_record.version_major,
        server_ccs_record.version_minor,
        server_ccs_record.length,
        hex::encode(&server_ccs_record.payload)
    );
    if server_ccs_record.content_type != TlsContentType::ChangeCipherSpec
        || server_ccs_record.payload != [0x01]
        || (
            server_ccs_record.version_major,
            server_ccs_record.version_minor,
        ) != (0x03, 0x03)
    {
        return Err(TlsError::HandshakeFailed(
            format!(
                "Expected Server ChangeCipherSpec (0x14 0x0303 0x0001 0x01), got type {:?} ({:02X}) version {:X}.{:X} length {} and payload {:?}",
                server_ccs_record.content_type,
                server_ccs_record.content_type.as_u8(),
                server_ccs_record.version_major,
                server_ccs_record.version_minor,
                server_ccs_record.length,
                hex::encode(&server_ccs_record.payload)
            )
            .to_string(),
        ));
    }
    println!("✓ Received Server ChangeCipherSpec (unencrypted).");
    let mut server_current_sequence_number = 0u64;
    println!("Waiting for Server Finished record...");
    let server_finished_record = messages::read_tls_record(&mut stream, tls_version)?;
    println!(
        "Received Server Finished record (raw): Type={}, Version={:X}.{:X}, Length={}, Payload={}",
        server_finished_record.content_type.as_u8(),
        server_finished_record.version_major,
        server_finished_record.version_minor,
        server_finished_record.length,
        hex::encode(
            &server_finished_record.payload
                [..std::cmp::min(32, server_finished_record.payload.len())]
        )
    );
    if server_finished_record.content_type != TlsContentType::Handshake {
        return Err(TlsError::HandshakeFailed(
            format!(
                "Expected encrypted Server Finished (Handshake content type 0x16), got {:?} ({:02X})",
                server_finished_record.content_type,
                server_finished_record.content_type.as_u8()
            )
            .to_string(),
        ));
    }
    println!(
        "Received encrypted Server Finished record ({} bytes). Attempting to decrypt.",
        server_finished_record.payload.len()
    );

    // Decrypt the Finished message payload
    let decrypted_server_finished_payload = keys::decrypt_gcm_message(
        &server_finished_record.payload,
        &server_cipher,
        &server_fixed_iv,
        server_current_sequence_number, // Server's sequence number (starts at 0, increments for each record)
        TlsContentType::Handshake,
        tls_version,
    )?;
    server_current_sequence_number += 1; // Update for future records

    // Now, verify the server's Finished message
    if decrypted_server_finished_payload.len() < 16 {
        // 1 (type) + 3 (len) + 12 (verify_data)
        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
            "Server Finished payload too short".to_string(),
        )));
    }
    if decrypted_server_finished_payload[0] != HandshakeMessageType::Finished as u8 {
        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
            "Decrypted payload is not Finished message".to_string(),
        )));
    }
    // Extract the verify_data (12 bytes)
    let server_verify_data_received = &decrypted_server_finished_payload[4..]; // After type (1) and length (3) bytes

    // Add the *plaintext* Server Finished message (type + length + verify_data) to the transcript *before verification*
    handshake_transcript.extend_from_slice(&decrypted_server_finished_payload);
    println!("Added plaintext Server Finished message to handshake transcript hash.");

    // For server Finished, after decryption and before verify, log handshake_hash and verify_data
    let (expected_verify_data_from_transcript, server_handshake_hash) =
        keys::calculate_verify_data_with_hash(
            &master_secret,
            &handshake_transcript, // The full transcript of raw handshake messages so far
            b"server finished",
        )?;
    println!(
        "[DEBUG] Server Finished handshake_hash: {}",
        hex::encode(&server_handshake_hash)
    );
    println!(
        "[DEBUG] Server Finished verify_data: {}",
        hex::encode(&expected_verify_data_from_transcript)
    );

    // Print verify_data mismatch error (hex) if it occurs
    if server_verify_data_received != expected_verify_data_from_transcript {
        println!(
            "Server Finished verify_data mismatch! Expected: {}, Received: {}",
            hex::encode(&expected_verify_data_from_transcript),
            hex::encode(&server_verify_data_received)
        );
        return Err(TlsError::HandshakeFailed(
            format!(
                "Server Finished verify_data mismatch! Expected: {}, Received: {}",
                hex::encode(&expected_verify_data_from_transcript),
                hex::encode(&server_verify_data_received)
            )
            .to_string(),
        ));
    }
    println!("✓ Server Finished message verified successfully!");

    println!("\n✓ TLS Handshake process completed successfully!");

    Ok(TlsConnectionState {
        master_secret,
        client_write_key,
        server_write_key,
        client_fixed_iv,
        server_fixed_iv,
        client_sequence_number: client_current_sequence_number,
        server_sequence_number: server_current_sequence_number, // Use the updated sequence number
        negotiated_cipher_suite: final_chosen_cipher_suite_struct,
        negotiated_tls_version: TlsVersion::TLS1_2, // Direct assignment as per validation
        client_random,
        server_random: server_hello_parsed.server_random,
        handshake_hash: Sha256::digest(&handshake_transcript).into(), // Final handshake hash
    })
}

/// Reads a single TLS record from the stream.
pub fn read_tls_record<R: Read>(
    reader: &mut R,
    _tls_version: TlsVersion, // tls_version is not directly used here, but kept for signature consistency
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

    Ok(TlsRecord {
        content_type: TlsContentType::from(content_type),
        version_major: version.0,
        version_minor: version.1,
        length: length as u16,
        payload,
    })
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
