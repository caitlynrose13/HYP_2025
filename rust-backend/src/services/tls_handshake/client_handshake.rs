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
use crate::{
    services::errors::TlsError,
    services::tls_parser::{
        self, CipherSuite, HandshakeMessageType, TlsContentType, TlsRecord, TlsVersion,
    },
};

// Assuming that in `keys.rs`, `derive_aead_keys` returns `(AesGcm<Aes128, U12, U16>, AesGcm<Aes128, U12, U16>)`
// You may need to add `use aes_gcm::AesGcm;` and `use aes::Aes128;` and `use typenum::{U12, U16};`
// or adjust `U12` and `U16` to `UInt<UInt<...>>` based on your `typenum` usage.
// For this fix, I'll use a specific type directly from the error, assuming necessary `use` statements exist in your environment:
type AeadCipherInstance = aes_gcm::AesGcm<aes::Aes128, typenum::U12, typenum::U16>; // Adjusted to include U16

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

    let client_hello = messages::HandshakeMessage::build_client_hello_with_random_and_key_share(
        domain,
        tls_version,
        &client_random,
        client_ephemeral_public_bytes,
    )?;
    let client_hello_handshake_message = &client_hello[5..]; // Slice to get only the handshake message content
    handshake_transcript.extend_from_slice(client_hello_handshake_message);

    // Debug: Print the exact ClientHello bytes
    println!("ClientHello bytes: {}", hex::encode(&client_hello));
    println!(
        "ClientHello handshake message: {}",
        hex::encode(client_hello_handshake_message)
    );

    stream.write_all(&client_hello)?;
    println!("Sent ClientHello ({} bytes)", client_hello.len());

    // Server Hello Flight - Read all records until ServerHelloDone or EOF/timeout
    let mut server_response_buffer = Vec::new();
    let mut temp_buffer = [0; 4096]; // Use a temporary buffer for reading from stream

    // Read initial bytes into a buffer to be processed by handle_server_hello_flight
    // This loop is for receiving the *entire* initial server flight.
    loop {
        match stream.read(&mut temp_buffer) {
            Ok(0) => {
                println!("Server closed connection or EOF reached during initial read.");
                break;
            }
            Ok(n) => {
                server_response_buffer.extend_from_slice(&temp_buffer[..n]);
                println!(
                    "Received {} bytes. Total received: {}",
                    n,
                    server_response_buffer.len()
                );
                // A simple heuristic to stop reading if enough data for ServerHello flight is received.
                // A more robust solution would parse records as they arrive.
                if server_response_buffer.len() >= 1000 {
                    // Minimum expected size for ServerHello flight
                    // Check if it looks like a handshake record and its length is plausible
                    if server_response_buffer.len() >= 5
                        && server_response_buffer[0] == TlsContentType::Handshake.as_u8()
                    {
                        let record_len = u16::from_be_bytes([
                            server_response_buffer[3],
                            server_response_buffer[4],
                        ]) as usize;
                        if server_response_buffer.len() >= record_len + 5 {
                            // If we have at least one full record, break and let handle_server_hello_flight parse it all
                            break;
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                println!("Read WouldBlock, assuming no more data for now from initial flight.");
                break;
            }
            Err(e) => return Err(TlsError::IoError(e)),
        }
    }

    if server_response_buffer.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "No server response received for initial flight.".to_string(),
        ));
    }

    println!(
        "Received {} bytes from server. Attempting to parse ServerHello flight...",
        server_response_buffer.len()
    );

    let (server_hello_parsed, certificates, server_key_exchange_parsed) =
        match messages::handle_server_hello_flight(
            &server_response_buffer,
            tls_version,
            &mut handshake_transcript,
        ) {
            Ok(parsed_data) => {
                println!("ServerHello flight parsed successfully!");
                println!("Finished parsing ServerHello flight. Proceeding to next handshake step.");
                parsed_data
            }
            Err(e) => {
                eprintln!("Failed to parse ServerHello flight: {:?}", e);
                eprintln!(
                    "Raw server response (hex): {}",
                    hex::encode(&server_response_buffer)
                );
                return Err(e);
            }
        };

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

    // Use a `let` binding with an `if` block to ensure all key derivation variables are initialized
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
                    .to_string(), // Changed .into() to .to_string()
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
            TlsError::KeyDerivationError("Invalid server ephemeral public key format".to_string()) // Changed .into() to .to_string()
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

        println!(
            "✓ Pre-Master Secret computed ({} bytes)",
            pre_master_secret_val.len()
        );

        println!("--- Phase 3.2: Deriving Master Secret ---");
        let master_secret_val = keys::calculate_master_secret(
            &pre_master_secret_val,
            &client_random,
            &server_hello_parsed.server_random,
        )?
        .to_vec(); // Convert [u8; 48] to Vec<u8>
        println!(
            "✓ Master Secret derived ({} bytes)",
            master_secret_val.len()
        );

        println!("--- Phase 3.3: Deriving Key Block ---");

        let key_block = keys::calculate_key_block(
            &master_secret_val,
            &client_random, // Corrected: Should be client_random not server_random as per TLS spec
            &server_hello_parsed.server_random, // Corrected: Should be server_random
            chosen_cipher_suite_struct_temp,
        )?;
        println!("Key Block derived ({} bytes)", key_block.len());

        // Derive AEAD keys using the key block
        let (c_cipher, s_cipher) =
            keys::derive_aead_keys(chosen_cipher_suite_struct_temp, &key_block)?;

        println!("✓ Derived AEAD cipher instances from Key Block.");

        let key_len = chosen_cipher_suite_struct_temp.key_length as usize;
        let fixed_iv_len = chosen_cipher_suite_struct_temp.fixed_iv_length as usize;
        let mac_key_len = chosen_cipher_suite_struct_temp.mac_key_length as usize;

        let client_write_key_val = key_block[mac_key_len..(mac_key_len + key_len)].to_vec();
        let server_write_key_val =
            key_block[(mac_key_len + key_len)..(mac_key_len + key_len * 2)].to_vec();
        let client_fixed_iv_val = key_block
            [(mac_key_len + key_len * 2)..(mac_key_len + key_len * 2 + fixed_iv_len)]
            .to_vec();
        let server_fixed_iv_val = key_block[(mac_key_len + key_len * 2 + fixed_iv_len)
            ..(mac_key_len + key_len * 2 + fixed_iv_len * 2)]
            .to_vec();

        println!("✓ Extracted individual session keys from Key Block.");

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
            "TLS 1.3 key exchange not yet implemented.".to_string(), // Changed .into() to .to_string()
        ));
    } else {
        return Err(TlsError::HandshakeFailed(
            "Unsupported TLS version or key exchange type.".to_string(), // Changed .into() to .to_string()
        ));
    }?;

    println!("\n--- Phase 4: Client Sending Final Handshake ---");

    let mut verify_data = [0u8; 12];
    keys::prf_tls12(&master_secret, b"client finished", &mut verify_data)
        .map_err(|e| TlsError::KeyDerivationError(format!("PRF error: {}", e)))?;
    println!("✓ Computed Finished verify_data");

    let mut finished_message_plaintext = Vec::new();
    finished_message_plaintext.push(HandshakeMessageType::Finished as u8);
    finished_message_plaintext.extend_from_slice(&(12u32.to_be_bytes()[1..]));
    finished_message_plaintext.extend_from_slice(&verify_data);

    handshake_transcript.extend_from_slice(&finished_message_plaintext);
    println!("Added plaintext Client Finished message to handshake transcript hash.");

    let change_cipher_spec = messages::HandshakeMessage::build_change_cipher_spec();
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
    encrypted_finished_record.push(TlsContentType::Handshake.as_u8()); // Use the TlsContentType enum method
    let (major, minor) = tls_version.to_u8_pair();
    encrypted_finished_record.push(major);
    encrypted_finished_record.push(minor);
    encrypted_finished_record
        .extend_from_slice(&(encrypted_finished_payload.len() as u16).to_be_bytes());
    encrypted_finished_record.extend_from_slice(&encrypted_finished_payload);
    stream.write_all(&encrypted_finished_record)?;
    println!(
        "Sent Encrypted Finished record ({} bytes).",
        encrypted_finished_record.len()
    );

    println!("--- Phase 5: Awaiting Server Final Handshake ---");

    // Increment client sequence number after sending its finished record
    let client_current_sequence_number = 1; // Client's first encrypted record was at 0, next is 1

    // Server should send ChangeCipherSpec, then Finished.
    // We need to parse these as individual records.

    // 1. Read Server's ChangeCipherSpec record
    println!("Waiting for Server ChangeCipherSpec...");
    let server_ccs_record = messages::read_tls_record(&mut stream, tls_version)?; // Use your read_tls_record
    if server_ccs_record.content_type != TlsContentType::ChangeCipherSpec
        || server_ccs_record.payload != &[0x01]
    {
        return Err(TlsError::HandshakeFailed(
            format!(
                "Expected Server ChangeCipherSpec, got type {:?} and payload {:?}",
                server_ccs_record.content_type,
                hex::encode(&server_ccs_record.payload)
            )
            .to_string(), // Changed .into() to .to_string()
        ));
    }
    println!("✓ Received Server ChangeCipherSpec.");
    // After CCS, the server transitions to encrypted messages.
    // The sequence number for server outgoing messages starts at 0.
    let server_current_sequence_number = 0; // Server's first encrypted record will be at 0

    // 2. Read Server's Encrypted Finished record
    println!("Waiting for Server Finished record...");
    let server_finished_record = messages::read_tls_record(&mut stream, tls_version)?; // Use your read_tls_record
    if server_finished_record.content_type != TlsContentType::Handshake {
        return Err(TlsError::HandshakeFailed(
            format!(
                "Expected encrypted Server Finished (Handshake content type), got {:?}",
                server_finished_record.content_type
            )
            .to_string(), // Changed .into() to .to_string()
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
    let server_next_sequence_number = server_current_sequence_number + 1; // Update for future records

    // Now, verify the server's Finished message
    // The verify_data is the last 12 bytes of the decrypted_server_finished_payload (after type and length)
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

    // Calculate the expected verify_data from your handshake_transcript
    let expected_verify_data_from_transcript = keys::calculate_verify_data(
        &master_secret,
        &handshake_transcript, // The full transcript of raw handshake messages so far
        b"server finished",
    )?;

    if server_verify_data_received != expected_verify_data_from_transcript {
        return Err(TlsError::HandshakeFailed(
            format!(
                "Server Finished verify_data mismatch! Expected: {}, Received: {}",
                hex::encode(&expected_verify_data_from_transcript),
                hex::encode(&server_verify_data_received)
            )
            .to_string(), // Changed .into() to .to_string()
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
        server_sequence_number: server_next_sequence_number, // Use the updated sequence number
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
    let mut header = [0u8; 5];
    reader.read_exact(&mut header)?;

    let content_type = header[0];
    let version = (header[1], header[2]);
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;

    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)?;

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

    // Test TLS 1.2 (most common)
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
            // Check if it's a protocol version alert (downgrade request)
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

    // TODO: Add TLS 1.3 test when implemented
    // For now, if TLS 1.2 fails, assume deprecated
    println!("    TLS 1.3 not yet implemented - assuming deprecated if TLS 1.2 failed");
    TlsSecurityLevel::Deprecated
}
