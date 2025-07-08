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

use crate::{
    services::errors::TlsError,
    services::tls_parser::{self, CipherSuite, HandshakeMessageType, TlsContentType, TlsVersion},
};

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
    pub handshake_hasher: Sha256,
}

// Now, move the `perform_tls_handshake_full` function and update its internal calls:
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

    let mut handshake_transcript_hash = Sha256::new();

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
    handshake_transcript_hash.update(client_hello_handshake_message);

    stream.write_all(&client_hello)?;
    println!("Sent ClientHello ({} bytes)", client_hello.len());

    let mut server_response_buffer = Vec::new();
    let mut temp_buffer = [0; 4096];

    loop {
        match stream.read(&mut temp_buffer) {
            Ok(0) => {
                println!("Server closed connection or EOF reached.");
                break;
            }
            Ok(n) => {
                server_response_buffer.extend_from_slice(&temp_buffer[..n]);
                println!(
                    "Received {} bytes. Total received: {}",
                    n,
                    server_response_buffer.len()
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                println!("Read WouldBlock, assuming no more data for now.");
                break;
            }
            Err(e) => return Err(TlsError::IoError(e)),
        }
    }

    if server_response_buffer.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "No server response received.".to_string(),
        ));
    }

    println!(
        "Attempting to parse server response of {} bytes.",
        server_response_buffer.len()
    );

    let (server_hello_parsed, certificates, server_key_exchange_parsed) =
        messages::HandshakeMessage::handle_server_hello_flight(
            &server_response_buffer,
            tls_version,
            &mut handshake_transcript_hash,
        )?;

    println!("\n--- Parsed Server Hello Flight ---");
    println!(
        "Negotiated TLS Version: {:X}.{:X}",
        server_hello_parsed.negotiated_tls_version.0, server_hello_parsed.negotiated_tls_version.1
    );
    println!(
        "Server Random: {}",
        hex::encode(&server_hello_parsed.server_random)
    );
    println!(
        "Chosen Cipher Suite: 0x{:02X}{:02X}",
        server_hello_parsed.chosen_cipher_suite[0], server_hello_parsed.chosen_cipher_suite[1]
    );
    if let Some(key_share) = &server_hello_parsed.server_key_share_public {
        println!(
            "Server Key Share Public (TLS 1.3): {}",
            hex::encode(key_share)
        );
    }
    println!("Number of Certificates received: {}", certificates.len());
    for (i, cert_der) in certificates.iter().enumerate() {
        println!("  Certificate {}: {} bytes (DER)", i + 1, cert_der.len());
    }
    if let Some(ske_parsed_debug) = &server_key_exchange_parsed {
        println!(
            "Server Key Exchange Payload: {} bytes",
            ske_parsed_debug.public_key.len()
        );
    }

    println!("\n--- Phase 2: Performing Certificate Validation & Hostname Verification ---");
    // This is already in `certificate_validator.rs`
    crate::services::certificate_validator::validate_server_certificate(&certificates, domain)?;
    println!("Server certificate chain and hostname validated successfully!");

    let (
        master_secret,
        client_write_key,
        server_write_key,
        client_fixed_iv,
        server_fixed_iv,
        chosen_cipher_suite_struct,
    ) = if tls_version == TlsVersion::TLS1_2 {
        let ske = server_key_exchange_parsed.ok_or_else(|| {
            TlsError::HandshakeFailed(
                "ServerKeyExchange expected but not received for TLS 1.2 ECDHE cipher suite."
                    .into(),
            )
        })?;

        println!("--- Phase 2.5: Verifying ServerKeyExchange Signature ---");
        // CALL MOVED FUNCTION: validation::verify_server_key_exchange_signature
        validation::verify_server_key_exchange_signature(
            &ske,
            &client_random,
            &server_hello_parsed.server_random,
            &certificates,
        )?;
        println!("✓ ServerKeyExchange signature verified.");

        println!("--- Phase 3.1: Computing Pre-Master Secret ---");

        // p256::EncodedPoint and p256::PublicKey are now imported at the top of this file
        let server_ephemeral_point = EncodedPoint::from_bytes(&ske.public_key).map_err(|_| {
            TlsError::KeyDerivationError("Invalid server ephemeral public key format".into())
        })?;

        let server_public_key =
            PublicKey::from_encoded_point(&server_ephemeral_point).map_err(|e| {
                TlsError::KeyDerivationError(format!(
                    "Failed to create PublicKey from encoded point: {:?}",
                    e
                ))
            })?;

        let shared_secret = client_ephemeral_secret.diffie_hellman(&server_public_key);
        let pre_master_secret = shared_secret.raw_secret_bytes().to_vec();

        println!(
            "✓ Pre-Master Secret computed ({} bytes)",
            pre_master_secret.len()
        );

        println!("--- Phase 3.2: Deriving Master Secret ---");
        // CALL MOVED FUNCTION: keys::derive_master_secret
        let master_secret = keys::calculate_master_secret(
            &pre_master_secret,
            &client_random,
            &server_hello_parsed.server_random,
        )?;
        println!("✓ Master Secret derived ({} bytes)", master_secret.len());

        println!("--- Phase 3.3: Deriving Key Block ---");

        let chosen_cipher_suite_struct =
            tls_parser::get_cipher_suite_by_id(&server_hello_parsed.chosen_cipher_suite)
                .ok_or_else(|| {
                    TlsError::HandshakeFailed("Unsupported cipher suite from server".into())
                })?;

        let key_block = keys::calculate_key_block(
            &master_secret,
            &client_random,
            &server_hello_parsed.server_random,
            chosen_cipher_suite_struct,
        )?;
        println!("Key Block derived ({} bytes)", key_block.len());

        let key_len = chosen_cipher_suite_struct.key_length as usize;
        let fixed_iv_len = chosen_cipher_suite_struct.fixed_iv_length as usize;
        let mac_key_len = chosen_cipher_suite_struct.mac_key_length as usize;

        let client_write_key = key_block[mac_key_len..(mac_key_len + key_len)].to_vec();
        let server_write_key =
            key_block[(mac_key_len + key_len)..(mac_key_len + key_len * 2)].to_vec();
        let client_fixed_iv = key_block
            [(mac_key_len + key_len * 2)..(mac_key_len + key_len * 2 + fixed_iv_len)]
            .to_vec();
        let server_fixed_iv = key_block[(mac_key_len + key_len * 2 + fixed_iv_len)
            ..(mac_key_len + key_len * 2 + fixed_iv_len * 2)]
            .to_vec();

        println!("✓ Extracted individual session keys from Key Block.");

        (
            master_secret,
            client_write_key,
            server_write_key,
            client_fixed_iv,
            server_fixed_iv,
            chosen_cipher_suite_struct,
        )
    } else if tls_version == TlsVersion::TLS1_3 {
        return Err(TlsError::HandshakeFailed(
            "TLS 1.3 key exchange not yet implemented.".into(),
        ));
    } else {
        return Err(TlsError::HandshakeFailed(
            "Unsupported TLS version or key exchange type.".into(),
        ));
    };

    println!("\n--- Phase 4: Client Sending Final Handshake ---");

    let client_finished_hash_input = handshake_transcript_hash.clone().finalize();

    // CALL MOVED FUNCTION: keys::prf_tls12
    let verify_data = keys::prf_tls12(
        &master_secret,
        b"client finished",
        client_finished_hash_input.as_slice(),
        12,
    )?;
    println!("✓ Computed Finished verify_data");

    let mut finished_message_plaintext = Vec::new();
    finished_message_plaintext.push(HandshakeMessageType::Finished as u8);
    finished_message_plaintext.extend_from_slice(&(12u32.to_be_bytes()[1..]));
    finished_message_plaintext.extend_from_slice(&verify_data);

    handshake_transcript_hash.update(&finished_message_plaintext);
    println!("Added plaintext Client Finished message to handshake transcript hash.");

    let change_cipher_spec = messages::build_change_cipher_spec();
    stream.write_all(&change_cipher_spec)?;
    println!("Sent ChangeCipherSpec.");

    let encrypted_finished_payload = keys::encrypt_gcm_message(
        &finished_message_plaintext,
        &client_write_key,
        &client_fixed_iv,
        0,
        TlsContentType::Handshake,
        tls_version,
    )?;
    println!(
        "✓ Encrypted Finished message payload generated ({} bytes).",
        encrypted_finished_payload.len()
    );

    let mut encrypted_finished_record = Vec::new();
    encrypted_finished_record.push(TlsContentType::Handshake.as_u8()); // Use the TlsContentType enum method
    let (major, minor) = tls_version.into();
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
    let mut final_server_response_buffer = Vec::new();
    loop {
        match stream.read(&mut temp_buffer) {
            Ok(0) => break,
            Ok(n) => {
                final_server_response_buffer.extend_from_slice(&temp_buffer[..n]);
                // This condition is potentially problematic. It assumes a fixed size response.
                // A robust parser would need to read the record length.
                if final_server_response_buffer.len() > 100 {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(TlsError::IoError(e)),
        }
    }
    println!(
        "Received server's final handshake bytes. Need to parse ChangeCipherSpec and Finished."
    );

    println!("\n✓ TLS Handshake process completed (remaining steps are placeholders).");

    Ok(TlsConnectionState {
        master_secret,
        client_write_key,
        server_write_key,
        client_fixed_iv,
        server_fixed_iv,
        client_sequence_number: 1,
        server_sequence_number: 0,
        negotiated_cipher_suite: chosen_cipher_suite_struct,
        negotiated_tls_version: tls_version,
        client_random,
        server_random: server_hello_parsed.server_random,
        handshake_hasher: handshake_transcript_hash,
    })
}
