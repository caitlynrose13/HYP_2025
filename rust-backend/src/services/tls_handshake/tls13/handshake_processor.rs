use crate::services::errors::TlsError;
use crate::services::tls_handshake::tls13::record_layer::decrypt_record;
use crate::services::tls_parser::{CipherSuite, TlsContentType, TlsRecord};
use std::io::Read;
use std::net::TcpStream;

/// yes encrypted handshake records after ServerHello in TLS 1.3
pub fn process_encrypted_handshake_records(
    stream: &mut TcpStream,
    server_hs_traffic_secret: &[u8],
    _server_app_traffic_secret: &[u8], // Not used during handshake phase
    cipher_suite: &CipherSuite,
    transcript: &mut crate::services::tls_handshake::tls13::transcript::TranscriptHash,
) -> Result<Vec<TlsRecord>, TlsError> {
    let mut sequence_number = 0u64; // Single sequence counter for TLS 1.3
    let mut decrypted_records = Vec::new();
    let mut server_finished_verified = false;
    let mut finished_verified_by_mac = false;

    use crate::services::tls_handshake::tls13::key_schedule::derive_tls13_finished_key_and_verify;
    use crate::services::tls_parser::parse_handshake_messages;

    let mut consecutive_decrypt_failures = 0;
    loop {
        // Read the next TLS record header
        let mut header = [0u8; 5];
        let mut bytes_read = 0;
        while bytes_read < 5 {
            let n = match stream.read(&mut header[bytes_read..]) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[ERROR] Failed to read TLS record header: {:?}", e);
                    return Err(TlsError::IoError(e));
                }
            };
            if n == 0 {
                if server_finished_verified {
                    break;
                } else {
                    eprintln!("[ERROR] Connection closed before handshake completion.");
                    return Err(TlsError::HandshakeError(
                        "Connection closed before handshake completion".to_string(),
                    ));
                }
            }
            bytes_read += n;
        }
        if bytes_read == 0 {
            if server_finished_verified {
                break;
            } else {
                eprintln!("[ERROR] Connection closed before handshake completion.");
                return Err(TlsError::HandshakeError(
                    "Connection closed before handshake completion".to_string(),
                ));
            }
        }
        let content_type = header[0];
        let version_major = header[1];
        let version_minor = header[2];
        let record_length = u16::from_be_bytes([header[3], header[4]]) as usize;

        // CRITICAL: Check for protocol violations
        match content_type {
            20 => {
                let mut ccs_payload = vec![0u8; record_length];
                if let Err(e) = stream.read_exact(&mut ccs_payload) {
                    eprintln!("[ERROR] Failed to read CCS payload: {:?}", e);
                    return Err(TlsError::IoError(e));
                }
                // TLS 1.3: ChangeCipherSpec is a legacy compatibility message and does NOT increment sequence number
                // Sequence numbers only apply to encrypted records (Handshake/ApplicationData)
                continue;
            }
            21 => {
                let mut alert_payload = vec![0u8; record_length];
                if let Err(e) = stream.read_exact(&mut alert_payload) {
                    eprintln!("[ERROR] Failed to read Alert payload: {:?}", e);
                    return Err(TlsError::IoError(e));
                }
                if alert_payload.len() >= 2 {
                    let level = alert_payload[0];
                    let description = alert_payload[1];
                    eprintln!(
                        "[ERROR] TLS Alert: level=0x{:02x}, description=0x{:02x}",
                        level, description
                    );
                    if level == 2 {
                        return Err(TlsError::HandshakeError("Fatal alert received".to_string()));
                    }
                }
                continue;
            }
            22 | 23 => {
                // Use single sequence number for TLS 1.3
                let current_sequence = sequence_number;

                // Handle ApplicationData records during handshake phase
                if content_type == 0x17 && !server_finished_verified {
                    // Don't skip - try to decrypt as it might contain handshake messages
                }

                let mut payload = vec![0u8; record_length];
                let mut payload_read = 0;
                while payload_read < record_length {
                    let n = match stream.read(&mut payload[payload_read..]) {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("[ERROR] Failed to read record payload: {:?}", e);
                            return Err(TlsError::IoError(e));
                        }
                    };
                    if n == 0 {
                        eprintln!(
                            "[ERROR] Connection closed while reading payload: got {} of {} bytes",
                            payload_read, record_length
                        );
                        return Err(TlsError::HandshakeError(format!(
                            "Connection closed while reading payload: got {} of {} bytes",
                            payload_read, record_length
                        )));
                    }
                    payload_read += n;
                }

                // DIAGNOSTIC: Confirm we read the full record
                assert_eq!(
                    payload.len(),
                    record_length,
                    "[CRITICAL] Payload length mismatch! Expected: {}, Got: {}",
                    record_length,
                    payload.len()
                );

                // Key and IV derivation is handled inside decrypt_record function
                // No need to derive them separately here

                match decrypt_record(
                    &payload,
                    server_hs_traffic_secret,
                    _server_app_traffic_secret, // Pass the actual app secret instead of hs secret
                    current_sequence,
                    content_type,
                    version_major,
                    version_minor,
                    record_length as u16, // This should be the actual payload length, not the outer record
                    cipher_suite,
                ) {
                    Ok(plaintext) => {
                        // --- Parse handshake messages and update transcript ---
                        if !plaintext.is_empty() {
                            match parse_handshake_messages(&plaintext) {
                                Ok(handshake_msgs) => {
                                    for handshake_msg in handshake_msgs {
                                        let handshake_type = handshake_msg.msg_type.as_u8();

                                        // If Finished, verify MAC BEFORE updating transcript
                                        if handshake_type == 0x14 {
                                            server_finished_verified = true;
                                            // Get transcript hash BEFORE adding Finished message
                                            let transcript_hash =
                                                transcript.clone_hash().unwrap_or_default();
                                            let verify_data = &handshake_msg.payload;
                                            let hash_alg = if cipher_suite.hash_algorithm == crate::services::tls_parser::HashAlgorithm::Sha384 {
                                                crate::services::tls_handshake::tls13::transcript::TranscriptHashAlgorithm::Sha384
                                            } else {
                                                crate::services::tls_handshake::tls13::transcript::TranscriptHashAlgorithm::Sha256
                                            };
                                            match derive_tls13_finished_key_and_verify(
                                                server_hs_traffic_secret,
                                                &transcript_hash,
                                                hash_alg,
                                                verify_data,
                                            ) {
                                                Ok(true) => {
                                                    finished_verified_by_mac = true;
                                                }
                                                Ok(false) => {
                                                    eprintln!(
                                                        "[ERROR] Server Finished MAC verification failed!"
                                                    );
                                                }
                                                Err(e) => {
                                                    eprintln!(
                                                        "[ERROR] Finished MAC verification error: {:?}",
                                                        e
                                                    );
                                                }
                                            }
                                        }

                                        // Now update transcript with this message
                                        transcript.update(&handshake_msg.raw_bytes);
                                    }
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[ERROR] Failed to parse handshake messages: {:?}",
                                        e
                                    );
                                }
                            }
                        }
                        let decrypted_record = TlsRecord {
                            content_type: TlsContentType::from(content_type),
                            version_major,
                            version_minor,
                            length: plaintext.len() as u16,
                            payload: plaintext,
                        };
                        decrypted_records.push(decrypted_record);

                        // Increment sequence number for next record
                        sequence_number += 1;
                        consecutive_decrypt_failures = 0;
                    }
                    Err(e) => {
                        eprintln!("[ERROR] Failed to decrypt record: {:?}", e);
                        consecutive_decrypt_failures += 1;
                        // Try different sequence numbers - maybe we're off by some amount
                        println!("[DEBUG] Trying alternative sequence numbers...");
                        let mut found_working_seq = false;
                        for alt_seq in 0..=5 {
                            match decrypt_record(
                                &payload,
                                server_hs_traffic_secret,
                                _server_app_traffic_secret, // Use the actual app secret
                                alt_seq,
                                content_type,
                                version_major,
                                version_minor,
                                record_length as u16,
                                cipher_suite,
                            ) {
                                Ok(plaintext) => {
                                    println!(
                                        "[SUCCESS] Decrypted with sequence {}: {} bytes!",
                                        alt_seq,
                                        plaintext.len()
                                    );
                                    sequence_number = alt_seq + 1;
                                    consecutive_decrypt_failures = 0;
                                    // Parse handshake messages
                                    if !plaintext.is_empty() {
                                        match parse_handshake_messages(&plaintext) {
                                            Ok(handshake_msgs) => {
                                                for handshake_msg in handshake_msgs {
                                                    transcript.update(&handshake_msg.raw_bytes);
                                                    let handshake_type =
                                                        handshake_msg.msg_type.as_u8();
                                                    println!(
                                                        "[INFO] Updated transcript with handshake type: 0x{:02x}",
                                                        handshake_type
                                                    );
                                                    if handshake_type == 0x14 {
                                                        server_finished_verified = true;
                                                        // Try to verify Finished message
                                                        let transcript_hash = transcript
                                                            .clone_hash()
                                                            .unwrap_or_default();
                                                        let verify_data = &handshake_msg.payload;
                                                        let hash_alg = if cipher_suite.hash_algorithm == crate::services::tls_parser::HashAlgorithm::Sha384 {
                                                            crate::services::tls_handshake::tls13::transcript::TranscriptHashAlgorithm::Sha384
                                                        } else {
                                                            crate::services::tls_handshake::tls13::transcript::TranscriptHashAlgorithm::Sha256
                                                        };
                                                        match derive_tls13_finished_key_and_verify(
                                                            server_hs_traffic_secret,
                                                            &transcript_hash,
                                                            hash_alg,
                                                            verify_data,
                                                        ) {
                                                            Ok(true) => {
                                                                println!(
                                                                    "[SUCCESS] Server Finished MAC verified!"
                                                                );
                                                                finished_verified_by_mac = true;
                                                            }
                                                            Ok(false) => {
                                                                eprintln!(
                                                                    "[ERROR] Server Finished MAC verification failed!"
                                                                );
                                                            }
                                                            Err(e) => {
                                                                eprintln!(
                                                                    "[ERROR] Finished MAC verification error: {:?}",
                                                                    e
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "[ERROR] Failed to parse handshake messages: {:?}",
                                                    e
                                                );
                                            }
                                        }
                                    }
                                    let decrypted_record = TlsRecord {
                                        content_type: TlsContentType::from(content_type),
                                        version_major,
                                        version_minor,
                                        length: plaintext.len() as u16,
                                        payload: plaintext,
                                    };
                                    decrypted_records.push(decrypted_record);
                                    found_working_seq = true;
                                    break;
                                }
                                Err(_) => {
                                    println!("[DEBUG] Sequence {} failed", alt_seq);
                                }
                            }
                        }
                        if !found_working_seq {
                            println!("[ERROR] All sequence numbers failed for this record");
                            if consecutive_decrypt_failures > 3 {
                                return Err(TlsError::HandshakeError(
                                    "Too many consecutive decrypt failures during handshake"
                                        .to_string(),
                                ));
                            }
                            sequence_number += 1;
                        }
                    }
                }
            }
            _ => {
                let mut unknown_payload = vec![0u8; record_length];
                if let Err(e) = stream.read_exact(&mut unknown_payload) {
                    eprintln!(
                        "[ERROR] Failed to read unknown record type payload: {:?}",
                        e
                    );
                    return Err(TlsError::IoError(e));
                }

                continue;
            }
        }
        if server_finished_verified {
            if finished_verified_by_mac {
                break;
            } else {
                eprintln!("[ERROR] Handshake did not complete: Finished message not verified.");
                return Err(TlsError::HandshakeError(
                    "Handshake did not complete: Finished message not verified".to_string(),
                ));
            }
        }
    }
    if !server_finished_verified {
        eprintln!("[ERROR] Handshake did not complete: Finished message not received.");
        return Err(TlsError::HandshakeError(
            "Handshake did not complete: Finished message not received".to_string(),
        ));
    }
    Ok(decrypted_records)
}

/// Read a single TLS record from a stream
pub fn read_tls_record(stream: &mut TcpStream) -> Result<TlsRecord, TlsError> {
    // Read the header (5 bytes)
    let mut header = [0u8; 5];
    let mut bytes_read = 0;

    while bytes_read < 5 {
        let n = stream
            .read(&mut header[bytes_read..])
            .map_err(|e| TlsError::IoError(e))?;
        if n == 0 {
            return Err(TlsError::HandshakeError(
                "Connection closed while reading header".to_string(),
            ));
        }
        bytes_read += n;
    }

    // Parse the header
    let content_type = header[0];
    let version_major = header[1];
    let version_minor = header[2];
    let record_length = u16::from_be_bytes([header[3], header[4]]) as usize;

    // Read the record payload
    let mut payload = vec![0u8; record_length];
    let mut payload_read = 0;

    while payload_read < record_length {
        let n = stream
            .read(&mut payload[payload_read..])
            .map_err(|e| TlsError::IoError(e))?;
        if n == 0 {
            return Err(TlsError::HandshakeError(format!(
                "Connection closed while reading payload: got {} of {} bytes",
                payload_read, record_length
            )));
        }
        payload_read += n;
    }

    Ok(TlsRecord {
        content_type: TlsContentType::from(content_type),
        version_major,
        version_minor,
        length: record_length as u16,
        payload,
    })
}
