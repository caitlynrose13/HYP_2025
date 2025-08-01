use crate::services::errors::TlsError;
use crate::services::tls_handshake::tls13::key_schedule::derive_tls13_finished_key_and_verify;
use crate::services::tls_handshake::tls13::record_layer::decrypt_record;
use crate::services::tls_handshake::tls13::transcript::TranscriptHashAlgorithm;
use crate::services::tls_parser::{
    CipherSuite, TlsContentType, TlsRecord, parse_handshake_messages,
};
use std::io::Read;
use std::net::TcpStream;
use std::sync::Mutex;

const MAX_CONSECUTIVE_DECRYPT_FAILURES: usize = 3;
const MAX_ALTERNATIVE_SEQUENCES: u64 = 5;
const MAX_TLS_RECORD_SIZE: usize = 16384;

// Add a static buffer for fragmented handshake messages
static HANDSHAKE_BUFFER: Mutex<Vec<u8>> = Mutex::new(Vec::new());

// ======================================================
// MAIN PROCESSING FUNCTION

/// Process encrypted handshake records after ServerHello in TLS 1.3
pub fn process_encrypted_handshake_records(
    stream: &mut TcpStream,
    server_hs_traffic_secret: &[u8],
    _server_app_traffic_secret: &[u8], // Not used during handshake phase
    cipher_suite: &CipherSuite,
    transcript: &mut crate::services::tls_handshake::tls13::transcript::TranscriptHash,
) -> Result<Vec<TlsRecord>, TlsError> {
    let mut sequence_number = 0u64;
    let mut decrypted_records = Vec::new();
    let mut server_finished_verified = false;
    let mut finished_verified_by_mac = false;
    let mut consecutive_decrypt_failures = 0;

    loop {
        // Read TLS record
        let record = match read_tls_record(stream) {
            Ok(record) => record,
            Err(e) => {
                if server_finished_verified {
                    break;
                } else {
                    eprintln!("[ERROR] Failed to read TLS record: {:?}", e);
                    return Err(e);
                }
            }
        };

        let content_type = record.content_type.as_u8();
        let payload = record.payload;

        // Process based on content type
        match content_type {
            20 => {
                // ChangeCipherSpec - legacy compatibility, no sequence increment
                continue;
            }
            21 => {
                // Alert
                if let Err(e) = handle_alert(&payload) {
                    return Err(e);
                }
                continue;
            }
            22 | 23 => {
                // Handshake or ApplicationData
                let result = process_encrypted_record(
                    &payload,
                    server_hs_traffic_secret,
                    _server_app_traffic_secret,
                    &mut sequence_number,
                    &mut consecutive_decrypt_failures,
                    content_type,
                    record.version_major,
                    record.version_minor,
                    record.length,
                    cipher_suite,
                    transcript,
                    &mut server_finished_verified,
                    &mut finished_verified_by_mac,
                )?;

                if let Some(decrypted_record) = result {
                    decrypted_records.push(decrypted_record);
                }
            }
            _ => {
                // Unknown content type - skip
                continue;
            }
        }

        // Check if handshake is complete
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

// ============================================================================
// HELPER FUNCTIONS

/// Handle TLS Alert messages
fn handle_alert(payload: &[u8]) -> Result<(), TlsError> {
    if payload.len() >= 2 {
        let level = payload[0];
        let description = payload[1];
        eprintln!(
            "[ERROR] TLS Alert: level=0x{:02x}, description=0x{:02x}",
            level, description
        );

        if level == 2 {
            return Err(TlsError::HandshakeError("Fatal alert received".to_string()));
        }
    }
    Ok(())
}

/// Process encrypted handshake/application data records
fn process_encrypted_record(
    payload: &[u8],
    server_hs_traffic_secret: &[u8],
    server_app_traffic_secret: &[u8],
    sequence_number: &mut u64,
    consecutive_decrypt_failures: &mut usize,
    content_type: u8,
    version_major: u8,
    version_minor: u8,
    record_length: u16,
    cipher_suite: &CipherSuite,
    transcript: &mut crate::services::tls_handshake::tls13::transcript::TranscriptHash,
    server_finished_verified: &mut bool,
    finished_verified_by_mac: &mut bool,
) -> Result<Option<TlsRecord>, TlsError> {
    // Try to decrypt with current sequence number
    match decrypt_record(
        payload,
        server_hs_traffic_secret,
        server_app_traffic_secret,
        *sequence_number,
        content_type,
        version_major,
        version_minor,
        record_length,
        cipher_suite,
    ) {
        Ok(plaintext) => {
            process_decrypted_handshake_messages(
                &plaintext,
                transcript,
                server_finished_verified,
                finished_verified_by_mac,
                server_hs_traffic_secret,
                cipher_suite,
            )?;

            *sequence_number += 1;
            *consecutive_decrypt_failures = 0;

            Ok(Some(TlsRecord {
                content_type: TlsContentType::from(content_type),
                version_major,
                version_minor,
                length: plaintext.len() as u16,
                payload: plaintext,
            }))
        }
        Err(e) => {
            eprintln!("[ERROR] Failed to decrypt record: {:?}", e);
            *consecutive_decrypt_failures += 1;

            // Try alternative sequence numbers
            if let Some(working_seq) = try_alternative_sequences(
                payload,
                server_hs_traffic_secret,
                server_app_traffic_secret,
                content_type,
                version_major,
                version_minor,
                record_length,
                cipher_suite,
                transcript,
                server_finished_verified,
                finished_verified_by_mac,
            )? {
                *sequence_number = working_seq + 1;
                *consecutive_decrypt_failures = 0;
                return Ok(None); // Record processed in try_alternative_sequences
            }

            // Check if too many consecutive failures
            if *consecutive_decrypt_failures > MAX_CONSECUTIVE_DECRYPT_FAILURES {
                return Err(TlsError::HandshakeError(
                    "Too many consecutive decrypt failures during handshake".to_string(),
                ));
            }

            *sequence_number += 1;
            Ok(None)
        }
    }
}

/// Try alternative sequence numbers for decryption
fn try_alternative_sequences(
    payload: &[u8],
    server_hs_traffic_secret: &[u8],
    server_app_traffic_secret: &[u8],
    content_type: u8,
    version_major: u8,
    version_minor: u8,
    record_length: u16,
    cipher_suite: &CipherSuite,
    transcript: &mut crate::services::tls_handshake::tls13::transcript::TranscriptHash,
    server_finished_verified: &mut bool,
    finished_verified_by_mac: &mut bool,
) -> Result<Option<u64>, TlsError> {
    println!("[DEBUG] Trying alternative sequence numbers...");

    for alt_seq in 0..=MAX_ALTERNATIVE_SEQUENCES {
        match decrypt_record(
            payload,
            server_hs_traffic_secret,
            server_app_traffic_secret,
            alt_seq,
            content_type,
            version_major,
            version_minor,
            record_length,
            cipher_suite,
        ) {
            Ok(plaintext) => {
                println!(
                    "[SUCCESS] Decrypted with sequence {}: {} bytes!",
                    alt_seq,
                    plaintext.len()
                );

                process_decrypted_handshake_messages(
                    &plaintext,
                    transcript,
                    server_finished_verified,
                    finished_verified_by_mac,
                    server_hs_traffic_secret,
                    cipher_suite,
                )?;

                return Ok(Some(alt_seq));
            }
            Err(_) => {
                println!("[DEBUG] Sequence {} failed", alt_seq);
            }
        }
    }

    println!("[ERROR] All sequence numbers failed for this record");
    Ok(None)
}

/// Process decrypted handshake messages and update transcript
fn process_decrypted_handshake_messages(
    plaintext: &[u8],
    transcript: &mut crate::services::tls_handshake::tls13::transcript::TranscriptHash,
    server_finished_verified: &mut bool,
    finished_verified_by_mac: &mut bool,
    server_hs_traffic_secret: &[u8],
    cipher_suite: &CipherSuite,
) -> Result<(), TlsError> {
    if plaintext.is_empty() {
        return Ok(());
    }

    let mut buffer = HANDSHAKE_BUFFER.lock().unwrap();

    // Append new plaintext to buffer
    buffer.extend_from_slice(plaintext);
    println!("[DEBUG] Handshake buffer now has {} bytes", buffer.len());

    let mut processed_bytes = 0;

    // Process all complete handshake messages in the buffer
    while processed_bytes < buffer.len() {
        // Check if we have at least the 4-byte handshake header
        if buffer.len() - processed_bytes < 4 {
            println!("[DEBUG] Waiting for more data - need handshake header");
            break;
        }

        // Read handshake message header
        let start = processed_bytes;
        let msg_type = buffer[start];
        let length_bytes = [buffer[start + 1], buffer[start + 2], buffer[start + 3]];
        let msg_length =
            u32::from_be_bytes([0, length_bytes[0], length_bytes[1], length_bytes[2]]) as usize;
        let total_msg_size = 4 + msg_length; // header + payload

        println!(
            "[DEBUG] Handshake message: type=0x{:02x}, length={}, total_size={}",
            msg_type, msg_length, total_msg_size
        );

        // Check if we have the complete message
        if buffer.len() - processed_bytes < total_msg_size {
            println!(
                "[DEBUG] Waiting for more data - need {} more bytes",
                total_msg_size - (buffer.len() - processed_bytes)
            );
            break;
        }

        // Extract the complete handshake message
        let complete_message = &buffer[start..start + total_msg_size];

        // Parse this single complete message
        match parse_handshake_messages(complete_message) {
            Ok(handshake_msgs) => {
                for handshake_msg in handshake_msgs {
                    let handshake_type = handshake_msg.msg_type.as_u8();
                    println!(
                        "[SUCCESS] Parsed complete handshake message: type=0x{:02x}, size={}",
                        handshake_type,
                        handshake_msg.raw_bytes.len()
                    );

                    // Handle Finished message specially
                    if handshake_type == 0x14 {
                        *server_finished_verified = true;

                        // Verify Finished MAC before updating transcript
                        let transcript_hash = transcript.clone_hash().unwrap_or_default();
                        let verify_data = &handshake_msg.payload;
                        let hash_alg = get_hash_algorithm(cipher_suite);

                        match derive_tls13_finished_key_and_verify(
                            server_hs_traffic_secret,
                            &transcript_hash,
                            hash_alg,
                            verify_data,
                        ) {
                            Ok(true) => {
                                println!("[SUCCESS] Server Finished MAC verified!");
                                *finished_verified_by_mac = true;
                            }
                            Ok(false) => {
                                eprintln!("[ERROR] Server Finished MAC verification failed!");
                            }
                            Err(e) => {
                                eprintln!("[ERROR] Finished MAC verification error: {:?}", e);
                            }
                        }
                    }

                    // Update transcript with this message
                    transcript.update(&handshake_msg.raw_bytes);
                    println!(
                        "[INFO] Updated transcript with handshake type: 0x{:02x}",
                        handshake_type
                    );
                }
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to parse handshake message: {:?}", e);
                // Skip this message and continue
                processed_bytes += 1;
                continue;
            }
        }

        processed_bytes += total_msg_size;
    }

    // Remove processed bytes from buffer
    if processed_bytes > 0 {
        buffer.drain(0..processed_bytes);
        println!(
            "[DEBUG] Removed {} processed bytes, buffer now has {} bytes",
            processed_bytes,
            buffer.len()
        );
    }

    Ok(())
}

/// Get hash algorithm from cipher suite
fn get_hash_algorithm(cipher_suite: &CipherSuite) -> TranscriptHashAlgorithm {
    if cipher_suite.hash_algorithm == crate::services::tls_parser::HashAlgorithm::Sha384 {
        TranscriptHashAlgorithm::Sha384
    } else {
        TranscriptHashAlgorithm::Sha256
    }
}

// ============================================================================
// TLS RECORD READING

/// Read a single TLS record from a stream
pub fn read_tls_record(stream: &mut TcpStream) -> Result<TlsRecord, TlsError> {
    // Read the 5-byte TLS record header
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            TlsError::HandshakeError("Connection closed before handshake completion".to_string())
        } else {
            TlsError::IoError(e)
        }
    })?;

    // Parse header
    let content_type = header[0];
    let version_major = header[1];
    let version_minor = header[2];
    let payload_length = u16::from_be_bytes([header[3], header[4]]) as usize;

    println!(
        "[DEBUG] Reading TLS record: type={:02x}, version={:02x}{:02x}, length={}",
        content_type, version_major, version_minor, payload_length
    );

    // Validate payload length
    if payload_length > MAX_TLS_RECORD_SIZE {
        return Err(TlsError::HandshakeError(format!(
            "TLS record payload too large: {} bytes",
            payload_length
        )));
    }

    // Read the complete payload
    let mut payload = vec![0u8; payload_length];
    stream.read_exact(&mut payload).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            TlsError::HandshakeError(format!(
                "Connection closed while reading payload: expected {} bytes",
                payload_length
            ))
        } else {
            TlsError::IoError(e)
        }
    })?;

    println!(
        "[DEBUG] Successfully read complete TLS record: {} bytes total",
        5 + payload_length
    );

    // Parse content type
    let content_type_enum = TlsContentType::try_from_u8(content_type).ok_or_else(|| {
        TlsError::HandshakeError(format!("Invalid content type: 0x{:02x}", content_type))
    })?;

    Ok(TlsRecord {
        content_type: content_type_enum,
        version_major,
        version_minor,
        length: payload_length as u16,
        payload,
    })
}
