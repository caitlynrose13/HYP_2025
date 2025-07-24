use crate::services::errors::TlsError;
use crate::services::tls_handshake::tls13::record_layer::decrypt_record;
use crate::services::tls_parser::{CipherSuite, TlsContentType, TlsRecord};
use std::io::Read;
use std::net::TcpStream;

/// Process encrypted handshake records after ServerHello in TLS 1.3
pub fn process_encrypted_handshake_records(
    stream: &mut TcpStream,
    server_hs_traffic_secret: &[u8],
    cipher_suite: &CipherSuite,
) -> Result<Vec<TlsRecord>, TlsError> {
    let mut sequence_number = 0u64;
    let mut records_processed = 0;
    let mut decrypted_records = Vec::new();
    let server_finished_verified = false;

    println!("[TLS13_HANDSHAKE] 📖 Processing server handshake completion messages...");

    loop {
        // Safety limit to prevent infinite loops
        if records_processed >= 20 {
            return Err(TlsError::HandshakeError(
                "Too many records processed, possible infinite loop".to_string(),
            ));
        }

        println!(
            "[TLS13_HANDSHAKE] Reading TLS record #{} (seq: {})",
            records_processed + 1,
            sequence_number
        );

        // Read the next TLS record header
        let mut header = [0u8; 5];
        let mut bytes_read = 0;

        while bytes_read < 5 {
            let n = stream
                .read(&mut header[bytes_read..])
                .map_err(|e| TlsError::IoError(e))?;
            if n == 0 {
                if server_finished_verified {
                    println!(
                        "[TLS13_HANDSHAKE] Connection closed after handshake completion - this is normal"
                    );
                    break;
                } else {
                    return Err(TlsError::HandshakeError(
                        "Connection closed before handshake completion".to_string(),
                    ));
                }
            }
            bytes_read += n;
        }

        // Check if we read nothing (connection closed)
        if bytes_read == 0 {
            if server_finished_verified {
                println!("[TLS13_HANDSHAKE] Connection closed after handshake completion");
                break;
            } else {
                return Err(TlsError::HandshakeError(
                    "Connection closed before handshake completion".to_string(),
                ));
            }
        }

        // Parse the header
        let content_type = header[0];
        let version_major = header[1];
        let version_minor = header[2];
        let record_length = u16::from_be_bytes([header[3], header[4]]) as usize;

        println!(
            "[TLS13_HANDSHAKE] Record #{}: type={} (0x{:02x}), version={}.{}, length={}",
            records_processed + 1,
            content_type,
            content_type,
            version_major,
            version_minor,
            record_length
        );

        // Handle different TLS record types
        match content_type {
            20 => {
                // ChangeCipherSpec - skip in TLS 1.3 (compatibility)
                println!("[TLS13_HANDSHAKE] Skipping ChangeCipherSpec compatibility record");
                let mut ccs_payload = vec![0u8; record_length];
                stream.read_exact(&mut ccs_payload)?;
                records_processed += 1;
                continue;
            }
            21 => {
                // Alert
                println!("[TLS13_HANDSHAKE] ⚠️ Received Alert record");
                let mut alert_payload = vec![0u8; record_length];
                stream.read_exact(&mut alert_payload)?;

                if alert_payload.len() >= 2 {
                    let level = alert_payload[0];
                    let description = alert_payload[1];
                    println!(
                        "[TLS13_HANDSHAKE] Alert: level={}, description={}",
                        level, description
                    );

                    if level == 2 {
                        return Err(TlsError::HandshakeError(format!(
                            "Fatal alert received: {}",
                            description
                        )));
                    }
                }
                records_processed += 1;
                continue;
            }
            22 => {
                // Handshake (encrypted after ServerHello in TLS 1.3)
                println!("[TLS13_HANDSHAKE] Processing encrypted handshake record");
            }
            23 => {
                // ApplicationData - In TLS 1.3, this could be encrypted handshake messages OR actual application data
                if !server_finished_verified {
                    println!(
                        "[TLS13_HANDSHAKE] Processing ApplicationData that may contain handshake messages"
                    );
                } else {
                    println!("[TLS13_HANDSHAKE] Received actual application data");
                }
            }
            _ => {
                println!("[TLS13_HANDSHAKE] ⚠️ Unknown record type: {}", content_type);
                // Read and discard unknown record types
                let mut unknown_payload = vec![0u8; record_length];
                stream.read_exact(&mut unknown_payload)?;
                records_processed += 1;
                continue;
            }
        }

        // For handshake records (type 22) OR ApplicationData that might contain handshake messages (type 23), read and decrypt
        if content_type == 22 || (content_type == 23 && !server_finished_verified) {
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

            println!(
                "[TLS13_HANDSHAKE] Successfully read {} bytes for encrypted {} record",
                payload_read,
                if content_type == 22 {
                    "handshake"
                } else {
                    "ApplicationData"
                }
            );

            // Debug: Show first and last bytes of the encrypted payload
            println!("[TLS13_DEBUG] About to decrypt record:");
            println!("[TLS13_DEBUG] - Record type: 0x{:02x}", content_type);
            println!("[TLS13_DEBUG] - Record length: {} bytes", record_length);
            println!("[TLS13_DEBUG] - Sequence number: {}", sequence_number);

            if payload.len() > 64 {
                println!(
                    "[TLS13_DEBUG] - Payload start: {}",
                    hex::encode(&payload[..32])
                );
                println!(
                    "[TLS13_DEBUG] - Payload end: {}",
                    hex::encode(&payload[payload.len() - 32..])
                );
            } else if payload.len() > 32 {
                println!(
                    "[TLS13_DEBUG] - Payload start: {}",
                    hex::encode(&payload[..16])
                );
                println!(
                    "[TLS13_DEBUG] - Payload end: {}",
                    hex::encode(&payload[payload.len() - 16..])
                );
            } else {
                println!("[TLS13_DEBUG] - Full payload: {}", hex::encode(&payload));
            }

            // Attempt to decrypt the record
            // In TLS 1.3, encrypted records use ApplicationData (0x17) in the record header
            // The AAD must use the exact record header values
            match decrypt_record(
                &payload,
                server_hs_traffic_secret,
                sequence_number,
                content_type, // Use the exact record header content type for AAD
                version_major,
                version_minor,
                record_length as u16,
                cipher_suite,
            ) {
                Ok(plaintext) => {
                    println!("[TLS13_HANDSHAKE] ✅ Successfully decrypted record!");
                    println!("[TLS13_HANDSHAKE] Plaintext length: {}", plaintext.len());

                    if !plaintext.is_empty() {
                        println!(
                            "[TLS13_HANDSHAKE] Plaintext preview: {}",
                            hex::encode(&plaintext[..std::cmp::min(32, plaintext.len())])
                        );
                    }

                    // Create a decrypted record
                    let decrypted_record = TlsRecord {
                        content_type: TlsContentType::from(content_type),
                        version_major,
                        version_minor,
                        length: plaintext.len() as u16,
                        payload: plaintext,
                    };
                    decrypted_records.push(decrypted_record);
                }
                Err(e) => {
                    println!("[TLS13_HANDSHAKE] ❌ Failed to decrypt record: {}", e);
                    // For debugging, continue processing other records
                }
            }

            sequence_number += 1;
        }

        records_processed += 1;

        // Simple heuristic: stop after processing a few records for initial testing
        if records_processed >= 5 {
            println!(
                "[TLS13_HANDSHAKE] Stopping after processing {} records for testing",
                records_processed
            );
            break;
        }
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
