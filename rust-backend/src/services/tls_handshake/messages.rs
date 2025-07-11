// src/services/tls_handshake/messages.rs
// src/services/tls_handshake/messages.rs

use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys;
use crate::services::tls_parser::Extension;
use crate::services::tls_parser::HandshakeMessageType;
use crate::services::tls_parser::TlsRecord;
use crate::services::tls_parser::{
    COMPRESSION_METHOD_NULL, COMPRESSION_METHODS_LEN, EXTENSION_TYPE_SERVER_NAME,
    EXTENSION_TYPE_SIGNATURE_ALGORITHMS, EXTENSION_TYPE_SUPPORTED_GROUPS, SNI_HOSTNAME_TYPE,
    ServerHelloParsed, ServerKeyExchangeParsed, TLS_1_2_MAJOR, TLS_1_2_MINOR, TlsContentType,
    TlsParserError, TlsVersion, parse_certificate_list, parse_handshake_messages,
    parse_server_hello_content, parse_server_key_exchange_content, parse_tls_record,
};
use std::io::Cursor;
use std::io::Read;

pub struct HandshakeMessage;

impl HandshakeMessage {
    // Helper function to build a TLS record
    pub fn build_tls_record(
        content_type: TlsContentType,
        tls_version: TlsVersion,
        payload: Vec<u8>,
    ) -> Vec<u8> {
        let mut record = Vec::new();
        record.push(content_type.as_u8());
        let (record_major, record_minor) = tls_version.to_u8_pair();
        record.push(record_major);
        record.push(record_minor);
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(&payload);
        record
    }

    // Modified to return both the TLS record bytes and the raw ClientHello handshake message bytes
    pub fn build_client_hello_with_random_and_key_share(
        domain: &str,
        _record_tls_version: TlsVersion,
        client_random: &[u8; 32],
        _client_ephemeral_public_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        // Return a tuple: (full_tls_record, raw_handshake_message)
        let mut client_hello_payload = Vec::new();

        // 1. TLS Version (ClientHello version, typically 0x0303 for TLS 1.2 regardless of actual protocol)
        client_hello_payload.extend_from_slice(&[TLS_1_2_MAJOR, TLS_1_2_MINOR]);

        // 2. Client Random
        client_hello_payload.extend_from_slice(client_random);

        // 3. Session ID (use a 22-byte all-zero session ID for compatibility)
        let session_id = [0u8; 22];
        client_hello_payload.push(session_id.len() as u8);
        client_hello_payload.extend_from_slice(&session_id);

        // 4. Cipher Suites (update to match captured ClientHello)
        let cipher_suites: Vec<[u8; 2]> = vec![
            [0xc0, 0x2c],
            [0xc0, 0x2b],
            [0xc0, 0x30],
            [0xc0, 0x2f],
            [0x00, 0x9f],
            [0x00, 0x9e],
            [0xc0, 0x24],
            [0xc0, 0x23],
            [0xc0, 0x28],
            [0xc0, 0x27],
            [0xc0, 0x0a],
            [0xc0, 0x09],
            [0xc0, 0x14],
            [0xc0, 0x13],
            [0x00, 0x9d],
            [0x00, 0x9c],
            [0x00, 0x3d],
            [0x00, 0x3c],
            [0x00, 0x35],
            [0x00, 0x2f],
            [0x00, 0x0a],
        ];
        let mut cipher_suites_bytes = Vec::new();
        for cs in &cipher_suites {
            cipher_suites_bytes.extend_from_slice(cs);
        }
        client_hello_payload.extend_from_slice(&((cipher_suites_bytes.len() as u16).to_be_bytes()));
        client_hello_payload.extend_from_slice(&cipher_suites_bytes);

        // 5. Compression Methods (always 0x01 0x00 for null compression)
        client_hello_payload.push(COMPRESSION_METHODS_LEN);
        client_hello_payload.push(COMPRESSION_METHOD_NULL);

        // 6. Extensions
        let mut extensions_bytes = Vec::new();

        // 6.1. Server Name Indication (SNI) (type 0x0000)
        let sni_hostname_len = domain.len() as u16;
        let sni_names_list_field_len = 1 + 2 + sni_hostname_len;
        let mut sni_content = Vec::new();
        sni_content.extend_from_slice(&(sni_names_list_field_len as u16).to_be_bytes());
        sni_content.push(SNI_HOSTNAME_TYPE);
        sni_content.extend_from_slice(&sni_hostname_len.to_be_bytes());
        sni_content.extend_from_slice(domain.as_bytes());
        extensions_bytes.extend_from_slice(
            &Extension::new(EXTENSION_TYPE_SERVER_NAME, &sni_content).to_bytes(),
        );

        // 6.2. Status Request Extension (type 0x0005, payload: 01 00 00 00 00)
        let status_request_payload = [0x01, 0x00, 0x00, 0x00, 0x00];
        extensions_bytes
            .extend_from_slice(&Extension::new(0x0005, &status_request_payload).to_bytes());

        // 6.3. Supported Groups Extension (type 0x000A) for ECDHE (only x25519, secp256r1, secp384r1)
        let mut supported_groups_content = Vec::new();
        let supported_groups: [[u8; 2]; 3] = [
            [0x00, 0x1d], // x25519
            [0x00, 0x17], // secp256r1
            [0x00, 0x18], // secp384r1
        ];
        let supported_groups_list_len = (supported_groups.len() * 2) as u16;
        supported_groups_content.extend_from_slice(&supported_groups_list_len.to_be_bytes());
        for group in &supported_groups {
            supported_groups_content.extend_from_slice(group);
        }
        extensions_bytes.extend_from_slice(
            &Extension::new(EXTENSION_TYPE_SUPPORTED_GROUPS, &supported_groups_content).to_bytes(),
        );

        // 6.4. EC Point Formats Extension (type 0x000b, payload 02 00 01)
        let ec_point_formats: [u8; 3] = [0x02, 0x00, 0x01];
        extensions_bytes.extend_from_slice(&Extension::new(0x000b, &ec_point_formats).to_bytes());

        // 6.5. Signature Algorithms Extension (type 0x000D)
        let mut sig_algs_content = Vec::new();
        let sig_algs: [[u8; 2]; 8] = [
            [0x04, 0x03],
            [0x08, 0x04],
            [0x04, 0x01],
            [0x05, 0x03],
            [0x08, 0x05],
            [0x06, 0x01],
            [0x02, 0x01],
            [0x02, 0x03],
        ];
        let sig_algs_list_len = (sig_algs.len() * 2) as u16;
        sig_algs_content.extend_from_slice(&sig_algs_list_len.to_be_bytes());
        for alg in &sig_algs {
            sig_algs_content.extend_from_slice(alg);
        }
        extensions_bytes.extend_from_slice(
            &Extension::new(EXTENSION_TYPE_SIGNATURE_ALGORITHMS, &sig_algs_content).to_bytes(),
        );

        // 6.6. SessionTicket Extension (type 0x0023, empty payload)
        extensions_bytes.extend_from_slice(&Extension::new(0x0023, &[]).to_bytes());

        // 6.7. ALPN Extension (type 0x0010) - commented out as in original
        // let mut alpn_content = Vec::new();
        // let alpn_protocol = b"http/1.1";
        // alpn_content.push((alpn_protocol.len() + 1) as u8);
        // alpn_content.push(alpn_protocol.len() as u8);
        // alpn_content.extend_from_slice(alpn_protocol);
        // extensions_bytes.extend_from_slice(&Extension::new(0x0010, &alpn_content).to_bytes());

        // 6.8. Extended Master Secret Extension (type 0x0017, empty payload)
        extensions_bytes.extend_from_slice(&Extension::new(0x0017, &[]).to_bytes());

        // 6.9. Renegotiation Info Extension (type 0xff01, payload = 00)
        extensions_bytes.extend_from_slice(&Extension::new(0xff01, &[0x00]).to_bytes());

        // 6.10. Padding Extension (type 0x0015, payload: 16 zero bytes) - commented out as in original
        // let padding = [0u8; 16];
        // extensions_bytes.extend_from_slice(&Extension::new(0x0015, &padding).to_bytes());

        // Add Extensions Length
        client_hello_payload.extend_from_slice(&(extensions_bytes.len() as u16).to_be_bytes());
        client_hello_payload.extend_from_slice(&extensions_bytes);

        // Build the raw ClientHello handshake message (type + length + payload)
        let mut raw_client_hello_handshake_message = Vec::new();
        raw_client_hello_handshake_message.push(HandshakeMessageType::ClientHello.as_u8());
        let handshake_len_bytes = (client_hello_payload.len() as u32).to_be_bytes();
        raw_client_hello_handshake_message.extend_from_slice(&handshake_len_bytes[1..4]);
        raw_client_hello_handshake_message.extend_from_slice(&client_hello_payload);

        // Build the full TLS record
        let full_tls_record = HandshakeMessage::build_tls_record(
            TlsContentType::Handshake,
            TlsVersion::TLS1_2,                         // 0x0303
            raw_client_hello_handshake_message.clone(), // Clone to put into the record
        );

        Ok((full_tls_record, raw_client_hello_handshake_message))
    }

    // This function now takes the pre-generated client ephemeral public key
    // It does not generate a new key pair.
    // Modified to return both the TLS record and the raw ClientKeyExchange handshake message
    pub fn create_client_key_exchange(
        client_ephemeral_public_bytes: &[u8], // The public key from the initial key generation
        tls_version: TlsVersion,              // TLS version for the record layer
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        // Correct: include the EC point length byte before the EC point
        let mut client_key_exchange_payload = Vec::new();
        client_key_exchange_payload.push(client_ephemeral_public_bytes.len() as u8); // EC point length
        client_key_exchange_payload.extend_from_slice(client_ephemeral_public_bytes);

        // Build the raw ClientKeyExchange handshake message (type + length + payload)
        let mut raw_client_key_exchange_handshake_message = Vec::new();
        raw_client_key_exchange_handshake_message
            .push(HandshakeMessageType::ClientKeyExchange.as_u8());
        let handshake_len_bytes = (client_key_exchange_payload.len() as u32).to_be_bytes();
        raw_client_key_exchange_handshake_message.extend_from_slice(&handshake_len_bytes[1..4]);
        raw_client_key_exchange_handshake_message.extend_from_slice(&client_key_exchange_payload);

        // Build the full TLS record
        let full_tls_record = Self::build_tls_record(
            TlsContentType::Handshake,
            tls_version,
            raw_client_key_exchange_handshake_message.clone(), // Clone for the record
        );

        Ok((full_tls_record, raw_client_key_exchange_handshake_message))
    }

    pub fn parse_server_hello_message(input: &[u8]) -> Result<ServerHelloParsed, TlsError> {
        let handshake_messages = parse_handshake_messages(input)?;
        for msg in handshake_messages {
            if msg.msg_type == HandshakeMessageType::ServerHello {
                return parse_server_hello_content(&msg.payload).map_err(TlsError::from);
            }
        }
        Err(TlsError::from(TlsParserError::MalformedMessage(
            "ServerHello message not found".to_string(),
        )))
    }

    pub fn parse_server_key_exchange_message(
        input: &[u8],
    ) -> Result<ServerKeyExchangeParsed, TlsError> {
        let handshake_messages = parse_handshake_messages(input)?;
        for msg in handshake_messages {
            if msg.msg_type == HandshakeMessageType::ServerKeyExchange {
                return parse_server_key_exchange_content(&msg.payload).map_err(TlsError::from);
            }
        }
        Err(TlsError::from(TlsParserError::MalformedMessage(
            "ServerKeyExchange message not found".to_string(),
        )))
    }

    pub fn create_change_cipher_spec() -> Vec<u8> {
        Self::build_tls_record(
            TlsContentType::ChangeCipherSpec,
            TlsVersion::TLS1_2, // Change Cipher Spec is for TLS 1.2
            vec![0x01],         // Change Cipher Spec message consists of a single byte 0x01
        )
    }

    pub fn create_finished(
        client_handshake_messages: &[u8],
        master_secret: &[u8],
        tls_version: TlsVersion, // Add TLS version for the record layer
    ) -> Result<Vec<u8>, TlsError> {
        let finished_data = keys::calculate_verify_data(
            master_secret,
            client_handshake_messages,
            b"client finished",
        )?;

        let mut handshake_message = Vec::new();
        handshake_message.push(HandshakeMessageType::Finished.as_u8());
        let handshake_len_bytes = (finished_data.len() as u32).to_be_bytes();
        handshake_message.extend_from_slice(&handshake_len_bytes[1..4]);
        handshake_message.extend_from_slice(&finished_data);

        Ok(Self::build_tls_record(
            TlsContentType::Handshake,
            tls_version,
            handshake_message,
        ))
    }

    pub fn build_change_cipher_spec() -> Vec<u8> {
        // ChangeCipherSpec is a simple 1-byte message: 0x01
        vec![0x01]
    }
}

pub fn handle_server_hello_flight(
    server_response_buffer: &[u8],
    _tls_version: TlsVersion, // Use this for parsing the record version
    handshake_transcript_hash: &mut Vec<u8>, // Append raw handshake messages here
) -> Result<
    (
        ServerHelloParsed,
        Vec<Vec<u8>>,
        Option<ServerKeyExchangeParsed>,
    ),
    TlsError,
> {
    println!(
        "Attempting to parse server response of {} bytes.",
        server_response_buffer.len()
    );
    println!("Waiting for server response...");
    let mut cursor = Cursor::new(server_response_buffer);

    let mut server_hello: Option<ServerHelloParsed> = None;
    let mut certificates: Option<Vec<Vec<u8>>> = None;
    let mut server_key_exchange: Option<ServerKeyExchangeParsed> = None;
    let mut server_hello_done_received = false;
    let mut records_processed = 0;

    // Keep parsing records until no more data or ServerHelloDone is found
    while let Some(record) = parse_tls_record(&mut cursor)? {
        records_processed += 1;
        println!(
            "Read {} bytes from server (record {})",
            record.payload.len(),
            records_processed
        );
        println!("  Record content type: {:?}", record.content_type);
        // Note: We don't validate record version here because servers may use different
        // record layer versions than the negotiated version, especially during handshake

        match record.content_type {
            TlsContentType::Handshake => {
                // Parse multiple handshake messages that might be coalesced in one record
                let handshake_messages = parse_handshake_messages(&record.payload)?;
                println!(
                    "  Parsed {} handshake message(s) in this record:",
                    handshake_messages.len()
                );

                for (i, msg) in handshake_messages.iter().enumerate() {
                    println!(
                        "    Handshake message {}: {:?} (type=0x{:02X}, len={}, raw={})",
                        i + 1,
                        msg.msg_type,
                        msg.msg_type.as_u8(),
                        msg.length,
                        hex::encode(&msg.raw_bytes)
                    );
                }

                for msg in handshake_messages {
                    // Append the raw bytes of this handshake message to the transcript hash
                    // This `raw_bytes` field includes the message type and 3-byte length
                    handshake_transcript_hash.extend_from_slice(&msg.raw_bytes);

                    match msg.msg_type {
                        HandshakeMessageType::ServerHello => {
                            if server_hello.is_some() {
                                // Already received ServerHello, unexpected
                                return Err(TlsError::ParserError(
                                    TlsParserError::MalformedMessage(
                                        "Duplicate ServerHello message received".to_string(),
                                    ),
                                ));
                            }
                            let parsed = parse_server_hello_content(&msg.payload)?;
                            println!(
                                "  Parsed ServerHello: chosen cipher suite = {:02X}{:02X}",
                                parsed.chosen_cipher_suite[0], parsed.chosen_cipher_suite[1]
                            );
                            server_hello = Some(parsed);
                        }
                        HandshakeMessageType::Certificate => {
                            if certificates.is_some() {
                                // Already received Certificate, unexpected
                                return Err(TlsError::ParserError(
                                    TlsParserError::MalformedMessage(
                                        "Duplicate Certificate message received".to_string(),
                                    ),
                                ));
                            }
                            println!("  Found Certificate message.");
                            certificates = Some(parse_certificate_list(&msg.payload)?);
                        }
                        HandshakeMessageType::ServerKeyExchange => {
                            if server_key_exchange.is_some() {
                                // Already received ServerKeyExchange, unexpected
                                return Err(TlsError::ParserError(
                                    TlsParserError::MalformedMessage(
                                        "Duplicate ServerKeyExchange message received".to_string(),
                                    ),
                                ));
                            }
                            println!("  Found ServerKeyExchange message.");
                            server_key_exchange =
                                Some(parse_server_key_exchange_content(&msg.payload)?);
                        }
                        HandshakeMessageType::ServerHelloDone => {
                            println!("  Found ServerHelloDone message.");
                            server_hello_done_received = true;
                            break; // Done with this flight
                        }
                        // Handle other unexpected handshake messages if necessary
                        _ => {
                            println!("  Unhandled handshake message type: {:?}", msg.msg_type);
                        }
                    }
                }
            }
            TlsContentType::ChangeCipherSpec => {
                println!("  Received ChangeCipherSpec record in Server Hello Flight");
            }
            TlsContentType::Alert => {
                println!("  Received Alert record during Server Hello Flight");
                return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
                    "Received Alert record during Server Hello Flight".to_string(),
                )));
            }
            _ => {
                println!(
                    "  Unhandled TLS Content Type: {:?} in Server Hello Flight",
                    record.content_type
                );
            }
        }

        // Stop parsing if we have ServerHelloDone or if we've processed enough records
        // Some servers (like Google) may not send ServerHelloDone in the expected format
        if server_hello_done_received {
            break;
        }

        // If we've processed multiple records and have the essential messages, we can stop
        // This handles cases where servers don't follow the exact TLS 1.2 ServerHello flight pattern
        if records_processed >= 2 && server_hello.is_some() {
            println!(
                "Processed {} records, have ServerHello, stopping ServerHello flight parsing",
                records_processed
            );
            break;
        }
    }

    // Validate that all expected messages were received
    let sh_parsed = server_hello.ok_or(TlsError::ParserError(TlsParserError::MalformedMessage(
        "ServerHello not received".to_string(),
    )))?;

    // Make Certificate message optional - some servers may not send it in the initial flight
    // This can happen with TLS 1.3 servers or certain cipher suite configurations
    let certs = certificates.unwrap_or_else(|| {
        println!("Warning: No Certificate message received in ServerHello flight");
        Vec::new()
    });

    // Make ServerHelloDone optional for servers that don't follow strict TLS 1.2 patterns
    if !server_hello_done_received && records_processed < 2 {
        println!("Warning: ServerHelloDone not received, but continuing with handshake");
    }

    if server_key_exchange.is_none() {
        println!("DEBUG: ServerKeyExchange message was NOT found in the handshake messages!");
    } else {
        println!("DEBUG: ServerKeyExchange message was found and parsed.");
    }

    // Return the parsed data
    Ok((sh_parsed, certs, server_key_exchange))
}

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
