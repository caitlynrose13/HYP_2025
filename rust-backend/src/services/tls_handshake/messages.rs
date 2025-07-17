use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys;
use crate::services::tls_parser::Extension;
use crate::services::tls_parser::HandshakeMessageType;
use crate::services::tls_parser::TlsRecord;
use crate::services::tls_parser::{
    ServerHelloParsed, ServerKeyExchangeParsed, TLS_1_2_MAJOR, TLS_1_2_MINOR, TlsContentType,
    TlsParserError, TlsVersion, parse_certificate_list, parse_handshake_messages,
    parse_server_hello_content, parse_server_key_exchange_content, parse_tls_alert,
    parse_tls_record,
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

    pub fn build_client_hello_with_random_and_key_share(
        domain: &str,
        _record_tls_version: TlsVersion,
        client_random: &[u8; 32],
        _client_ephemeral_public_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        let mut client_hello_payload = Vec::new();

        // TLS Version
        client_hello_payload.extend_from_slice(&[TLS_1_2_MAJOR, TLS_1_2_MINOR]);

        //  Client Random
        client_hello_payload.extend_from_slice(client_random);

        // Session ID
        client_hello_payload.push(0u8);

        //Cipher Suites
        let cipher_suites: Vec<[u8; 2]> = vec![
            [0xc0, 0x2f], // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            [0xc0, 0x30], // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ];
        let mut cipher_suites_bytes = Vec::new();
        for cs in &cipher_suites {
            cipher_suites_bytes.extend_from_slice(cs);
        }
        client_hello_payload.extend_from_slice(&((cipher_suites_bytes.len() as u16).to_be_bytes()));
        client_hello_payload.extend_from_slice(&cipher_suites_bytes);

        client_hello_payload.push(1u8); // 1 compression method
        client_hello_payload.push(0u8); // null compression

        let mut extensions_bytes = Vec::new();

        //  renegotiation_info (0xff01), payload 00
        let reneg_info_payload = [0x00];
        extensions_bytes.extend_from_slice(&Extension::new(0xff01, &reneg_info_payload).to_bytes());

        //  server_name (SNI, 0x0000) - Essential for modern servers
        let sni_hostname = domain.as_bytes();
        let mut sni_payload = Vec::new();
        sni_payload.extend_from_slice(&(sni_hostname.len() as u16 + 3).to_be_bytes());
        sni_payload.push(0x00); // name type: host_name
        sni_payload.extend_from_slice(&(sni_hostname.len() as u16).to_be_bytes());
        sni_payload.extend_from_slice(sni_hostname);
        extensions_bytes.extend_from_slice(&Extension::new(0x0000, &sni_payload).to_bytes());

        // 3. supported_groups (0x000a) - Essential for ECDHE
        let mut supported_groups_content = Vec::new();
        let supported_groups: [[u8; 2]; 2] = [
            [0x00, 0x17], // secp256r1
            [0x00, 0x18], // secp384r1
        ];
        let supported_groups_list_len = (supported_groups.len() * 2) as u16;
        supported_groups_content.extend_from_slice(&supported_groups_list_len.to_be_bytes());
        for group in &supported_groups {
            supported_groups_content.extend_from_slice(group);
        }
        extensions_bytes
            .extend_from_slice(&Extension::new(0x000a, &supported_groups_content).to_bytes());

        // 4. signature_algorithms (0x000d) - Essential for modern servers
        let mut sig_algs_content = Vec::new();
        let sig_algs: [[u8; 2]; 4] = [
            [0x04, 0x01], // ecdsa_secp256r1_sha256 (legacy)
            [0x05, 0x01], // ecdsa_secp384r1_sha384 (legacy)
            [0x03, 0x01], // ecdsa_sha1
            [0x03, 0x02], // ecdsa_sha256
        ];
        let sig_algs_list_len = (sig_algs.len() * 2) as u16;
        sig_algs_content.extend_from_slice(&sig_algs_list_len.to_be_bytes());
        for alg in &sig_algs {
            sig_algs_content.extend_from_slice(alg);
        }
        extensions_bytes.extend_from_slice(&Extension::new(0x000d, &sig_algs_content).to_bytes());

        // 5. supported_versions (0x002b) - Explicitly restrict to TLS 1.2
        let supported_versions = [0x02, 0x03, 0x03]; // Only TLS 1.2
        extensions_bytes.extend_from_slice(&Extension::new(0x002b, &supported_versions).to_bytes());

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
            TlsVersion::TLS1_2, // Changed from TLS1_0 to TLS1_2 for real-world compatibility
            raw_client_hello_handshake_message.clone(), // Clone to put into the record
        );

        Ok((full_tls_record, raw_client_hello_handshake_message))
    }

    //CreateKeyExchange
    pub fn create_client_key_exchange(
        client_ephemeral_public_bytes: &[u8], // The public key from the initial key generation
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        let mut client_key_exchange_payload = Vec::new();
        client_key_exchange_payload.push(client_ephemeral_public_bytes.len() as u8); // EC point length
        client_key_exchange_payload.extend_from_slice(client_ephemeral_public_bytes);

        // Build the raw ClientKeyExchange handshake message (type + length + payload) [0x10][len3][payload]
        let mut raw_client_key_exchange_handshake_message = Vec::new();
        raw_client_key_exchange_handshake_message //0x10 is type of ClientKeyExchange
            .push(HandshakeMessageType::ClientKeyExchange.as_u8());
        let handshake_len_bytes = (client_key_exchange_payload.len() as u32).to_be_bytes();
        raw_client_key_exchange_handshake_message.extend_from_slice(&handshake_len_bytes[1..4]);
        raw_client_key_exchange_handshake_message.extend_from_slice(&client_key_exchange_payload);

        // Build the full TLS record  [ContentType][Version][Length][Handshake Message]
        let full_tls_record = Self::build_tls_record(
            TlsContentType::Handshake,
            TlsVersion::TLS1_2,                                //need to update 1.3
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

    //extract the key exchange message from the server response
    pub fn parse_server_key_exchange_message(
        input: &[u8],
    ) -> Result<ServerKeyExchangeParsed, TlsError> {
        let handshake_messages = parse_handshake_messages(input)?;
        for msg in handshake_messages {
            //if serverkeyexchange is found, parse the content
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
            TlsVersion::TLS1_2,
            vec![0x01],
        )
    }

    pub fn create_finished(
        client_handshake_messages: &[u8],
        master_secret: &[u8],
        tls_version: TlsVersion,
        hash_algorithm: crate::services::tls_parser::HashAlgorithm,
    ) -> Result<Vec<u8>, TlsError> {
        let finished_data = keys::calculate_verify_data(
            master_secret,
            client_handshake_messages,
            b"client finished",
            hash_algorithm,
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
    _tls_version: TlsVersion,
    handshake_transcript_hash: &mut Vec<u8>,
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

        match record.content_type {
            TlsContentType::Handshake => {
                // Parse multiple handshake messages
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
                match parse_tls_alert(&record.payload) {
                    Ok(alert) => {
                        println!("  {}", alert.to_string());
                        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
                            format!(
                                "Received {} Alert: {}",
                                alert.get_level_name(),
                                alert.get_description_name()
                            ),
                        )));
                    }
                    Err(e) => {
                        println!("  Failed to parse alert: {:?}", e);
                        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
                            "Received Alert record during Server Hello Flight (failed to parse)"
                                .to_string(),
                        )));
                    }
                }
            }
            _ => {
                println!(
                    "  Unhandled TLS Content Type: {:?} in Server Hello Flight",
                    record.content_type
                );
            }
        }

        // Stop parsing ifhave ServerHelloDone or if  processed enough records
        if server_hello_done_received {
            break;
        }

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
                return Err(TlsError::IoError(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Failed to read full TLS record header",
                )));
            }
            Ok(n) => {
                bytes_read += n;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(TlsError::IoError(e));
            }
        }
    }

    let content_type = header[0];
    let version = (header[1], header[2]);
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;

    if length > 16384 {
        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
            format!("TLS record length {} exceeds max allowed (16384)", length),
        )));
    }

    let mut payload = vec![0u8; length];
    bytes_read = 0;
    while bytes_read < length {
        match reader.read(&mut payload[bytes_read..]) {
            Ok(0) => {
                return Err(TlsError::IoError(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Failed to read full TLS record payload",
                )));
            }
            Ok(n) => {
                bytes_read += n;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(TlsError::IoError(e));
            }
        }
    }

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
                println!("Failed to parse alert: {:?}", e);
            }
        }
    }

    Ok(record)
}
