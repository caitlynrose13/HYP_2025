// TLS 1.2 handshake message construction and parsing

use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys;
use crate::services::tls_parser::{
    Extension, HandshakeMessageType, ServerHelloParsed, ServerKeyExchangeParsed, TLS_1_2_MAJOR,
    TLS_1_2_MINOR, TlsContentType, TlsParserError, TlsRecord, TlsVersion, parse_certificate_list,
    parse_handshake_messages, parse_server_hello_content, parse_server_key_exchange_content,
    parse_tls_alert, parse_tls_record,
};
use std::io::{Cursor, Read};
use std::net::TcpStream;
use std::time::Duration;

// ===========================
// CORE MESSAGE BUILDER

pub struct HandshakeMessage;

impl HandshakeMessage {
    /// Build a TLS record with the given content type, version, and payload
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
}

// =========================
// CLIENT HELLO CONSTRUCTION

impl HandshakeMessage {
    /// Build a TLS 1.2 ClientHello message with SNI and modern extensions
    pub fn build_client_hello_with_random_and_key_share(
        domain: &str,
        _record_tls_version: TlsVersion,
        client_random: &[u8; 32],
        _client_ephemeral_public_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        let mut client_hello_payload = Vec::new();

        // TLS Version (1.2)
        client_hello_payload.extend_from_slice(&[TLS_1_2_MAJOR, TLS_1_2_MINOR]);

        // Client Random
        client_hello_payload.extend_from_slice(client_random);

        // Session ID (empty)
        client_hello_payload.push(0u8);

        // Cipher Suites - Add supported TLS 1.2 cipher suites
        let cipher_suites: Vec<[u8; 2]> = vec![
            // Modern cipher suites (preferred - will get A grades)
            [0xc0, 0x2f], // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            [0xc0, 0x30], // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            [0xc0, 0x2b], // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            [0xc0, 0x2c], // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            [0xcc, 0xa8], // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            [0xcc, 0xa9], // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        ];

        let mut cipher_suites_bytes = Vec::new();
        for cs in &cipher_suites {
            cipher_suites_bytes.extend_from_slice(cs);
        }
        client_hello_payload.extend_from_slice(&((cipher_suites_bytes.len() as u16).to_be_bytes()));
        client_hello_payload.extend_from_slice(&cipher_suites_bytes);

        // Compression Methods (null only)
        client_hello_payload.push(1u8); // 1 compression method
        client_hello_payload.push(0u8); // null compression

        // Extensions
        let extensions_bytes = Self::build_client_hello_extensions(domain)?;
        client_hello_payload.extend_from_slice(&(extensions_bytes.len() as u16).to_be_bytes());
        client_hello_payload.extend_from_slice(&extensions_bytes);

        // Build handshake message
        let raw_handshake =
            Self::build_handshake_message(HandshakeMessageType::ClientHello, client_hello_payload);

        // Build TLS record
        let full_record = Self::build_tls_record(
            TlsContentType::Handshake,
            TlsVersion::TLS1_2,
            raw_handshake.clone(),
        );

        Ok((full_record, raw_handshake))
    }

    /// Build extensions for ClientHello
    fn build_client_hello_extensions(domain: &str) -> Result<Vec<u8>, TlsError> {
        let mut extensions_bytes = Vec::new();

        // 1. Renegotiation Info (0xff01)
        let reneg_info_payload = [0x00];
        extensions_bytes.extend_from_slice(&Extension::new(0xff01, &reneg_info_payload).to_bytes());

        // 2. Server Name Indication (0x0000)
        extensions_bytes.extend_from_slice(&Self::build_sni_extension(domain));

        // 3. Supported Groups (0x000a)
        extensions_bytes.extend_from_slice(&Self::build_supported_groups_extension());

        // 4. Signature Algorithms (0x000d)
        extensions_bytes.extend_from_slice(&Self::build_signature_algorithms_extension());

        // 5. Supported Versions (0x002b) - TLS 1.2 only
        let supported_versions = [0x02, 0x03, 0x03]; // Only TLS 1.2
        extensions_bytes.extend_from_slice(&Extension::new(0x002b, &supported_versions).to_bytes());

        Ok(extensions_bytes)
    }

    fn build_sni_extension(domain: &str) -> Vec<u8> {
        let sni_hostname = domain.as_bytes();
        let mut sni_payload = Vec::new();
        sni_payload.extend_from_slice(&(sni_hostname.len() as u16 + 3).to_be_bytes());
        sni_payload.push(0x00); // name type: host_name
        sni_payload.extend_from_slice(&(sni_hostname.len() as u16).to_be_bytes());
        sni_payload.extend_from_slice(sni_hostname);
        Extension::new(0x0000, &sni_payload).to_bytes()
    }

    fn build_supported_groups_extension() -> Vec<u8> {
        let mut content = Vec::new();
        let supported_groups: [[u8; 2]; 2] = [
            [0x00, 0x17], // secp256r1
            [0x00, 0x18], // secp384r1
        ];
        let list_len = (supported_groups.len() * 2) as u16;
        content.extend_from_slice(&list_len.to_be_bytes());
        for group in &supported_groups {
            content.extend_from_slice(group);
        }
        Extension::new(0x000a, &content).to_bytes()
    }

    fn build_signature_algorithms_extension() -> Vec<u8> {
        let mut extension = Vec::new();

        // Extension Type: signature_algorithms (0x000d)
        extension.extend_from_slice(&[0x00, 0x0d]);

        // Signature algorithms list (include RSA-PSS!)
        let algorithms = vec![
            // RSA-PSS algorithms (essential for modern servers)
            0x08, 0x04, // rsa_pss_rsae_sha256 ← This is what eve.uj.ac.za needs!
            0x08, 0x05, // rsa_pss_rsae_sha384
            0x08, 0x06, // rsa_pss_rsae_sha512
            0x08, 0x09, // rsa_pss_pss_sha256
            0x08, 0x0a, // rsa_pss_pss_sha384
            0x08, 0x0b, // rsa_pss_pss_sha512
            // ECDSA algorithms
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x05, 0x03, // ecdsa_secp384r1_sha384
            0x06, 0x03, // ecdsa_secp521r1_sha512
            // Legacy RSA algorithms (for compatibility)
            0x04, 0x01, // rsa_pkcs1_sha256
            0x05, 0x01, // rsa_pkcs1_sha384
            0x06, 0x01, // rsa_pkcs1_sha512
        ];

        let algorithms_length = algorithms.len() as u16;

        // Extension Length (2 bytes for algorithms length + algorithms)
        let extension_length = 2 + algorithms_length;
        extension.extend_from_slice(&extension_length.to_be_bytes());

        // Algorithms Length
        extension.extend_from_slice(&algorithms_length.to_be_bytes());

        // Algorithms
        extension.extend_from_slice(&algorithms);

        extension
    }
}

// =======================
// CLIENT KEY EXCHANGE

impl HandshakeMessage {
    /// Create a ClientKeyExchange message for ECDHE
    pub fn create_client_key_exchange(
        client_ephemeral_public_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        let mut payload = Vec::new();
        payload.push(client_ephemeral_public_bytes.len() as u8); // EC point length
        payload.extend_from_slice(client_ephemeral_public_bytes);

        let raw_handshake =
            Self::build_handshake_message(HandshakeMessageType::ClientKeyExchange, payload);

        let full_record = Self::build_tls_record(
            TlsContentType::Handshake,
            TlsVersion::TLS1_2,
            raw_handshake.clone(),
        );

        Ok((full_record, raw_handshake))
    }
}

// =======================================
// CONTROL MESSAGES

impl HandshakeMessage {
    /// Create a ChangeCipherSpec message
    pub fn create_change_cipher_spec() -> Vec<u8> {
        Self::build_tls_record(
            TlsContentType::ChangeCipherSpec,
            TlsVersion::TLS1_2,
            vec![0x01],
        )
    }

    /// Build a ChangeCipherSpec TLS record (alternative method)
    pub fn build_change_cipher_spec_record() -> Vec<u8> {
        Self::create_change_cipher_spec()
    }

    /// Create a Finished message
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

        let handshake_message =
            Self::build_handshake_message(HandshakeMessageType::Finished, finished_data);

        Ok(Self::build_tls_record(
            TlsContentType::Handshake,
            tls_version,
            handshake_message,
        ))
    }
}

// =================================
// MESSAGE PARSING

impl HandshakeMessage {
    /// Parse ServerHello from handshake messages
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

    /// Parse ServerKeyExchange from handshake messages
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
}

// ======================
// HELPER FUNCTIONS

impl HandshakeMessage {
    /// Build a handshake message with type, length, and payload
    fn build_handshake_message(msg_type: HandshakeMessageType, payload: Vec<u8>) -> Vec<u8> {
        let mut message = Vec::new();
        message.push(msg_type.as_u8());
        let len_bytes = (payload.len() as u32).to_be_bytes();
        message.extend_from_slice(&len_bytes[1..4]); // 3-byte length
        message.extend_from_slice(&payload);
        message
    }
}

// ==========================================================
// SERVER RESPONSE HANDLING

/// Handle the complete server hello flight (ServerHello + Certificate + ServerKeyExchange + ServerHelloDone)
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
    let mut cursor = Cursor::new(server_response_buffer);

    let mut server_hello: Option<ServerHelloParsed> = None;
    let mut certificates: Option<Vec<Vec<u8>>> = None;
    let mut server_key_exchange: Option<ServerKeyExchangeParsed> = None;
    let mut server_hello_done_received = false;
    let mut records_processed = 0;

    // Parse records until ServerHelloDone or limit reached
    while let Some(record) = parse_tls_record(&mut cursor)? {
        records_processed += 1;

        match record.content_type {
            TlsContentType::Handshake => {
                let handshake_messages = parse_handshake_messages(&record.payload)?;
                for msg in handshake_messages {
                    handshake_transcript_hash.extend_from_slice(&msg.raw_bytes);

                    match msg.msg_type {
                        HandshakeMessageType::ServerHello => {
                            if server_hello.is_some() {
                                return Err(TlsError::ParserError(
                                    TlsParserError::MalformedMessage(
                                        "Duplicate ServerHello message received".to_string(),
                                    ),
                                ));
                            }
                            server_hello = Some(parse_server_hello_content(&msg.payload)?);
                        }
                        HandshakeMessageType::Certificate => {
                            if certificates.is_some() {
                                return Err(TlsError::ParserError(
                                    TlsParserError::MalformedMessage(
                                        "Duplicate Certificate message received".to_string(),
                                    ),
                                ));
                            }
                            certificates = Some(parse_certificate_list(&msg.payload)?);
                        }
                        HandshakeMessageType::ServerKeyExchange => {
                            if server_key_exchange.is_some() {
                                return Err(TlsError::ParserError(
                                    TlsParserError::MalformedMessage(
                                        "Duplicate ServerKeyExchange message received".to_string(),
                                    ),
                                ));
                            }
                            server_key_exchange =
                                Some(parse_server_key_exchange_content(&msg.payload)?);
                        }
                        HandshakeMessageType::ServerHelloDone => {
                            server_hello_done_received = true;
                            break;
                        }
                        _ => {}
                    }
                }
            }
            TlsContentType::Alert => match parse_tls_alert(&record.payload) {
                Ok(alert) => {
                    return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
                        format!(
                            "Received {} Alert: {}",
                            alert.get_level_name(),
                            alert.get_description_name()
                        ),
                    )));
                }
                Err(_) => {
                    return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
                        "Received Alert record during Server Hello Flight (failed to parse)"
                            .to_string(),
                    )));
                }
            },
            TlsContentType::ChangeCipherSpec => {
                // Ignore during server hello flight
            }
            _ => {}
        }

        if server_hello_done_received || (records_processed >= 2 && server_hello.is_some()) {
            break;
        }
    }

    let sh_parsed = server_hello.ok_or(TlsError::ParserError(TlsParserError::MalformedMessage(
        "ServerHello not received".to_string(),
    )))?;

    let certs = certificates.unwrap_or_default();

    Ok((sh_parsed, certs, server_key_exchange))
}

// ============================================================================
// RECORD READING

/// Read a single TLS record from a stream
pub fn read_tls_record<R: Read>(
    reader: &mut R,
    _tls_version: TlsVersion,
) -> Result<TlsRecord, TlsError> {
    use std::io::{self, ErrorKind};

    // Read 5-byte header
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

    let record = TlsRecord {
        content_type: TlsContentType::from(content_type),
        version_major: version.0,
        version_minor: version.1,
        length: length as u16,
        payload,
    };

    // Handle alerts (optional debug logging removed)
    if record.content_type == TlsContentType::Alert {
        let _ = parse_tls_alert(&record.payload); // Parse but don't log
    }

    Ok(record)
}

// Add this to your signature algorithm parsing
pub fn parse_signature_algorithm(sig_alg: &[u8; 2]) -> Result<String, TlsError> {
    match sig_alg {
        [0x08, 0x04] => Ok("rsa_pss_rsae_sha256".to_string()),
        [0x08, 0x05] => Ok("rsa_pss_rsae_sha384".to_string()),
        [0x08, 0x06] => Ok("rsa_pss_rsae_sha512".to_string()),
        [0x04, 0x03] => Ok("ecdsa_secp256r1_sha256".to_string()),
        [0x04, 0x01] => Ok("rsa_pkcs1_sha256".to_string()),
        [0x05, 0x01] => Ok("rsa_pkcs1_sha384".to_string()),
        _ => Err(TlsError::HandshakeFailed(format!(
            "Unsupported signature algorithm: 0x{:02x}{:02x}",
            sig_alg[0], sig_alg[1]
        ))),
    }
}

// In your handshake parsing, add timeout and retry logic
pub fn read_server_response_with_retry(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<Vec<u8>, TlsError> {
    stream.set_read_timeout(Some(timeout))?;
    let mut buffer = Vec::new();
    let mut temp_buffer = [0u8; 4096];

    // Read multiple records if needed
    loop {
        match stream.read(&mut temp_buffer) {
            Ok(0) => break, // End of stream
            Ok(n) => {
                buffer.extend_from_slice(&temp_buffer[..n]);
                // Check if we have complete records
                if buffer.len() >= 5 {
                    let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
                    if buffer.len() >= 5 + record_len {
                        break; // We have at least one complete record
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout - return what we have
                break;
            }
            Err(e) => return Err(TlsError::IoError(e)),
        }
    }

    Ok(buffer)
}

// Update your build_client_hello to include ChaCha20 cipher suites:
pub fn build_client_hello(domain: &str) -> Vec<u8> {
    let mut client_hello_payload = Vec::new();

    // TLS Version (1.2)
    client_hello_payload.extend_from_slice(&[TLS_1_2_MAJOR, TLS_1_2_MINOR]);

    // Client Random
    client_hello_payload.extend_from_slice(&[0u8; 32]);

    // Session ID (empty)
    client_hello_payload.push(0u8);

    // Cipher Suites (fix the data structure)
    let cipher_suites: Vec<[u8; 2]> = vec![
        // TLS 1.3 cipher suites
        [0x13, 0x01], // TLS_AES_128_GCM_SHA256
        [0x13, 0x02], // TLS_AES_256_GCM_SHA384
        [0x13, 0x03], // TLS_CHACHA20_POLY1305_SHA256
        // TLS 1.2 cipher suites (including ChaCha20)
        [0xC0, 0x2F], // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        [0xC0, 0x30], // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        [0xCC, 0xA8], // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ← Fix: array instead of individual bytes
        [0xCC, 0xA9], // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ← Fix: array instead of individual bytes
        [0xC0, 0x2B], // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        [0xC0, 0x2C], // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    ];

    let mut cipher_suites_bytes = Vec::new();
    for cs in &cipher_suites {
        cipher_suites_bytes.extend_from_slice(cs); // ← Now cs is &[u8; 2] which implements AsRef<[u8]>
    }
    client_hello_payload.extend_from_slice(&((cipher_suites_bytes.len() as u16).to_be_bytes()));
    client_hello_payload.extend_from_slice(&cipher_suites_bytes);

    // Compression Methods (null only)
    client_hello_payload.push(1u8); // 1 compression method
    client_hello_payload.push(0u8); // null compression

    // Extensions
    let extensions_bytes = HandshakeMessage::build_client_hello_extensions(domain).unwrap();
    client_hello_payload.extend_from_slice(&(extensions_bytes.len() as u16).to_be_bytes());
    client_hello_payload.extend_from_slice(&extensions_bytes);

    // Build handshake message
    let raw_handshake = HandshakeMessage::build_handshake_message(
        HandshakeMessageType::ClientHello,
        client_hello_payload,
    );

    // Build TLS record
    HandshakeMessage::build_tls_record(TlsContentType::Handshake, TlsVersion::TLS1_2, raw_handshake)
}
