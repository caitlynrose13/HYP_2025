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

    pub fn build_client_hello_with_random_and_key_share(
        domain: &str,
        record_tls_version: TlsVersion,
        client_random: &[u8; 32],
        client_ephemeral_public_bytes: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
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
        // The length of the ServerNameList structure: 1 (name type) + 2 (hostname length) + hostname bytes
        let sni_names_list_field_len = 1 + 2 + sni_hostname_len;
        let mut sni_content = Vec::new();
        // Add the length of the ServerNameList structure (2 bytes)
        sni_content.extend_from_slice(&(sni_names_list_field_len as u16).to_be_bytes());
        // Add the NameType
        sni_content.push(SNI_HOSTNAME_TYPE);
        // Add the HostName.length
        sni_content.extend_from_slice(&sni_hostname_len.to_be_bytes());
        // Add the actual HostName bytes
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
            [0x04, 0x03], // ecdsa_secp256r1_sha256
            [0x08, 0x04], // rsa_pss_rsae_sha256
            [0x04, 0x01], // rsa_pkcs1_sha256
            [0x05, 0x03], // ecdsa_secp384r1_sha384
            [0x08, 0x05], // rsa_pss_rsae_sha512
            [0x06, 0x01], // rsa_pkcs1_sha512
            [0x02, 0x01], // rsa_pkcs1_sha1
            [0x02, 0x03], // ecdsa_sha1
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

        // 6.7. ALPN Extension (type 0x0010)
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

        // 6.10. Padding Extension (type 0x0015, payload: 16 zero bytes)
        // let padding = [0u8; 16];
        // extensions_bytes.extend_from_slice(&Extension::new(0x0015, &padding).to_bytes());

        // Add Extensions Length
        client_hello_payload.extend_from_slice(&(extensions_bytes.len() as u16).to_be_bytes());
        client_hello_payload.extend_from_slice(&extensions_bytes);

        // Final Handshake Message construction
        let mut handshake_message = Vec::new();
        handshake_message.push(HandshakeMessageType::ClientHello.as_u8());
        // Handshake message length (3 bytes, excludes the 1-byte type and 3-byte length itself)
        let handshake_len_bytes = (client_hello_payload.len() as u32).to_be_bytes();
        handshake_message.extend_from_slice(&handshake_len_bytes[1..4]);
        handshake_message.extend_from_slice(&client_hello_payload);

        // TLS Record Protocol Layer: set record version to 0x0303 (TLS 1.2) for compatibility
        Ok(HandshakeMessage::build_tls_record(
            TlsContentType::Handshake,
            TlsVersion::TLS1_2, // 0x0303
            handshake_message,
        ))
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

    // This function now takes the pre-generated client ephemeral public key
    // It does not generate a new key pair.
    pub fn create_client_key_exchange(
        client_ephemeral_public_bytes: &[u8], // The public key from the initial key generation
        tls_version: TlsVersion,              // TLS version for the record layer
    ) -> Result<Vec<u8>, TlsError> {
        let client_key_exchange_payload = client_ephemeral_public_bytes.to_vec();

        let mut handshake_message = Vec::new();
        handshake_message.push(HandshakeMessageType::ClientKeyExchange.as_u8());
        let handshake_len_bytes = (client_key_exchange_payload.len() as u32).to_be_bytes();
        handshake_message.extend_from_slice(&handshake_len_bytes[1..4]);
        handshake_message.extend_from_slice(&client_key_exchange_payload);

        Ok(Self::build_tls_record(
            TlsContentType::Handshake,
            tls_version,
            handshake_message,
        ))
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
    tls_version: TlsVersion, // Use this for parsing the record version
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

    // Keep parsing records until no more data or ServerHelloDone is found
    while let Some(record) = parse_tls_record(&mut cursor)? {
        println!("Read {} bytes from server", record.payload.len());
        // Note: We don't validate record version here because servers may use different
        // record layer versions than the negotiated version, especially during handshake

        match record.content_type {
            TlsContentType::Handshake => {
                // Parse multiple handshake messages that might be coalesced in one record
                let handshake_messages = parse_handshake_messages(&record.payload)?;

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
                            server_hello = Some(parse_server_hello_content(&msg.payload)?);
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
                            server_key_exchange =
                                Some(parse_server_key_exchange_content(&msg.payload)?);
                        }
                        HandshakeMessageType::ServerHelloDone => {
                            server_hello_done_received = true;
                            break; // Done with this flight
                        }
                        // Handle other unexpected handshake messages if necessary
                        _ => {
                            // For simplicity, we'll ignore other handshake messages for now
                            // (e.g., NewSessionTicket, HelloRequest)
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "Warning: Unhandled Handshake Message Type: {:?} in Server Hello Flight",
                                msg.msg_type
                            );
                        }
                    }
                }
            }
            TlsContentType::ChangeCipherSpec => {
                // This is not typically part of the Server Hello flight, but can sometimes
                // be sent immediately before the Finished message in TLS 1.2 if the server
                // immediately transitions to encrypted data. We'll allow it but not expect it.
                #[cfg(debug_assertions)]
                eprintln!("Warning: Received ChangeCipherSpec record in Server Hello Flight");
            }
            TlsContentType::Alert => {
                // An alert record indicates an error or warning
                return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
                    "Received Alert record during Server Hello Flight".to_string(),
                )));
            }
            _ => {
                // For simplicity, ignore other content types like ApplicationData for now
                #[cfg(debug_assertions)]
                eprintln!(
                    "Warning: Unhandled TLS Content Type: {:?} in Server Hello Flight",
                    record.content_type
                );
            }
        }
        if server_hello_done_received {
            break;
        }
    }

    // Validate that all expected messages were received
    let sh_parsed = server_hello.ok_or(TlsError::ParserError(TlsParserError::MalformedMessage(
        "ServerHello not received".to_string(),
    )))?;
    let certs = certificates.ok_or(TlsError::ParserError(TlsParserError::MalformedMessage(
        "Certificate message not received".to_string(),
    )))?;

    if !server_hello_done_received {
        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
            "ServerHelloDone not received or flight incomplete".to_string(),
        )));
    }

    // Return the parsed data
    Ok((sh_parsed, certs, server_key_exchange))
}

pub fn read_tls_record<R: Read>(
    reader: &mut R,
    _tls_version: TlsVersion,
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
