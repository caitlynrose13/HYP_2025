// src/services/tls_handshake/messages.rs

use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys;
use crate::services::tls_parser::{
    COMPRESSION_METHOD_NULL, COMPRESSION_METHODS_LEN, EXTENSION_TYPE_KEY_SHARE,
    EXTENSION_TYPE_SERVER_NAME, EXTENSION_TYPE_SIGNATURE_ALGORITHMS,
    EXTENSION_TYPE_SUPPORTED_GROUPS, EXTENSION_TYPE_SUPPORTED_VERSIONS, Extension,
    HandshakeMessageType, NamedGroup, SESSION_ID_LEN_EMPTY, SIG_ALG_ECDSA_SECP256R1_SHA256,
    SIG_ALG_RSA_PKCS1_SHA256, SIG_ALG_RSA_PSS_RSAE_SHA256, SIG_ALG_RSA_PSS_RSAE_SHA512,
    SNI_HOSTNAME_TYPE, ServerHelloParsed, ServerKeyExchangeParsed, TLS_1_2_MAJOR, TLS_1_2_MINOR,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TlsContentType, TlsParserError, TlsVersion,
    parse_handshake_messages, parse_server_hello_content, parse_server_key_exchange_content,
};
use std::io::Cursor;
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

        // 3. Session ID (empty for new connection)
        client_hello_payload.push(SESSION_ID_LEN_EMPTY);

        // 4. Cipher Suites (using only the single preferred cipher)
        let supported_cipher_suite = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        let cipher_suites_bytes = vec![supported_cipher_suite.id[0], supported_cipher_suite.id[1]];
        client_hello_payload.extend_from_slice(&((cipher_suites_bytes.len() as u16).to_be_bytes()));
        client_hello_payload.extend_from_slice(&cipher_suites_bytes);

        // 5. Compression Methods (always 0x01 0x00 for null compression)
        client_hello_payload.push(COMPRESSION_METHODS_LEN);
        client_hello_payload.push(COMPRESSION_METHOD_NULL);

        // 6. Extensions
        let mut extensions_bytes = Vec::new();

        // 6.1. Server Name Indication (SNI) (type 0x0000)
        let sni_hostname_len = domain.len() as u16;
        let sni_list_len = sni_hostname_len + 5; // Type (1 byte) + Length of HostName (2 bytes) + HostName (domain.len())

        let mut sni_content = Vec::new();
        sni_content.extend_from_slice(&sni_list_len.to_be_bytes()); // Overall list length
        sni_content.push(SNI_HOSTNAME_TYPE); // ServerNameType: host_name (0)
        sni_content.extend_from_slice(&sni_hostname_len.to_be_bytes()); // HostName Length
        sni_content.extend_from_slice(domain.as_bytes());
        extensions_bytes.extend_from_slice(
            &Extension::new(EXTENSION_TYPE_SERVER_NAME, &sni_content).to_bytes(),
        );

        // 6.2. Supported Groups Extension (type 0x000A) for ECDHE
        let mut supported_groups_content = Vec::new();
        let supported_groups_list_len =
            (NamedGroup::P256.as_bytes().len() + NamedGroup::P384.as_bytes().len()) as u16;
        supported_groups_content.extend_from_slice(&supported_groups_list_len.to_be_bytes()); // Length of group list
        supported_groups_content.extend_from_slice(&NamedGroup::P256.as_bytes()); // P-256
        supported_groups_content.extend_from_slice(&NamedGroup::P384.as_bytes()); // P-384
        extensions_bytes.extend_from_slice(
            &Extension::new(EXTENSION_TYPE_SUPPORTED_GROUPS, &supported_groups_content).to_bytes(),
        );

        // 6.3. Key Share Extension (type 0x0033) for ECDHE/TLS 1.3
        let key_exchange_len = client_ephemeral_public_bytes.len() as u16;
        let key_share_entry_len = 2 + 2 + key_exchange_len; // NamedGroup + KeyExchange Length + KeyExchange
        let key_share_list_len = key_share_entry_len; // Only one entry for now

        let mut key_share_content = Vec::new();
        key_share_content.extend_from_slice(&key_share_list_len.to_be_bytes()); // Total length of KeyShare list

        // KeyShareEntry for P-256
        key_share_content.extend_from_slice(&NamedGroup::P256.as_bytes()); // NamedGroup
        key_share_content.extend_from_slice(&key_exchange_len.to_be_bytes()); // KeyExchange Length
        key_share_content.extend_from_slice(client_ephemeral_public_bytes); // Client's Ephemeral Public Key
        extensions_bytes.extend_from_slice(
            &Extension::new(EXTENSION_TYPE_KEY_SHARE, &key_share_content).to_bytes(),
        );

        // 6.4. Supported Versions Extension (type 0x002B)
        let mut supported_versions_content = Vec::new();
        supported_versions_content.push(0x02); // Length of versions list (2 bytes for TLS 1.2)
        supported_versions_content.push(TLS_1_2_MAJOR); // TLS 1.2 Major
        supported_versions_content.push(TLS_1_2_MINOR); // TLS 1.2 Minor
        // If you intend to support TLS 1.3, you would add its version here:
        // supported_versions_content.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
        extensions_bytes.extend_from_slice(
            &Extension::new(
                EXTENSION_TYPE_SUPPORTED_VERSIONS,
                &supported_versions_content,
            )
            .to_bytes(),
        );

        // 6.5. Signature Algorithms Extension (type 0x000D)
        let mut sig_algs_content = Vec::new();
        let sig_algs_list_len = (2 * 4) as u16; // 4 algorithms, 2 bytes each
        sig_algs_content.extend_from_slice(&sig_algs_list_len.to_be_bytes()); // Length of algorithms list
        sig_algs_content.extend_from_slice(&SIG_ALG_RSA_PSS_RSAE_SHA256);
        sig_algs_content.extend_from_slice(&SIG_ALG_ECDSA_SECP256R1_SHA256);
        sig_algs_content.extend_from_slice(&SIG_ALG_RSA_PSS_RSAE_SHA512);
        sig_algs_content.extend_from_slice(&SIG_ALG_RSA_PKCS1_SHA256);
        extensions_bytes.extend_from_slice(
            &Extension::new(EXTENSION_TYPE_SIGNATURE_ALGORITHMS, &sig_algs_content).to_bytes(),
        );

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

        // TLS Record Protocol Layer
        Ok(HandshakeMessage::build_tls_record(
            TlsContentType::Handshake,
            record_tls_version,
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
    let mut cursor = Cursor::new(server_response_buffer);

    let mut server_hello: Option<ServerHelloParsed> = None;
    let mut certificates: Option<Vec<Vec<u8>>> = None;
    let mut server_key_exchange: Option<ServerKeyExchangeParsed> = None;
    let mut server_hello_done_received = false;

    // Keep parsing records until no more data or ServerHelloDone is found
    while let Some(record) = parse_tls_record(&mut cursor)? {
        // Validate the record version matches the negotiated TLS version
        let (rec_major, rec_minor) = record.version_major_minor(); // Assuming you have this helper in TlsRecord
        if TlsVersion::from_u8_pair(rec_major, rec_minor) != tls_version {
            return Err(TlsError::ParserError(TlsParserError::InvalidVersion(
                rec_major, rec_minor,
            )));
        }

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
