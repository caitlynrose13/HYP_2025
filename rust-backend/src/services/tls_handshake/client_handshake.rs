use crate::services::errors::TlsError;
use crate::services::tls_handshake::keys;
use crate::services::tls_handshake::messages;
use crate::services::tls_handshake::validation;
use elliptic_curve::sec1::ToEncodedPoint;
use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey};
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::services::tls_handshake::keys::TlsAeadCipher;
use crate::services::tls_parser::{
    CipherSuite, HandshakeMessageType, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TlsContentType, TlsParserError, TlsRecord, TlsVersion,
    parse_tls_alert,
};

#[derive(Debug, Clone, PartialEq)]
pub enum TlsSecurityLevel {
    Modern,     // Supports TLS 1.2 or 1.3
    Deprecated, // Only supports TLS 1.0 or 1.1
    Unknown,    // Couldn't determine
}

//this is the main ctls code and primariy uses 1.2 - there is inconsistenct naming because poor planning....
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
    pub handshake_hash: [u8; 32],
}

#[derive(Debug, Default)]
struct HandshakeState {
    server_hello: bool,
    certificate: bool,
    server_key_exchange: bool,
    server_hello_done: bool,
    chosen_cipher_suite: Option<[u8; 2]>,
}

//uppdate sets te state to true/false - tracks the part of the handshake that has been completed
impl HandshakeState {
    fn update(
        &mut self,
        msg_type: &crate::services::tls_parser::HandshakeMessageType,
        payload: &[u8],
    ) {
        use crate::services::tls_parser::HandshakeMessageType::*;
        match msg_type {
            ServerHello => {
                self.server_hello = true;
                // Parse and store the chosen cipher suite
                if payload.len() > 4 {
                    match crate::services::tls_parser::parse_server_hello_content(&payload[4..]) {
                        //skip the first 4 bytes which contains the length of the server hello, go straight to message
                        Ok(parsed) => {
                            self.chosen_cipher_suite = Some(parsed.chosen_cipher_suite);
                        }
                        Err(_) => {
                            // Failed to parse ServerHello content
                        }
                    }
                }
            }
            Certificate => self.certificate = true,
            ServerKeyExchange => self.server_key_exchange = true,
            ServerHelloDone => self.server_hello_done = true,
            _ => {}
        }
    }

    //check if all required messages have been received
    fn all_required_received(&self) -> bool {
        if let Some(cs_id) = self.chosen_cipher_suite {
            // ECDHE_RSA suites
            if cs_id == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.id
                || cs_id == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.id
            {
                self.server_hello
                    && self.certificate
                    && self.server_key_exchange
                    && self.server_hello_done
            } else {
                // For all other (static RSA) suites, require ServerHello, Certificate, ServerHelloDone
                self.server_hello && self.certificate && self.server_hello_done
            }
        } else {
            false
        }
    }
}

pub fn perform_tls_handshake_full(
    domain: &str,
    tls_version: TlsVersion,
) -> Result<TlsConnectionState, TlsError> {
    perform_tls_handshake_full_with_cert(domain, tls_version).map(|(state, _)| state)
}

pub fn perform_tls_handshake_full_with_cert(
    domain: &str,
    tls_version: TlsVersion,
) -> Result<(TlsConnectionState, Option<Vec<u8>>), TlsError> {
    // Use the provided domain parameter.
    // TODO: Add HSTS detection.

    let domain = domain;
    let port = 443; //default for tls/https
    let addr_str = format!("{}:{}", domain, port);
    let mut addrs_iter = addr_str
        .to_socket_addrs() //convert the domain to an address
        .map_err(|e| TlsError::InvalidAddress(format!("Couldn't resolve address: {}", e)))?; //if error return error
    let addr = addrs_iter
        .next() //get the first address
        .ok_or_else(|| TlsError::ConnectionFailed(format!("No address found for {}", domain)))?;

    //connect to the address and start tcp connection, after 10 sec give up
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| TlsError::ConnectionFailed(format!("TCP connect failed: {}", e)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let mut handshake_transcript: Vec<u8> = Vec::new();

    let mut client_random = [0u8; 32]; // client random balue used for key derivation later
    rand::thread_rng().fill(&mut client_random); //fill random bytes 

    let mut rng = thread_rng();
    let client_ephemeral_secret = EphemeralSecret::random(&mut rng); // new ephemeral secret for each handshake
    let client_ephemeral_public_encoded =
        client_ephemeral_secret.public_key().to_encoded_point(false);
    let client_ephemeral_public_bytes = client_ephemeral_public_encoded.as_bytes(); // get the raw byes to send to server

    // Client Hello - record is the full tls record with headers, raw client handshake is the bytes with no record header
    let (client_hello_record, raw_client_hello_handshake) =
        messages::HandshakeMessage::build_client_hello_with_random_and_key_share(
            domain,
            tls_version,
            &client_random,
            client_ephemeral_public_bytes, //for key exchange
        )?;
    stream.write_all(&client_hello_record)?; //send the clienthello over tcp stream
    handshake_transcript.extend_from_slice(&raw_client_hello_handshake); //append the raw message as well for the finished message/keyderivation

    // Server Response
    //prepare the message
    let handshake_transcript_len = handshake_transcript.len();
    let mut handshake_messages = Vec::new();
    let mut handshake_state = HandshakeState::default(); //track the messages recieved 

    // Read all handshake records until all required messages are received
    while !handshake_state.all_required_received() {
        let server_response = messages::read_tls_record(&mut stream, tls_version)?;
        let msgs = crate::services::tls_parser::parse_handshake_messages(&server_response.payload)?;

        for msg in msgs.iter() {
            handshake_state.update(&msg.msg_type, &msg.raw_bytes);
            handshake_transcript.extend_from_slice(&msg.raw_bytes);
        }
        handshake_messages.extend(msgs);
    }

    //trim the message to upto the number of messages recieved
    handshake_transcript.truncate(
        handshake_transcript_len
            + handshake_messages
                .iter()
                .map(|m| m.raw_bytes.len())
                .sum::<usize>(),
    );

    if !handshake_state.all_required_received() {
        return Err(TlsError::HandshakeFailed(
            "Server did not send all required handshake messages".into(),
        ));
    }

    // Parse ServerHello to get server random and chosen cipher suite
    let server_hello_msg = handshake_messages
        .iter()
        .find(|m| m.msg_type == crate::services::tls_parser::HandshakeMessageType::ServerHello)
        .ok_or_else(|| {
            TlsError::HandshakeFailed("ServerHello not found in handshake messages".to_string())
        })?;
    let server_hello_parsed =
        messages::HandshakeMessage::parse_server_hello_message(&server_hello_msg.raw_bytes)?;

    // Parse ServerKeyExchange
    let server_key_exchange_msg = handshake_messages
        .iter()
        .find(|m| {
            m.msg_type == crate::services::tls_parser::HandshakeMessageType::ServerKeyExchange
        })
        .ok_or_else(|| {
            TlsError::HandshakeFailed(
                "ServerKeyExchange not found in handshake messages".to_string(),
            )
        })?;

    //send the key exchange message to the function and assign
    let server_key_exchange = messages::HandshakeMessage::parse_server_key_exchange_message(
        &server_key_exchange_msg.raw_bytes,
    )?;

    // Parse Certificate
    let certificate_msg = handshake_messages //get the certificate message from the handshake messages
        .iter()
        .find(|m| m.msg_type == crate::services::tls_parser::HandshakeMessageType::Certificate)
        .ok_or_else(|| {
            TlsError::HandshakeFailed("Certificate not found in handshake messages".to_string())
        })?;
    let certificates =
        crate::services::tls_parser::parse_certificate_list(&certificate_msg.raw_bytes[4..])?; //skip the first 4 bytes which contains the length of the certificate list
    let first_cert = certificates.get(0).cloned();

    // Convert chosen_cipher_suite from [u8; 2] to CipherSuite
    let chosen_cipher_suite = crate::services::tls_parser::get_cipher_suite_by_id(
        &server_hello_parsed.chosen_cipher_suite,
    )
    .ok_or_else(|| {
        TlsError::HandshakeFailed(format!(
            "Server chose unsupported cipher suite: {:02X}{:02X}",
            server_hello_parsed.chosen_cipher_suite[0], server_hello_parsed.chosen_cipher_suite[1]
        ))
    })?;

    //authenticate the key exchange parameters with server certificate and rnadom values.
    validation::verify_server_key_exchange_signature(
        &server_key_exchange,
        &client_random,
        &server_hello_parsed.server_random,
        &certificates,
    )?;

    //take server ephemeral pub key and convert to public key using sec1 encoding. (ECDHE)
    let server_ephemeral_point = EncodedPoint::from_bytes(&server_key_exchange.public_key)
        .map_err(|_| {
            TlsError::KeyDerivationError("Invalid server ephemeral public key format".to_string())
        })?;
    let server_public_key =
        PublicKey::from_sec1_bytes(server_ephemeral_point.as_bytes()).map_err(|e| {
            TlsError::KeyDerivationError(format!(
                "Failed to create PublicKey from encoded point: {:?}",
                e
            ))
        })?;

    //calculate the shared secret using the client ephemeral secret and the server public key.
    let shared_secret = client_ephemeral_secret.diffie_hellman(&server_public_key);
    let pre_master_secret = shared_secret.raw_secret_bytes().to_vec(); //will be used to derive the master secret.

    //Get mastersecret and key block
    let master_secret = keys::calculate_master_secret(
        &pre_master_secret,
        &client_random,
        &server_hello_parsed.server_random,
        chosen_cipher_suite.hash_algorithm,
    )?;

    let key_block = keys::calculate_key_block(
        &master_secret,
        &server_hello_parsed.server_random,
        &client_random,
        &chosen_cipher_suite,
    )?;

    //only 1.2 for now,
    let (
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
        TlsAeadCipher,
        TlsAeadCipher,
        CipherSuite,
    ) = if tls_version == TlsVersion::TLS1_2 {
        let (client_cipher, client_iv, server_cipher, server_iv) =
            keys::derive_aead_keys(&chosen_cipher_suite, &key_block)?; //derive the aead keys for the cipher suite

        let key_len = chosen_cipher_suite.key_length as usize;
        let mut offset = 0;
        offset += chosen_cipher_suite.mac_key_length as usize; //skip the Client mac key
        offset += chosen_cipher_suite.mac_key_length as usize; //skip the Server mac key
        let client_key = key_block[offset..offset + key_len].to_vec(); //get the client key
        offset += key_len;
        let server_key = key_block[offset..offset + key_len].to_vec(); //get the server key

        (
            client_key,
            server_key,
            client_iv,
            server_iv,
            client_cipher,
            server_cipher,
            chosen_cipher_suite.clone(),
        )
    } else {
        return Err(TlsError::HandshakeFailed(
            "Unsupported TLS version for key derivation".into(),
        ));
    };

    let mut client_sequence_number: u64 = 0; //sequence numbers to prevent replay attacks, start at 0
    let (client_key_exchange_record, raw_client_key_exchange_handshake) =
        messages::HandshakeMessage::create_client_key_exchange(client_ephemeral_public_bytes)?;
    stream.write_all(&client_key_exchange_record)?;
    handshake_transcript.extend_from_slice(&raw_client_key_exchange_handshake);

    let change_cipher_spec_record = messages::HandshakeMessage::create_change_cipher_spec(); //tell server that encryption is starting andf will use negotiated cipher suite
    stream.write_all(&change_cipher_spec_record)?;

    //calculate the verify data for the client finished message. Final step of the handshake. proving end same keys
    let (client_verify_data, _client_handshake_hash) = keys::calculate_verify_data_with_hash(
        &master_secret,
        &handshake_transcript,
        b"client finished",
        chosen_cipher_suite.hash_algorithm,
    )?;

    let mut finished_message_plaintext = Vec::new();
    finished_message_plaintext.push(HandshakeMessageType::Finished as u8);
    finished_message_plaintext.extend_from_slice(&(12u32.to_be_bytes()[1..]));
    finished_message_plaintext.extend_from_slice(&client_verify_data);

    let encrypted_finished_payload = keys::encrypt_gcm_message(
        &finished_message_plaintext,
        &client_cipher,
        &client_fixed_iv,
        client_sequence_number,
        TlsContentType::Handshake,
        TlsVersion::TLS1_2,
    )?;

    let finished_record = build_tls12_gcm_record_with_explicit_nonce(
        TlsContentType::Handshake,
        TlsVersion::TLS1_2,
        &encrypted_finished_payload,
        client_sequence_number,
    );
    stream.write_all(&finished_record)?;
    client_sequence_number += 1;

    handshake_transcript.extend_from_slice(&finished_message_plaintext);

    let mut server_sequence_number: u64 = 0;
    let server_ccs_record = messages::read_tls_record(&mut stream, tls_version)?;
    if server_ccs_record.content_type != TlsContentType::ChangeCipherSpec {
        return Err(TlsError::HandshakeFailed(format!(
            "Expected Server ChangeCipherSpec, got {:?}",
            server_ccs_record.content_type
        )));
    }

    let record = messages::read_tls_record(&mut stream, tls_version)?;
    if record.payload.len() < 8 + 16 {
        return Err(TlsError::EncryptionError(
            "Server Finished record too short".into(),
        ));
    }
    let explicit_nonce = &record.payload[0..8];
    let ciphertext = &record.payload[8..];

    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&server_fixed_iv);
    nonce[4..].copy_from_slice(explicit_nonce);

    let plaintext_length = ciphertext.len() - 16;
    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&server_sequence_number.to_be_bytes());
    aad.push(TlsContentType::Handshake as u8);
    let (major, minor) = tls_version.to_u8_pair();
    aad.push(major);
    aad.push(minor);
    aad.extend_from_slice(&(plaintext_length as u16).to_be_bytes());

    let plaintext = match &server_cipher {
        TlsAeadCipher::Aes128Gcm(cipher) => {
            use aes_gcm::aead::{Aead, Payload};
            cipher.decrypt(
                &nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
        }
        TlsAeadCipher::Aes256Gcm(cipher) => {
            use aes_gcm::aead::{Aead, Payload};
            cipher.decrypt(
                &nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
        }
    };
    let plaintext = match plaintext {
        Ok(pt) => pt,
        Err(e) => {
            return Err(TlsError::EncryptionError(format!(
                "AES-GCM decryption failed: {:?}",
                e
            )));
        }
    };

    server_sequence_number += 1;

    if plaintext.len() < 4 + 12 {
        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
            "Server Finished payload too short".to_string(),
        )));
    }
    if plaintext[0] != HandshakeMessageType::Finished as u8 {
        return Err(TlsError::ParserError(TlsParserError::MalformedMessage(
            "Decrypted payload is not Finished message".to_string(),
        )));
    }

    let _message_type = plaintext[0];
    let message_length = u32::from_be_bytes([0, plaintext[1], plaintext[2], plaintext[3]]) as usize;
    let server_verify_data_received = &plaintext[4..4 + message_length];

    let prf_label = b"server finished";
    let (expected_verify_data_from_transcript, _server_handshake_hash) =
        keys::calculate_verify_data_with_hash(
            &master_secret,
            &handshake_transcript,
            prf_label,
            chosen_cipher_suite.hash_algorithm,
        )?;

    if server_verify_data_received != expected_verify_data_from_transcript {
        return Err(TlsError::HandshakeFailed(
            "Server Finished verify_data mismatch".into(),
        ));
    }

    Ok((
        TlsConnectionState {
            master_secret: master_secret.to_vec(),
            client_write_key,
            server_write_key,
            client_fixed_iv,
            server_fixed_iv,
            client_sequence_number,
            server_sequence_number,
            negotiated_cipher_suite: final_chosen_cipher_suite_struct,
            negotiated_tls_version: TlsVersion::TLS1_2,
            client_random,
            server_random: server_hello_parsed.server_random,
            handshake_hash: Sha256::digest(&handshake_transcript).into(),
        },
        first_cert,
    ))
}

// Build encrypted TLS record with explicit nonce
fn build_tls12_gcm_record_with_explicit_nonce(
    content_type: TlsContentType,
    tls_version: TlsVersion,
    ciphertext_with_tag: &[u8],
    sequence_number: u64,
) -> Vec<u8> {
    // create the payload
    let mut payload = Vec::with_capacity(8 + ciphertext_with_tag.len());
    payload.extend_from_slice(&sequence_number.to_be_bytes());
    payload.extend_from_slice(ciphertext_with_tag);
    // Build the TLS record
    let mut record = Vec::new(); //Header is [ContentType, VersionMajor, VersionMinor, Length]
    record.push(content_type.as_u8());
    let (major, minor) = tls_version.to_u8_pair(); //version major and mnor
    record.push(major);
    record.push(minor);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes()); //payload is [ExplicitNonce , Ciphertext+Tag]
    record.extend_from_slice(&payload);
    record
}

/// Reads a single TLS record from a tcp stream., returns a tls record
pub fn read_tls_record<R: Read>(
    reader: &mut R,
    _tls_version: TlsVersion,
) -> Result<TlsRecord, TlsError> {
    use std::io::{self};
    use std::time::Duration;
    let mut header = [0u8; 5];
    let mut bytes_read = 0;

    // Read the 5 byte header
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

//test the tls security level of the server => currently only 1.2
pub fn probe_tls_security_level(domain: &str) -> TlsSecurityLevel {
    println!("Probing {} for TLS security level...", domain);

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

    println!("    TLS 1.3 not yet implemented - assuming deprecated if TLS 1.2 failed");
    TlsSecurityLevel::Deprecated
}

/// Test function to perform a TLS 1.2 handshake with google.com
/// This function is called from main.rs to ensure the TLS 1.2 code is used
pub fn test_tls12_handshake_to_google() {
    let domain = "google.com";
    match perform_tls_handshake_full(domain, TlsVersion::TLS1_2) {
        Ok(_) => {
            println!("TLS 1.2 handshake completed successfully with {}", domain);
        }
        Err(e) => {
            println!("TLS 1.2 handshake failed: {:?}", e);
        }
    }
}
