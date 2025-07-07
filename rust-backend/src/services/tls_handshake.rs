// src/services/tls_handshake.rs

use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use hex;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{
    EncodedPoint,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
};
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use super::certificate_validator;
use super::errors::TlsError;
use super::tls_parser::{
    HandshakeMessageType, ServerHelloParsed, ServerKeyExchangeParsed, TLS_CHANGE_CIPHER_SPEC,
    TLS_HANDSHAKE, TlsContentType, parse_certificate_list, parse_handshake_messages,
    parse_server_hello_content, parse_server_key_exchange_content, parse_tls_record,
};

// --- TlsVersion Enum ---
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    Tls12, // 0x0303
    Tls13, // 0x0304
}

impl From<TlsVersion> for (u8, u8) {
    fn from(version: TlsVersion) -> Self {
        match version {
            TlsVersion::Tls12 => (0x03, 0x03),
            TlsVersion::Tls13 => (0x03, 0x04),
        }
    }
}

pub fn build_client_hello_with_random_and_key_share(
    domain: &str,
    tls_version: TlsVersion,
    client_random: &[u8; 32],
    client_key_share_public_bytes: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let mut client_hello = Vec::new();

    client_hello.push(0x01);

    let handshake_length_placeholder = client_hello.len();
    client_hello.extend_from_slice(&[0, 0, 0]);

    // 2. TLS Version (e.g., TLS 1.2 is 0x0303, TLS 1.3 is 0x0304)
    let (major, minor) = tls_version.into();
    client_hello.push(major);
    client_hello.push(minor);

    // 3. Client Random (32 bytes)
    client_hello.extend_from_slice(client_random);

    // 4. Session ID (1 byte length + Session ID bytes)
    client_hello.push(0x00); // Session ID length (0 for empty)

    // 5. Cipher Suites (2 bytes length + list of 2-byte cipher suite IDs)
    let cipher_suites: Vec<u8> = match tls_version {
        TlsVersion::Tls12 => {
            vec![
                0xC0, 0x2B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC0, 0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0x00, 0x9C, // TLS_RSA_WITH_AES_128_GCM_SHA256
            ]
        }
        TlsVersion::Tls13 => {
            vec![
                0x13, 0x01, // TLS_AES_128_GCM_SHA256
                0x13, 0x02, // TLS_AES_256_GCM_SHA384
            ]
        }
    };
    client_hello.push((cipher_suites.len() / 2) as u8 * 2);
    client_hello.extend_from_slice(&cipher_suites);

    client_hello.push(0x01);
    client_hello.push(0x00);

    let extensions_start_index = client_hello.len();
    client_hello.extend_from_slice(&[0, 0]);

    // --- Add Extensions ---
    // Supported Versions (for TLS 1.3 negotiation)
    if tls_version == TlsVersion::Tls13 {
        client_hello.extend_from_slice(&[0x00, 0x2B]); // Extension Type: supported_versions
        client_hello.extend_from_slice(&[0x00, 0x03]); // Extension Length
        client_hello.push(0x02); // Number of versions (1 version for TLS 1.3)
        client_hello.push(0x03); // TLS 1.3 Major
        client_hello.push(0x04); // TLS 1.3 Minor
    }

    // Supported Groups / Elliptic Curves (0x000A)
    client_hello.extend_from_slice(&[0x00, 0x0A]); // Extension Type: supported_groups
    client_hello.extend_from_slice(&[0x00, 0x08]); // Extension Length: 8 bytes
    client_hello.extend_from_slice(&[0x00, 0x06]); // List length (2 bytes) = 6 bytes of group IDs
    client_hello.extend_from_slice(&[0x00, 0x1D]); // x25519
    client_hello.extend_from_slice(&[0x00, 0x17]); // secp256r1

    // Key Share (0x0033)
    client_hello.extend_from_slice(&[0x00, 0x33]); // Extension Type: key_share
    let key_share_ext_len_placeholder = client_hello.len();
    client_hello.extend_from_slice(&[0, 0]); // Placeholder for key_share extension length

    // Key Share list length (2 bytes)
    client_hello
        .extend_from_slice(&(2 + 2 + client_key_share_public_bytes.len() as u16).to_be_bytes());

    // Named Group (e.g., secp256r1: 0x0017)
    client_hello.extend_from_slice(&[0x00, 0x17]); // secp256r1 (P-256)

    // Key Exchange Length (2 bytes) + Key Exchange Data
    client_hello.extend_from_slice(&(client_key_share_public_bytes.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(client_key_share_public_bytes);

    // Fill in key_share extension length
    let key_share_ext_total_len = client_hello.len() - (key_share_ext_len_placeholder + 2);
    let key_share_ext_total_len_bytes = (key_share_ext_total_len as u16).to_be_bytes();
    client_hello[key_share_ext_len_placeholder] = key_share_ext_total_len_bytes[0];
    client_hello[key_share_ext_len_placeholder + 1] = key_share_ext_total_len_bytes[1];

    // Signature Algorithms (0x000D)
    client_hello.extend_from_slice(&[0x00, 0x0D]); // Extension Type: signature_algorithms
    client_hello.extend_from_slice(&[0x00, 0x0A]); // Extension Length: 10 bytes
    client_hello.extend_from_slice(&[0x00, 0x08]); // List length (2 bytes) = 8 bytes of algos
    client_hello.extend_from_slice(&[0x04, 0x03]); // EcdsaSecp256r1Sha256
    client_hello.extend_from_slice(&[0x08, 0x04]); // RsaPssRsaSha256
    client_hello.extend_from_slice(&[0x04, 0x01]); // RsaPkcs1Sha256

    // SNI (Server Name Indication) (0x0000)
    client_hello.extend_from_slice(&[0x00, 0x00]); // Extension Type: server_name
    let sni_ext_len_placeholder = client_hello.len();
    client_hello.extend_from_slice(&[0, 0]); // Placeholder for SNI extension length

    // SNI content: list length (2 bytes) + SNI entry
    client_hello.extend_from_slice(&[0x00, 0x00]); // List length (always 1 entry)
    client_hello.push(0x00); // Name Type: hostname (0x00)
    client_hello.extend_from_slice(&(domain.len() as u16).to_be_bytes()); // Hostname length
    client_hello.extend_from_slice(domain.as_bytes()); // Hostname bytes

    // Fill in SNI extension length
    let sni_ext_total_len = client_hello.len() - (sni_ext_len_placeholder + 2);
    let sni_ext_total_len_bytes = (sni_ext_total_len as u16).to_be_bytes();
    client_hello[sni_ext_len_placeholder] = sni_ext_total_len_bytes[0];
    client_hello[sni_ext_len_placeholder + 1] = sni_ext_total_len_bytes[1];

    // Fill in total extensions length
    let total_extensions_len = client_hello.len() - (extensions_start_index + 2);
    let total_extensions_len_bytes = (total_extensions_len as u16).to_be_bytes();
    client_hello[extensions_start_index] = total_extensions_len_bytes[0];
    client_hello[extensions_start_index + 1] = total_extensions_len_bytes[1];

    // Final Handshake Message Length (3 bytes)
    let handshake_message_length = client_hello.len() - (handshake_length_placeholder + 3);
    client_hello[handshake_length_placeholder] = (handshake_message_length >> 16) as u8;
    client_hello[handshake_length_placeholder + 1] = (handshake_message_length >> 8) as u8;
    client_hello[handshake_length_placeholder + 2] = handshake_message_length as u8;

    // Prepend TLS Record Header
    let mut tls_record = Vec::new();
    tls_record.push(TLS_HANDSHAKE); // Content Type: Handshake (0x16)
    tls_record.push(major); // TLS Record Version (same as ClientHello version)
    tls_record.push(minor);
    tls_record.extend_from_slice(&(client_hello.len() as u16).to_be_bytes()); // Length of payload
    tls_record.extend_from_slice(&client_hello); // The actual ClientHello message

    println!("Built ClientHello TLS Record ({} bytes)", tls_record.len());
    Ok(tls_record)
}

pub fn derive_session_keys(
    _pre_master_secret: &[u8],
    _client_random: &[u8; 32],
    _server_random: &[u8; 32],
    _chosen_cipher_suite: &[u8; 2],
    _tls_version: TlsVersion,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), TlsError> {
    Ok((vec![0; 16], vec![0; 16], vec![0; 12], vec![0; 12]))
}

pub fn build_change_cipher_spec() -> Vec<u8> {
    vec![TLS_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]
}

pub fn encrypt_handshake_message(
    _payload: &[u8],
    _key: &[u8],
    _iv: &[u8],
    _tls_version: TlsVersion,
) -> Result<Vec<u8>, TlsError> {
    Ok(vec![
        0x17, 0x03, 0x03, 0x00, 0x10, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
        0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00,
    ])
}

pub fn verify_server_key_exchange_signature(
    ske: &ServerKeyExchangeParsed,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    cert_chain: &[Vec<u8>],
) -> Result<(), TlsError> {
    println!("   Attempting to verify ServerKeyExchange signature...");

    let cert_der = cert_chain
        .get(0)
        .ok_or_else(|| TlsError::CertificateError("No server certificate provided.".into()))?;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| TlsError::CertificateError(format!("Failed to parse server cert: {:?}", e)))?;

    let spki_bytes = cert.tbs_certificate.subject_pki.subject_public_key.data;

    let pub_key_point = EncodedPoint::from_bytes(spki_bytes)
        .map_err(|_| TlsError::CertificateError("Invalid SPKI EC point format.".into()))?;

    let verifying_key = VerifyingKey::from_encoded_point(&pub_key_point)
        .map_err(|e| TlsError::CertificateError(format!("Invalid EC public key: {:?}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(client_random);
    hasher.update(server_random);
    hasher.update(&[ske.curve_type]);
    hasher.update(&(ske.named_curve as u16).to_be_bytes());
    hasher.update(&[ske.public_key.len() as u8]);
    hasher.update(&ske.public_key);
    let message_hash = hasher.finalize();

    if ske.signature_algorithm != [0x04, 0x03] {
        return Err(TlsError::HandshakeFailed(format!(
            "Unsupported signature algorithm: 0x{:02X}{:02X}, expected ECDSA_P256_SHA256 (0x0403)",
            ske.signature_algorithm[0], ske.signature_algorithm[1]
        )));
    }

    if ske.signature.len() != 64 {
        return Err(TlsError::HandshakeFailed(
            "Signature must be exactly 64 bytes (ECDSA P-256)".into(),
        ));
    }

    let signature = Signature::from_slice(&ske.signature)
        .map_err(|e| TlsError::HandshakeFailed(format!("Invalid signature format: {:?}", e)))?;

    verifying_key
        .verify(message_hash.as_slice(), &signature)
        .map_err(|e| {
            TlsError::HandshakeFailed(format!("Signature verification failed: {:?}", e))
        })?;

    println!("   ServerKeyExchange signature successfully verified!");
    Ok(())
}

// --- perform_tls_handshake_full Function ---
pub fn perform_tls_handshake_full(
    domain: &str,
    tls_version: TlsVersion,
) -> Result<Vec<u8>, TlsError> {
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

    let mut client_random = [0u8; 32];
    rand::thread_rng().fill(&mut client_random);

    let mut rng = thread_rng();
    let client_ephemeral_secret = EphemeralSecret::random(&mut rng);
    let client_ephemeral_public_encoded =
        client_ephemeral_secret.public_key().to_encoded_point(false);
    let client_ephemeral_public_bytes = client_ephemeral_public_encoded.as_bytes();

    let client_hello = build_client_hello_with_random_and_key_share(
        domain,
        tls_version,
        &client_random,
        client_ephemeral_public_bytes,
    )?;
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
        handle_server_hello_flight(&server_response_buffer, tls_version)?; //call helper function

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
    if let Some(ske_payload) = &server_key_exchange_parsed {
        println!(
            "Server Key Exchange Payload: {} bytes",
            ske_payload.public_key.len()
        );
    }
    println!("----------------------------------");

    // ---  Certificate Validation ---
    // --- PHASE 2: Certificate Validation & Hostname Verification (Step 1) ---
    println!("\n--- Phase 2: Performing Certificate Validation & Hostname Verification ---");
    // This is where the call to your certificate_validator goes:
    certificate_validator::validate_server_certificate(&certificates, domain)?;
    println!("Server certificate chain and hostname validated successfully!");

    // --- Phase 2.5: ServerKeyExchange Signature Verification (Step 2) ---
    // This section is what replaces your old "Placeholder: Processing Server Key Exchange (TLS 1.2)"
    if tls_version == TlsVersion::Tls12 {
        if let Some(ske_parsed) = &server_key_exchange_parsed {
            // Use the `ske_parsed` from handle_server_hello_flight
            println!("--- Phase 2.5: Verifying ServerKeyExchange Signature ---");
            verify_server_key_exchange_signature(
                // Call your new verification function
                ske_parsed,
                &client_random, // You need to have `client_random` available in this scope
                &server_hello_parsed.server_random,
                &certificates, // Pass certificates to extract server's public key
            )?;
            println!("ServerKeyExchange signature verified successfully!");
        } else {
            println!(
                "No ServerKeyExchange message received (might be using RSA key exchange, or TLS 1.3)."
            );
        }
    } else if tls_version == TlsVersion::Tls13 {
        println!("TLS 1.3 negotiated, ServerKeyExchange is not used.");
    }

    // --- Placeholder for Phase 3: Key Exchange and Key Derivation ---
    println!("--- Placeholder: Performing Key Exchange & Key Derivation (Phase 3) ---");
    let pre_master_secret = vec![0; 48]; // Dummy for now
    let (_client_write_key, _server_write_key, _client_iv, _server_iv) = derive_session_keys(
        &pre_master_secret,
        &client_random,
        &server_hello_parsed.server_random,
        &server_hello_parsed.chosen_cipher_suite,
        tls_version,
    )?;
    println!("(Dummy) Session keys derived.");

    // --- Placeholder for Phase 4: Client Sends ChangeCipherSpec and Finished ---
    println!("--- Placeholder: Client Sending Final Handshake (Phase 4) ---");
    let change_cipher_spec = build_change_cipher_spec();
    stream.write_all(&change_cipher_spec)?;
    println!("(Dummy) Sent ChangeCipherSpec.");

    let finished_message_content = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF];
    let encrypted_finished = encrypt_handshake_message(
        &finished_message_content,
        &vec![0; 16],
        &vec![0; 12],
        tls_version,
    )?;
    stream.write_all(&encrypted_finished)?;
    println!("(Dummy) Sent Encrypted Finished.");

    // --- Placeholder for Phase 5: Awaiting Server ChangeCipherSpec and Finished ---
    println!("--- Placeholder: Awaiting Server Final Handshake (Phase 5) ---");
    let mut final_server_response_buffer = Vec::new();
    loop {
        match stream.read(&mut temp_buffer) {
            Ok(0) => break,
            Ok(n) => {
                final_server_response_buffer.extend_from_slice(&temp_buffer[..n]);
                if final_server_response_buffer.len() > 100 {
                    break;
                } // Placeholder
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(TlsError::IoError(e)),
        }
    }
    println!(
        "(Dummy) Received server's final handshake bytes. Need to parse ChangeCipherSpec and Finished."
    );
    Ok(vec![])
}

// (The handle_server_hello_flight function would come after perform_tls_handshake_full)
pub fn handle_server_hello_flight(
    response_bytes: &[u8],
    _tls_client_version: TlsVersion,
) -> Result<
    (
        ServerHelloParsed,
        Vec<Vec<u8>>,
        Option<ServerKeyExchangeParsed>,
    ),
    TlsError,
> {
    let mut cursor = Cursor::new(response_bytes);
    let mut server_hello_parsed: Option<ServerHelloParsed> = None;
    let mut certificates: Vec<Vec<u8>> = Vec::new();
    let mut server_key_exchange_parsed: Option<ServerKeyExchangeParsed> = None;
    let mut server_hello_done_received = false;

    println!("Processing server's initial flight records...");

    loop {
        match parse_tls_record(&mut cursor) {
            Ok(Some(record)) => {
                println!(
                    "  Parsed TLS Record: Type={:?}, Version={}.{}, Length={}",
                    record.content_type, record.version_major, record.version_minor, record.length
                );

                match record.content_type {
                    TlsContentType::Handshake => {
                        let handshake_messages = parse_handshake_messages(&record.payload)
                            .map_err(|e| {
                                TlsError::HandshakeFailed(format!(
                                    "Failed to parse handshake messages: {}",
                                    e
                                ))
                            })?;

                        for msg in handshake_messages {
                            println!(
                                "    Parsed Handshake Message: Type={:?}, Payload Len={}",
                                msg.msg_type,
                                msg.payload.len()
                            );

                            match msg.msg_type {
                                //_ to hide error
                                HandshakeMessageType::ServerHello => {
                                    if server_hello_parsed.is_some() {
                                        return Err(TlsError::HandshakeFailed(
                                            "Received duplicate ServerHello".to_string(),
                                        ));
                                    }
                                    server_hello_parsed = Some(
                                        parse_server_hello_content(&msg.payload).map_err(|e| {
                                            TlsError::HandshakeFailed(format!(
                                                "Failed to parse ServerHello content: {}",
                                                e
                                            ))
                                        })?,
                                    );
                                }

                                HandshakeMessageType::Certificate => {
                                    if !certificates.is_empty() {
                                        println!(
                                            "Warning: Received multiple Certificate messages, which is unusual. Appending."
                                        );
                                    }
                                    let parsed_certs = parse_certificate_list(&msg.payload)
                                        .map_err(|e| {
                                            TlsError::HandshakeFailed(format!(
                                                "Failed to parse certificate list: {}",
                                                e
                                            ))
                                        })?;
                                    certificates.extend(parsed_certs);
                                }

                                HandshakeMessageType::ServerKeyExchange => {
                                    if server_key_exchange_parsed.is_some() {
                                        return Err(TlsError::HandshakeFailed(
                                            "Received duplicate ServerKeyExchange".to_string(),
                                        ));
                                    }
                                    server_key_exchange_parsed = Some(
                                        parse_server_key_exchange_content(&msg.payload).map_err(
                                            |e| {
                                                TlsError::HandshakeFailed(format!(
                                                    "Failed to parse ServerKeyExchange content: {}",
                                                    e
                                                ))
                                            },
                                        )?,
                                    );
                                }

                                HandshakeMessageType::Unknown(t) => {
                                    println!(
                                        "Encountered unknown handshake message type: 0x{:02X}",
                                        t
                                    );
                                }

                                HandshakeMessageType::ServerHelloDone => {
                                    if server_hello_done_received {
                                        return Err(TlsError::HandshakeFailed(
                                            "Received duplicate ServerHelloDone".to_string(),
                                        ));
                                    }
                                    server_hello_done_received = true;
                                    break;
                                }

                                _ => {
                                    println!(
                                        "    Unexpected handshake message type for this phase: {:?}",
                                        msg.msg_type
                                    );
                                }
                            }
                        }
                    }
                    TlsContentType::Alert => {
                        if record.payload.len() >= 2 {
                            let level = record.payload[0];
                            let description = record.payload[1];
                            return Err(TlsError::HandshakeFailed(format!(
                                "TLS Alert received: Level=0x{:02X}, Description=0x{:02X}",
                                level, description
                            )));
                        } else {
                            return Err(TlsError::HandshakeFailed(
                                "Malformed TLS Alert record".to_string(),
                            ));
                        }
                    }
                    _ => {
                        println!(
                            "  Warning: Received unexpected TLS record type during initial handshake: {:?}",
                            record.content_type
                        );
                    }
                }
                if server_hello_done_received {
                    break;
                }
            }
            Ok(None) => {
                break;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    let Some(sh) = server_hello_parsed else {
        return Err(TlsError::HandshakeFailed(
            "Did not receive ServerHello message in server's initial flight".to_string(),
        ));
    };

    Ok((sh, certificates, server_key_exchange_parsed))
}
