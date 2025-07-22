use rand::RngCore;
use std::io::{Read, Write};
use std::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::services::errors::TlsError;
use crate::services::tls_handshake::tls13::key_schedule::derive_tls13_handshake_traffic_secrets;
use crate::services::tls_handshake::tls13::messages::build_client_hello;
use crate::services::tls_handshake::tls13::record_layer::decrypt_record;
use crate::services::tls_handshake::tls13::transcript::TranscriptHash;

pub struct Tls13ConnectionState {
    pub client_secret: Option<x25519_dalek::EphemeralSecret>, // Option so we can take ownership
    pub client_public: [u8; 32],
    pub server_public: [u8; 32],
    pub shared_secret: [u8; 32],
    pub handshake_secret: Vec<u8>,
    pub client_hs_traffic_secret: Vec<u8>,
    pub server_hs_traffic_secret: Vec<u8>,
    pub negotiated_cipher_suite: [u8; 2],
    pub server_random: [u8; 32],
    pub client_random: [u8; 32],
    pub transcript_hash: [u8; 32],
}

/// Perform X25519 key exchange and derive handshake secret using HKDF (TLS 1.3)
pub fn derive_tls13_handshake_secret(
    client_secret: x25519_dalek::EphemeralSecret,
    server_public: &[u8; 32],
) -> [u8; 32] {
    use x25519_dalek::PublicKey;
    let server_pub = PublicKey::from(*server_public);
    let shared = client_secret.diffie_hellman(&server_pub);
    shared.to_bytes()
}

/// Example: Perform handshake up to handshake secret derivation
pub fn perform_tls13_handshake_minimal(domain: &str) -> Result<Tls13ConnectionState, TlsError> {
    use crate::services::tls_handshake::keys::{derive_hkdf_keys, generate_x25519_keypair};
    use crate::services::tls_parser::{
        HandshakeMessageType, parse_handshake_messages, parse_server_hello_content,
    };

    // 1. Generate client random and X25519 keypair
    let mut client_random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_random);
    let (client_secret, client_public) = generate_x25519_keypair();

    // 2. Build and send ClientHello
    let client_hello = build_client_hello(domain, &client_random, &client_public);
    println!(
        "[DEBUG] Sending ClientHello ({} bytes): {}",
        client_hello.len(),
        hex::encode(&client_hello)
    );
    let mut stream =
        TcpStream::connect((domain, 443)).map_err(|e| TlsError::ConnectionFailed(e.to_string()))?;
    stream
        .write_all(&client_hello)
        .map_err(|e| TlsError::IoError(e))?;

    // 3. Read handshake messages and find ServerHello
    let mut buf = [0u8; 8192];
    let mut total_read = stream.read(&mut buf).map_err(|e| TlsError::IoError(e))?;
    println!(
        "[DEBUG] Received {} bytes from server: {}",
        total_read,
        hex::encode(&buf[..total_read])
    );
    let mut server_random = [0u8; 32];
    let mut negotiated_cipher_suite = [0u8; 2];
    let mut server_key_share = None;
    let mut all_messages = Vec::new();
    let mut cursor = std::io::Cursor::new(&buf[..total_read]);
    let mut found_server_hello = false;
    let mut app_data_record_sequence: u64 = 0; // TLS 1.3 record sequence number for ApplicationData
    let mut pending_app_data_records: Vec<Vec<u8>> = Vec::new();
    // Parse all records in the buffer
    while (cursor.position() as usize) < total_read {
        match crate::services::tls_parser::parse_tls_record(&mut cursor) {
            Ok(Some(record)) => {
                println!(
                    "[DEBUG] Parsed TLS record: content_type={:?}, version={:02x}{:02x}, length={}",
                    record.content_type, record.version_major, record.version_minor, record.length
                );
                println!(
                    "[DEBUG] Record payload ({} bytes): {}",
                    record.payload.len(),
                    hex::encode(&record.payload)
                );
                if record.content_type == crate::services::tls_parser::TlsContentType::Handshake {
                    let messages =
                        crate::services::tls_parser::parse_handshake_messages(&record.payload)?;
                    println!(
                        "[DEBUG] Parsed {} handshake messages from this record",
                        messages.len()
                    );
                    for (i, msg) in messages.iter().enumerate() {
                        println!(
                            "[DEBUG] Handshake message {}: {:?} ({} bytes), first 8 bytes: {}",
                            i,
                            msg.msg_type,
                            msg.payload.len(),
                            hex::encode(&msg.payload[..std::cmp::min(8, msg.payload.len())])
                        );
                    }
                    all_messages.extend(messages);
                } else if record.content_type
                    == crate::services::tls_parser::TlsContentType::ApplicationData
                {
                    // Store ApplicationData records for later decryption (after handshake traffic secret is available)
                    pending_app_data_records.push(record.payload);
                } else if record.content_type == crate::services::tls_parser::TlsContentType::Alert
                {
                    println!(
                        "[ALERT] Received TLS alert record: {}",
                        hex::encode(&record.payload)
                    );
                } else {
                    println!(
                        "[DEBUG] Ignored non-handshake record: content_type={:?}",
                        record.content_type
                    );
                }
            }
            Ok(None) => {
                // No more records in buffer
                break;
            }
            Err(e) => {
                println!("[ERROR] Failed to parse TLS record: {:?}", e);
                break;
            }
        }
    }

    let mut transcript = TranscriptHash::new();
    let mut client_hello_handshake_bytes = None;
    let mut server_hello_handshake_bytes = None;
    for msg in &all_messages {
        println!(
            "[DEBUG] Handshake message type: {:?}, length: {}",
            msg.msg_type,
            msg.payload.len()
        );
        println!(
            "[DEBUG] Handshake message type (raw): {:?} ({})",
            msg.msg_type, msg.msg_type as u8
        );
        println!(
            "[DEBUG] HandshakeMessageType::ServerHello as u8: {}",
            HandshakeMessageType::ServerHello as u8
        );

        if msg.msg_type == HandshakeMessageType::ClientHello {
            transcript.update(&msg.raw_bytes);
            client_hello_handshake_bytes = Some(msg.raw_bytes.clone());
        }
        if msg.msg_type == HandshakeMessageType::ServerHello {
            println!("[DEBUG] Entering ServerHello parsing block");
            std::io::stdout().flush().unwrap();
            println!("[DEBUG] ServerHello payload: {}", hex::encode(&msg.payload));
            std::io::stdout().flush().unwrap();
            transcript.update(&msg.raw_bytes);
            server_hello_handshake_bytes = Some(msg.raw_bytes.clone());
            let server_hello_body = &msg.payload;
            println!(
                "[DEBUG] About to call parse_server_hello_content with: {}",
                hex::encode(server_hello_body)
            );
            std::io::stdout().flush().unwrap();
            let sh = match parse_server_hello_content(server_hello_body) {
                Ok(sh) => sh,
                Err(e) => {
                    println!("[DEBUG] parse_server_hello_content error: {:?}", e);
                    std::io::stdout().flush().unwrap();
                    return Err(TlsError::ParserError(e));
                }
            };
            server_random = sh.server_random;
            negotiated_cipher_suite = sh.chosen_cipher_suite;
            println!(
                "[DEBUG] Parsed ServerHello: server_random={}, cipher_suite={:02x}{:02x}",
                hex::encode(server_random),
                negotiated_cipher_suite[0],
                negotiated_cipher_suite[1]
            );
            if let Some(ref key_share) = sh.server_key_share_public {
                println!(
                    "[DEBUG] Server key share ({} bytes): {}",
                    key_share.len(),
                    hex::encode(key_share)
                );
                if key_share.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(key_share);
                    server_key_share = Some(arr);
                }
            } else {
                println!("[DEBUG] No server key share found in ServerHello");
            }
        }
    }

    let server_public = server_key_share.ok_or_else(|| {
        TlsError::KeyDerivationError("No valid server key share found".to_string())
    })?;

    // 4. Compute shared secret (move client_secret)
    println!("[DEBUG] Deriving shared secret using client_secret and server_public");
    let shared_secret = derive_tls13_handshake_secret(client_secret, &server_public);
    println!("[DEBUG] Shared secret: {}", hex::encode(&shared_secret));

    // 5. Derive handshake secret (early secret, handshake secret, etc. - simplified for now)
    let handshake_secret = derive_hkdf_keys(&shared_secret, None, b"handshake secret", 32)?;
    println!(
        "[DEBUG] Handshake secret: {}",
        hex::encode(&handshake_secret)
    );

    // 6. Derive handshake traffic secrets using transcript hash
    let transcript_hash = transcript.clone_hash();
    println!("[DEBUG] Transcript hash: {}", hex::encode(&transcript_hash));
    let (client_hs_traffic_secret, server_hs_traffic_secret) =
        derive_tls13_handshake_traffic_secrets(&handshake_secret, &transcript_hash)?;
    println!(
        "[DEBUG] Client handshake traffic secret: {}",
        hex::encode(&client_hs_traffic_secret)
    );
    println!(
        "[DEBUG] Server handshake traffic secret: {}",
        hex::encode(&server_hs_traffic_secret)
    );

    // Now decrypt and parse any pending ApplicationData records
    for payload in pending_app_data_records.drain(..) {
        match crate::services::tls_handshake::tls13::record_layer::decrypt_record(
            &payload,
            &server_hs_traffic_secret,
            app_data_record_sequence,
        ) {
            Ok(plaintext) => {
                println!(
                    "[DEBUG] Decrypted ApplicationData record ({} bytes): {}",
                    plaintext.len(),
                    hex::encode(&plaintext[..std::cmp::min(32, plaintext.len())])
                );
                let messages = crate::services::tls_parser::parse_handshake_messages(&plaintext)?;
                println!(
                    "[DEBUG] Parsed {} handshake messages from decrypted ApplicationData",
                    messages.len()
                );
                for (i, msg) in messages.iter().enumerate() {
                    println!(
                        "[DEBUG] Decrypted handshake message {}: {:?} ({} bytes), first 8 bytes: {}",
                        i,
                        msg.msg_type,
                        msg.payload.len(),
                        hex::encode(&msg.payload[..std::cmp::min(8, msg.payload.len())])
                    );
                }
                all_messages.extend(messages);
            }
            Err(e) => {
                println!("[ERROR] Failed to decrypt ApplicationData record: {:?}", e);
            }
        }
        app_data_record_sequence += 1;
    }

    // 7. Read, decrypt, and parse EncryptedExtensions
    if let Some(ee_msg) = all_messages
        .iter()
        .find(|m| m.msg_type == HandshakeMessageType::EncryptedExtensions)
    {
        println!(
            "[DEBUG] Found EncryptedExtensions: {} bytes",
            ee_msg.payload.len()
        );
        // Optionally: parse or process the payload here
    } else {
        println!("[ERROR] EncryptedExtensions not found in handshake messages!");
    }

    // After all_messages is populated, print all handshake message types
    for (i, msg) in all_messages.iter().enumerate() {
        println!(
            "[DEBUG] all_messages[{}]: msg_type={:?} (raw: 0x{:02x}), len={}, first8={}",
            i,
            msg.msg_type,
            msg.msg_type as u8,
            msg.payload.len(),
            hex::encode(&msg.payload[..std::cmp::min(8, msg.payload.len())])
        );
        std::io::stdout().flush().unwrap();

        // Print the raw bytes of the handshake message
        println!(
            "[DEBUG] all_messages[{}] raw_bytes: {}",
            i,
            hex::encode(&msg.raw_bytes)
        );
        std::io::stdout().flush().unwrap();

        if msg.msg_type == HandshakeMessageType::ServerHello {
            println!("[DEBUG] >>> ENTERED ServerHello block <<<");
            std::io::stdout().flush().unwrap();
            // (You can comment out the rest if you only want to see if this is hit)
        }
    }

    Ok(Tls13ConnectionState {
        client_secret: None, // Consumed
        client_public,
        server_public,
        shared_secret,
        handshake_secret,
        client_hs_traffic_secret,
        server_hs_traffic_secret,
        negotiated_cipher_suite,
        server_random,
        client_random,
        transcript_hash,
    })
}

/// Build and send a TLS 1.3 ClientHello, then read and return all handshake messages from the server
pub fn read_all_handshake_messages(
    domain: &str,
) -> Result<Vec<crate::services::tls_parser::TlsHandshakeMessage>, TlsError> {
    let mut client_random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_random);
    // Generate X25519 keypair
    let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    let x25519_pubkey = public.as_bytes();
    // Build ClientHello
    let client_hello = build_client_hello(domain, &client_random, x25519_pubkey);
    println!("ClientHello (hex): {}", hex::encode(&client_hello));
    // Connect to server
    let mut stream =
        TcpStream::connect((domain, 443)).map_err(|e| TlsError::ConnectionFailed(e.to_string()))?;
    stream
        .write_all(&client_hello)
        .map_err(|e| TlsError::IoError(e))?;
    // Read and parse handshake messages from all records
    let mut all_messages = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => break, // connection closed
            Ok(n) => n,
            Err(e) => {
                if all_messages.is_empty() {
                    return Err(TlsError::IoError(e));
                } else {
                    break;
                }
            }
        };
        println!("Server response ({} bytes): {}", n, hex::encode(&buf[..n]));
        let mut cursor = std::io::Cursor::new(&buf[..n]);
        while let Ok(Some(record)) = crate::services::tls_parser::parse_tls_record(&mut cursor) {
            if record.content_type == crate::services::tls_parser::TlsContentType::Handshake {
                let messages =
                    crate::services::tls_parser::parse_handshake_messages(&record.payload)?;
                all_messages.extend(messages);
            } else {
                // Ignore non-handshake records for now
            }
        }
    }
    Ok(all_messages)
}

/// Read, decrypt, and parse the next handshake record (EncryptedExtensions) after ServerHello
pub fn read_and_decrypt_encrypted_extensions(
    stream: &mut std::net::TcpStream,
    server_hs_traffic_secret: &[u8],
    mut transcript: &mut crate::services::tls_handshake::tls13::transcript::TranscriptHash,
    record_sequence: u64,
) -> Result<(), TlsError> {
    use crate::services::tls_parser::{
        HandshakeMessageType, TlsContentType, parse_handshake_messages, parse_tls_record,
    };
    use std::io::Cursor;
    println!("[SANITY] Entered read_and_decrypt_encrypted_extensions");
    std::io::stdout().flush().unwrap();

    // Read enough bytes to ensure a full TLS record is present
    let mut buf = [0u8; 4096];
    let mut total_read = 0;
    // Read at least 5 bytes for the header
    while total_read < 5 {
        let n = stream
            .read(&mut buf[total_read..])
            .map_err(|e| TlsError::IoError(e))?;
        if n == 0 {
            return Err(TlsError::IoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed before record header",
            )));
        }
        total_read += n;
    }
    // Parse header to get record length
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    // Read until we have the full record
    while total_read < 5 + record_len {
        let n = stream
            .read(&mut buf[total_read..])
            .map_err(|e| TlsError::IoError(e))?;
        if n == 0 {
            return Err(TlsError::IoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed before full record",
            )));
        }
        total_read += n;
    }

    println!("[DEBUG] Read {} bytes from stream", total_read);
    println!(
        "[DEBUG] Buffer (first 32 bytes): {}",
        hex::encode(&buf[..std::cmp::min(32, total_read)])
    );
    std::io::stdout().flush().unwrap();

    let mut cursor = Cursor::new(&buf[..total_read]);
    // Read the next TLS record
    let record = parse_tls_record(&mut cursor)?.ok_or_else(|| {
        TlsError::ParserError(crate::services::tls_parser::TlsParserError::InvalidLength)
    })?;
    println!(
        "[DEBUG] Parsed record: content_type={:?}, version={:02x}{:02x}, length={}",
        record.content_type, record.version_major, record.version_minor, record.length
    );
    println!(
        "[DEBUG] Record payload len: {}, first 8 bytes: {}",
        record.payload.len(),
        hex::encode(&record.payload[..std::cmp::min(8, record.payload.len())])
    );
    std::io::stdout().flush().unwrap();

    // Decrypt the record payload
    let plaintext = decrypt_record(&record.payload, server_hs_traffic_secret, record_sequence)?;
    println!(
        "[DEBUG] Decrypted record plaintext len: {}, first 16 bytes: {}",
        plaintext.len(),
        hex::encode(&plaintext[..std::cmp::min(16, plaintext.len())])
    );
    println!(
        "[DEBUG] Decrypted plaintext (full): {}",
        hex::encode(&plaintext)
    );
    std::io::stdout().flush().unwrap();

    // Parse handshake messages from decrypted plaintext
    let messages = parse_handshake_messages(&plaintext)?;
    for msg in &messages {
        transcript.update(&msg.raw_bytes);
        if msg.msg_type == HandshakeMessageType::EncryptedExtensions {
            println!(
                "Parsed EncryptedExtensions: payload length {}",
                msg.payload.len()
            );
        } else {
            println!(
                "Parsed handshake message: {:?} ({} bytes)",
                msg.msg_type,
                msg.payload.len()
            );
        }
        std::io::stdout().flush().unwrap();
    }
    println!("[SANITY] Exiting read_and_decrypt_encrypted_extensions");
    std::io::stdout().flush().unwrap();
    Ok(())
}

pub fn test_send_client_hello_to_google() {
    let domain = "google.com";
    println!("--- TLS 1.3 handshake test to {} ---", domain);
    match perform_tls13_handshake_minimal(domain) {
        Ok(state) => {
            println!(
                "Handshake completed.\n  Server random: {}\n  Cipher suite: {:02x}{:02x}",
                hex::encode(state.server_random),
                state.negotiated_cipher_suite[0],
                state.negotiated_cipher_suite[1]
            );
            println!("  Transcript hash: {}", hex::encode(state.transcript_hash));
            println!(
                "  Client handshake traffic secret: {}",
                hex::encode(&state.client_hs_traffic_secret)
            );
            println!(
                "  Server handshake traffic secret: {}",
                hex::encode(&state.server_hs_traffic_secret)
            );
        }
        Err(e) => {
            println!("Handshake failed: {:?}", e);
        }
    }
}
