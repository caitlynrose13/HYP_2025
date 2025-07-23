use rand::RngCore;
use std::io::{Read, Write};
use std::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::services::errors::TlsError;
use crate::services::tls_handshake::tls13::key_schedule::derive_tls13_handshake_traffic_secrets;
use crate::services::tls_handshake::tls13::messages::build_client_hello;
use crate::services::tls_handshake::tls13::record_layer::decrypt_record;
use crate::services::tls_handshake::tls13::transcript::TranscriptHash;
use crate::services::tls_parser::CipherSuite;
use crate::services::tls_parser::parse_handshake_messages;

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

/// Perform a minimal TLS 1.3 handshake to derive traffic secrets.
/// This function sends a ClientHello, processes the ServerHello, and handles the first
/// encrypted handshake messages from the server.
pub fn perform_tls13_handshake_minimal(domain: &str) -> Result<Tls13ConnectionState, TlsError> {
    use crate::services::tls_handshake::keys::{derive_hkdf_keys, generate_x25519_keypair};
    use crate::services::tls_parser::{HandshakeMessageType, parse_tls13_server_hello_payload};

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

    // 3. Read ServerHello (should be the first message)
    // First read the header (5 bytes)
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

    println!(
        "[DEBUG] Initial record header: type={}, version={}.{}, length={}",
        content_type, version_major, version_minor, record_length
    );

    // Now read the record payload
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
        "[DEBUG] Read complete record: {} bytes payload",
        payload_read
    );

    // Construct the record
    let server_hello_record = crate::services::tls_parser::TlsRecord {
        content_type: crate::services::tls_parser::TlsContentType::from(content_type),
        version_major,
        version_minor,
        length: record_length as u16,
        payload: payload,
    };

    if server_hello_record.content_type != crate::services::tls_parser::TlsContentType::Handshake {
        return Err(TlsError::HandshakeError(
            "Expected Handshake record from server".to_string(),
        ));
    }

    let handshake_messages = parse_handshake_messages(&server_hello_record.payload)?;
    let server_hello_msg = handshake_messages
        .get(0)
        .ok_or_else(|| TlsError::HandshakeError("No handshake message in record".to_string()))?;

    if server_hello_msg.msg_type != HandshakeMessageType::ServerHello {
        return Err(TlsError::HandshakeError(
            "Expected ServerHello as first handshake message".to_string(),
        ));
    }

    let sh = parse_tls13_server_hello_payload(&server_hello_msg.payload)?;
    let server_random = sh.server_random;
    let negotiated_cipher_suite = sh.chosen_cipher_suite;
    let server_public = sh
        .server_key_share_public
        .ok_or_else(|| TlsError::KeyDerivationError("No server key share".to_string()))?;
    let server_public: [u8; 32] = server_public
        .try_into()
        .map_err(|_| TlsError::KeyDerivationError("Invalid server key length".to_string()))?;

    // 4. Update transcript and derive secrets
    let mut transcript = TranscriptHash::new();
    // The transcript should include the raw ClientHello and ServerHello messages
    // We need to reconstruct the raw ClientHello handshake message for the transcript
    let client_hello_hs_msg = crate::services::tls_parser::TlsHandshakeMessage {
        msg_type: HandshakeMessageType::ClientHello,
        length: (client_hello.len() - 9) as u32, // Total record len - record header (5) - handshake header (4)
        payload: client_hello[9..].to_vec(),
        raw_bytes: client_hello[5..].to_vec(), // The handshake message part of the record
    };
    transcript.update(&client_hello_hs_msg.raw_bytes);
    transcript.update(&server_hello_msg.raw_bytes);

    let shared_secret = derive_tls13_handshake_secret(client_secret, &server_public);
    let handshake_secret = derive_hkdf_keys(&shared_secret, None, b"handshake secret", 32)?;
    let transcript_hash = transcript.clone_hash();

    println!("[DEBUG] Shared secret length: {}", shared_secret.len());
    println!(
        "[DEBUG] Shared secret (hex): {}",
        hex::encode(&shared_secret)
    );
    println!(
        "[DEBUG] Handshake secret length: {}",
        handshake_secret.len()
    );
    println!(
        "[DEBUG] Handshake secret (hex): {}",
        hex::encode(&handshake_secret)
    );
    println!("[DEBUG] Transcript hash length: {}", transcript_hash.len());
    println!(
        "[DEBUG] Transcript hash (hex): {}",
        hex::encode(&transcript_hash)
    );

    let (client_hs_traffic_secret, server_hs_traffic_secret) =
        derive_tls13_handshake_traffic_secrets(&handshake_secret, &transcript_hash)?;

    println!(
        "[DEBUG] Client HS traffic secret length: {}",
        client_hs_traffic_secret.len()
    );
    println!(
        "[DEBUG] Client HS traffic secret (hex): {}",
        hex::encode(&client_hs_traffic_secret)
    );
    println!(
        "[DEBUG] Server HS traffic secret length: {}",
        server_hs_traffic_secret.len()
    );
    println!(
        "[DEBUG] Server HS traffic secret (hex): {}",
        hex::encode(&server_hs_traffic_secret)
    );

    // 5. Read and decrypt the next record (EncryptedExtensions, etc.)
    // Read the next record header
    let mut header = [0u8; 5];
    bytes_read = 0;

    while bytes_read < 5 {
        let n = stream
            .read(&mut header[bytes_read..])
            .map_err(|e| TlsError::IoError(e))?;
        if n == 0 {
            return Err(TlsError::HandshakeError(
                "Connection closed while reading next record header".to_string(),
            ));
        }
        bytes_read += n;
    }

    // Parse the header
    let content_type = header[0];
    let version_major = header[1];
    let version_minor = header[2];
    let record_length = u16::from_be_bytes([header[3], header[4]]) as usize;

    println!(
        "[DEBUG] Next record header: type={}, version={}.{}, length={}",
        content_type, version_major, version_minor, record_length
    );

    // Now read the record payload
    let mut payload = vec![0u8; record_length];
    let mut payload_read = 0;

    while payload_read < record_length {
        let n = stream
            .read(&mut payload[payload_read..])
            .map_err(|e| TlsError::IoError(e))?;
        if n == 0 {
            return Err(TlsError::HandshakeError(format!(
                "Connection closed while reading next record: got {} of {} bytes",
                payload_read, record_length
            )));
        }
        payload_read += n;
    }

    println!(
        "[DEBUG] Read complete next record: {} bytes payload",
        payload_read
    );

    // Construct the record
    let mut encrypted_record = crate::services::tls_parser::TlsRecord {
        content_type: crate::services::tls_parser::TlsContentType::from(content_type),
        version_major,
        version_minor,
        length: record_length as u16,
        payload: payload,
    };

    // Handle compatibility mode ChangeCipherSpec - in TLS 1.3, the server may send a CCS record
    // before encrypted handshake messages for middlebox compatibility
    if encrypted_record.content_type
        == crate::services::tls_parser::TlsContentType::ChangeCipherSpec
    {
        println!("[INFO] Received ChangeCipherSpec for compatibility mode - reading next record");

        // After CCS, read the next record more carefully
        let mut header = [0u8; 5];
        let mut bytes_read = 0;

        // Read exactly 5 bytes for the TLS record header
        while bytes_read < 5 {
            let n = stream
                .read(&mut header[bytes_read..])
                .map_err(|e| TlsError::IoError(e))?;
            if n == 0 {
                return Err(TlsError::HandshakeError(
                    "Connection closed while reading record header after CCS".to_string(),
                ));
            }
            bytes_read += n;
        }

        // Validate the record header
        let content_type = header[0];
        let version_major = header[1];
        let version_minor = header[2];

        if content_type != 23 {
            // 23 = ApplicationData in TLS
            println!(
                "[WARN] Expected ApplicationData (23) after CCS, got: {}",
                content_type
            );
        }

        if version_major != 3 || (version_minor != 3 && version_minor != 4) {
            println!(
                "[WARN] Unexpected TLS version after CCS: {}.{}",
                version_major, version_minor
            );
        }

        // Get the record length
        let record_length = u16::from_be_bytes([header[3], header[4]]) as usize;
        println!(
            "[DEBUG] Found record after CCS: type={}, version={}.{}, length={}",
            content_type, version_major, version_minor, record_length
        );

        // Reasonable length check (max TLS record is 16KB + some overhead)
        if record_length > 16384 + 256 {
            return Err(TlsError::HandshakeError(format!(
                "Unreasonable record length after CCS: {} bytes",
                record_length
            )));
        }

        // Read the record payload
        let mut payload = vec![0u8; record_length];
        let mut payload_read = 0;

        // Read with a reasonable timeout
        let start_time = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5);

        while payload_read < record_length {
            if start_time.elapsed() > timeout {
                println!(
                    "[DEBUG] Received partial record: {} of {} bytes",
                    payload_read, record_length
                );
                // Use what we have so far instead of failing
                break;
            }

            match stream.read(&mut payload[payload_read..]) {
                Ok(0) => {
                    println!(
                        "[DEBUG] Connection closed, got {} of {} bytes",
                        payload_read, record_length
                    );
                    // Try to process what we have instead of failing
                    break;
                }
                Ok(n) => {
                    payload_read += n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Non-blocking socket would block, wait a bit
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(TlsError::IoError(e));
                }
            }
        }

        println!(
            "[DEBUG] Read {} of {} bytes for record after CCS",
            payload_read, record_length
        );

        // Create a new record with what we've read
        encrypted_record = crate::services::tls_parser::TlsRecord {
            content_type: crate::services::tls_parser::TlsContentType::from(content_type),
            version_major,
            version_minor,
            length: payload_read as u16,
            payload: payload[..payload_read].to_vec(),
        };
    }

    if encrypted_record.content_type != crate::services::tls_parser::TlsContentType::ApplicationData
    {
        // In TLS 1.3, encrypted handshake messages are sent with content type ApplicationData
        // This is a simplification; they are actually type 23 but look like app data.
        // The record layer must be aware of the encryption state.
        println!(
            "[WARN] Expected ApplicationData record for encrypted handshake, got {:?} ({})",
            encrypted_record.content_type, encrypted_record.content_type as u8
        );

        if encrypted_record.content_type == crate::services::tls_parser::TlsContentType::Alert {
            // Try to parse the alert
            if encrypted_record.payload.len() >= 2 {
                let alert_level = encrypted_record.payload[0];
                let alert_desc = encrypted_record.payload[1];

                // Translate alert descriptions to meaningful messages
                let level_str = match alert_level {
                    1 => "Warning",
                    2 => "Fatal",
                    _ => "Unknown",
                };

                let desc_str = match alert_desc {
                    0 => "Close notify",
                    10 => "Unexpected message",
                    20 => "Bad record MAC",
                    22 => "Record overflow",
                    30 => "Decompression failure",
                    40 => "Handshake failure",
                    41 => "No certificate",
                    42 => "Bad certificate",
                    43 => "Unsupported certificate",
                    44 => "Certificate revoked",
                    45 => "Certificate expired",
                    46 => "Certificate unknown",
                    47 => "Illegal parameter",
                    48 => "Unknown CA",
                    49 => "Access denied",
                    50 => "Decode error",
                    51 => "Decrypt error",
                    70 => "Protocol version",
                    71 => "Insufficient security",
                    80 => "Internal error",
                    86 => "Inappropriate fallback",
                    90 => "User canceled",
                    100 => "No renegotiation",
                    109 => "Missing extension",
                    110 => "Unsupported extension",
                    112 => "Unrecognized name",
                    113 => "Bad certificate status response",
                    115 => "Unknown PSK identity",
                    116 => "Certificate required",
                    _ => "Unknown alert description",
                };

                println!(
                    "[ERROR] Received alert: level={} ({}), description={} ({})",
                    alert_level, level_str, alert_desc, desc_str
                );

                println!(
                    "[DEBUG] Alert payload hex: {}",
                    hex::encode(&encrypted_record.payload)
                );

                return Err(TlsError::HandshakeError(format!(
                    "Server sent alert: level={} ({}), description={} ({})",
                    alert_level, level_str, alert_desc, desc_str
                )));
            } else {
                println!(
                    "[ERROR] Received malformed alert: payload length {}",
                    encrypted_record.payload.len()
                );

                if !encrypted_record.payload.is_empty() {
                    println!(
                        "[DEBUG] Malformed alert payload hex: {}",
                        hex::encode(&encrypted_record.payload)
                    );
                }
            }
        }
    }

    // Create a CipherSuite instance using the negotiated cipher suite
    let cipher_suite_obj = CipherSuite::new(negotiated_cipher_suite[0], negotiated_cipher_suite[1]);

    println!(
        "[DEBUG] Decrypting with cipher suite: {:02x}{:02x} ({})",
        negotiated_cipher_suite[0], negotiated_cipher_suite[1], cipher_suite_obj.name
    );
    println!(
        "[DEBUG] Server HS traffic secret length: {}",
        server_hs_traffic_secret.len()
    );
    println!(
        "[DEBUG] Server HS traffic secret (hex): {}",
        hex::encode(&server_hs_traffic_secret)
    );
    println!(
        "[DEBUG] Encrypted record length: {}",
        encrypted_record.payload.len()
    );

    // Debug info about the record
    println!(
        "[DEBUG] Record type: {:?} ({}), version: {}.{}",
        encrypted_record.content_type,
        encrypted_record.content_type as u8,
        encrypted_record.version_major,
        encrypted_record.version_minor
    );

    // Show the beginning of the encrypted payload
    println!(
        "[DEBUG] Encrypted payload first bytes (hex): {}",
        hex::encode(&encrypted_record.payload[..std::cmp::min(64, encrypted_record.payload.len())])
    );

    let decrypted_payload = decrypt_record(
        &encrypted_record.payload,
        &server_hs_traffic_secret,
        0, // Sequence number for handshake messages is 0
        encrypted_record.content_type as u8,
        encrypted_record.version_major,
        encrypted_record.version_minor,
        &cipher_suite_obj,
    )?;

    // In TLS 1.3, the last byte of the plaintext is the real content type (0x17 for ApplicationData)
    let inner_plaintext = if decrypted_payload.ends_with(&[0x17]) {
        // Remove the content type byte at the end
        &decrypted_payload[..decrypted_payload.len() - 1]
    } else {
        println!("[WARN] Decrypted payload doesn't end with content type byte, using full payload");
        &decrypted_payload
    };

    println!("[DEBUG] Inner plaintext length: {}", inner_plaintext.len());
    if !inner_plaintext.is_empty() {
        println!(
            "[DEBUG] Inner plaintext (hex): {}",
            hex::encode(&inner_plaintext[..std::cmp::min(64, inner_plaintext.len())])
        );
    }

    let decrypted_messages = parse_handshake_messages(inner_plaintext)?;
    for msg in &decrypted_messages {
        println!("[DEBUG] Decrypted Handshake Message: {:?}", msg.msg_type);
        transcript.update(&msg.raw_bytes);
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
    stream: &mut TcpStream,
    server_hs_traffic_secret: &[u8],
    transcript: &mut crate::services::tls_handshake::tls13::transcript::TranscriptHash,
    record_sequence: u64,
    cipher_suite: &CipherSuite, // Add cipher_suite argument
) -> Result<(), TlsError> {
    use crate::services::tls_parser::{HandshakeMessageType, parse_tls_record};
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
    let plaintext = decrypt_record(
        &record.payload,
        server_hs_traffic_secret,
        record_sequence,
        record.content_type as u8,
        record.version_major,
        record.version_minor,
        cipher_suite, // Pass cipher_suite
    )?;
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
