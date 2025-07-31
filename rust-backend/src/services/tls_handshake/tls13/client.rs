use crate::services::errors::TlsError;
use crate::services::tls_handshake::tls13::handshake_processor::{
    process_encrypted_handshake_records, read_tls_record,
};
use crate::services::tls_handshake::tls13::key_schedule::derive_tls13_handshake_traffic_secrets_dynamic;
use crate::services::tls_handshake::tls13::messages::build_client_hello;
use crate::services::tls_handshake::tls13::transcript::{TranscriptHash, TranscriptHashAlgorithm};
use crate::services::tls_parser::CipherSuite;
use crate::services::tls_parser::{
    HandshakeMessageType, parse_handshake_messages, parse_tls13_server_hello_payload,
};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use std::io::Write;
use std::net::TcpStream;

#[allow(dead_code)]
pub struct Tls13ConnectionState {
    pub client_secret: Option<[u8; 32]>, // Option so we can take ownership
    pub client_public: [u8; 32],
    pub server_public: [u8; 32],
    pub shared_secret: [u8; 32],
    pub client_hs_traffic_secret: Vec<u8>,
    pub server_hs_traffic_secret: Vec<u8>,
    pub negotiated_cipher_suite: [u8; 2],
    pub server_random: [u8; 32],
    pub client_random: [u8; 32],
    pub transcript_hash: Vec<u8>,
}
pub fn perform_tls13_handshake_minimal(
    domain: &str,
) -> Result<(Tls13ConnectionState, Option<Vec<u8>>), TlsError> {
    let rng = SystemRandom::new();
    let mut client_random = [0u8; 32];
    rng.fill(&mut client_random).map_err(|e| {
        TlsError::KeyExchangeError(format!("Failed to generate client random: {:?}", e))
    })?;

    // Add timestamp to first 4 bytes to ensure each connection is unique
    // This prevents any potential session caching or 0-RTT issues with Google
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    client_random[0..4].copy_from_slice(&timestamp.to_be_bytes());

    // Generate X25519 keypair using ring
    let client_private = EphemeralPrivateKey::generate(&X25519, &rng).map_err(|e| {
        TlsError::KeyExchangeError(format!("Failed to generate X25519 private key: {:?}", e))
    })?;
    let client_public_bytes: [u8; 32] = {
        let pk = client_private.compute_public_key().unwrap();
        let pk_bytes = pk.as_ref();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pk_bytes);
        arr
    };

    let client_hello = build_client_hello(domain, &client_random, &client_public_bytes);
    use crate::services::tls_handshake::tls13::messages::build_raw_client_hello_handshake;
    let _raw_client_hello =
        build_raw_client_hello_handshake(domain, &client_random, &client_public_bytes);
    let mut stream =
        TcpStream::connect((domain, 443)).map_err(|e| TlsError::ConnectionFailed(e.to_string()))?;
    stream
        .write_all(&client_hello)
        .map_err(|e| TlsError::IoError(e))?;

    // 3. Read ServerHello using the modular function
    let server_hello_record = read_tls_record(&mut stream)?;

    if server_hello_record.content_type != crate::services::tls_parser::TlsContentType::Handshake {
        return Err(TlsError::HandshakeError(format!(
            "Expected Handshake record from server, got {:?} with length {}",
            server_hello_record.content_type, server_hello_record.length
        )));
    }

    // Parse handshake messages to find the Certificate message
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
        .map_err(|_| TlsError::KeyExchangeError("Invalid server key length".to_string()))?;

    let cipher_suite_obj = CipherSuite::new(negotiated_cipher_suite[0], negotiated_cipher_suite[1]);
    if cipher_suite_obj.id == [0x00, 0x00] {
        return Err(TlsError::UnsupportedCipherSuite(format!(
            "Cipher suite {:02x}{:02x} not supported",
            negotiated_cipher_suite[0], negotiated_cipher_suite[1]
        )));
    }
    let hash_alg = match cipher_suite_obj.hash_algorithm {
        crate::services::tls_parser::HashAlgorithm::Sha256 => TranscriptHashAlgorithm::Sha256,
        crate::services::tls_parser::HashAlgorithm::Sha384 => TranscriptHashAlgorithm::Sha384,
    };
    let mut transcript = TranscriptHash::new(hash_alg.clone());

    transcript.update(&client_hello[5..]);

    transcript.update(&server_hello_msg.raw_bytes);

    // Use ring to perform X25519 key exchange
    let shared_secret: [u8; 32] = ring::agreement::agree_ephemeral(
        client_private,
        &UnparsedPublicKey::new(&X25519, &server_public),
        |secret| {
            let mut out = [0u8; 32];
            out.copy_from_slice(secret);
            out
        },
    )
    .map_err(|_| TlsError::KeyExchangeError("Failed to derive shared secret".to_string()))?;

    // Use the correct TLS 1.3 key derivation function
    let (client_hs_traffic_secret, server_hs_traffic_secret) =
        derive_tls13_handshake_traffic_secrets_dynamic(
            &shared_secret,
            &transcript,
            hash_alg.clone(),
        )?;

    let cipher_suite_obj = CipherSuite::new(negotiated_cipher_suite[0], negotiated_cipher_suite[1]);

    let dummy_app_secret = vec![0u8; server_hs_traffic_secret.len()];

    let _decrypted_records = process_encrypted_handshake_records(
        &mut stream,
        &server_hs_traffic_secret,
        &dummy_app_secret, // Dummy value - handshake phase uses HS secrets only
        &cipher_suite_obj,
        &mut transcript,
    )?;

    use crate::services::tls_handshake::tls13::key_schedule::derive_tls13_application_traffic_secrets;
    let (_client_app_traffic_secret, server_app_traffic_secret) =
        derive_tls13_application_traffic_secrets(&shared_secret, &transcript, hash_alg.clone())?;

    use crate::services::tls_handshake::tls13::record_layer::decrypt_record;

    let mut handshake_sequence_number = 0u64; // Start from 0 for first encrypted record

    for _attempt in 0..3 {
        match read_tls_record(&mut stream) {
            Ok(record) => {
                match record.content_type {
                    crate::services::tls_parser::TlsContentType::ApplicationData => {
                        // Try different sequence numbers in case we're off
                        for seq_attempt in 0..5 {
                            let try_seq = handshake_sequence_number + seq_attempt;
                            println!("[DEBUG] Trying sequence number: {}", try_seq);

                            match decrypt_record(
                                &record.payload,
                                &server_hs_traffic_secret,
                                &server_app_traffic_secret,
                                try_seq,
                                0x17, // ApplicationData record type
                                record.version_major,
                                record.version_minor,
                                record.length,
                                &cipher_suite_obj,
                            ) {
                                Ok(decrypted) => {
                                    println!(
                                        "[SUCCESS] Decrypted {} bytes with sequence {}",
                                        decrypted.len(),
                                        try_seq
                                    );
                                    if !decrypted.is_empty() {
                                        println!(
                                            "[DEBUG] Decrypted content: {:02x?}",
                                            &decrypted[..std::cmp::min(64, decrypted.len())]
                                        );
                                    }
                                    handshake_sequence_number = try_seq + 1;
                                    break;
                                }
                                Err(e) => {
                                    if seq_attempt == 4 {
                                        eprintln!(
                                            "[ERROR] Failed to decrypt with all sequence attempts: {:?}",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    crate::services::tls_parser::TlsContentType::Handshake => {
                        println!(
                            "[DEBUG] Received post-handshake record (likely NewSessionTicket)"
                        );
                        // This uses application traffic secret in TLS 1.3
                        match decrypt_record(
                            &record.payload,
                            &server_hs_traffic_secret,
                            &server_app_traffic_secret, // Post-handshake messages use app secret
                            handshake_sequence_number,
                            0x16, // Handshake record type
                            record.version_major,
                            record.version_minor,
                            record.length,
                            &cipher_suite_obj,
                        ) {
                            Ok(decrypted) => {
                                println!(
                                    "[SUCCESS] Decrypted {} bytes of post-handshake",
                                    decrypted.len()
                                );
                                if !decrypted.is_empty() {
                                    println!(
                                        "[DEBUG] Post-handshake content: {:02x?}",
                                        &decrypted[..std::cmp::min(32, decrypted.len())]
                                    );
                                }
                            }
                            Err(e) => {
                                eprintln!("[ERROR] Failed to decrypt post-handshake: {:?}", e);
                            }
                        }
                        handshake_sequence_number += 1;
                    }
                    _ => {
                        println!(
                            "[DEBUG] Received other record type: {:?}",
                            record.content_type
                        );
                    }
                }
            }
            Err(_) => {
                break;
            }
        }
    }

    // Extract certificate bytes from handshake messages
    let mut server_certificate: Option<Vec<u8>> = None;
    for msg in handshake_messages.iter() {
        if msg.msg_type == HandshakeMessageType::Certificate {
            // Parse the certificate list (skip first 4 bytes if needed)
            if let Ok(certificates) =
                crate::services::tls_parser::parse_certificate_list(&msg.raw_bytes[4..])
            {
                server_certificate = certificates.get(0).cloned();
            }
            break;
        }
    }

    Ok((
        Tls13ConnectionState {
            client_secret: None, // ring does not expose private key bytes
            client_public: client_public_bytes.try_into().unwrap(),
            server_public,
            shared_secret,
            client_hs_traffic_secret: client_hs_traffic_secret.clone(),
            server_hs_traffic_secret: server_hs_traffic_secret.clone(),
            negotiated_cipher_suite,
            server_random,
            client_random,
            transcript_hash: transcript
                .clone_hash()
                .map_err(|e| TlsError::HandshakeError(e.to_string()))?,
        },
        server_certificate,
    ))
}

pub fn test_tls13(domain: &str) -> Result<Option<Vec<u8>>, TlsError> {
    perform_tls13_handshake_minimal(domain).map(|(_state, cert)| cert)
}
