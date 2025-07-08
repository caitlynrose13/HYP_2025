// src/services/tls_handshake.rs
use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use hex;
use hmac::{Hmac, Mac};
use p256::{
    EncodedPoint,
    ecdh::EphemeralSecret,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    elliptic_curve::sec1::FromEncodedPoint,
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use super::certificate_validator;
use super::errors::TlsError;
use super::tls_parser::{
    CipherSuite, HandshakeMessageType, ServerHelloParsed, ServerKeyExchangeParsed,
    TLS_CHANGE_CIPHER_SPEC, TLS_HANDSHAKE, TlsContentType, parse_certificate_list,
    parse_handshake_messages, parse_server_hello_content, parse_server_key_exchange_content,
    parse_tls_record,
};
use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit, Nonce};

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
    pub handshake_hasher: Sha256,
}

fn prf_tls12(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Result<Vec<u8>, TlsError> {
    type HmacSha256 = Hmac<Sha256>;

    let mut result = Vec::with_capacity(len);
    let mut a_n = Vec::new();

    // A(0) = label + seed
    a_n.extend_from_slice(label);
    a_n.extend_from_slice(seed);

    // Calculate A(1) = HMAC_hash(secret, A(0))
    let mut hmac_a = <HmacSha256 as KeyInit>::new_from_slice(secret).map_err(|_| {
        // FIX HERE
        TlsError::KeyDerivationError("Invalid HMAC secret length for PRF A(1)".to_string())
    })?;
    hmac_a.update(&a_n);
    let a1_output = hmac_a.finalize().into_bytes().to_vec();
    a_n = a1_output; // Update A(n) for next iteration

    // Loop to generate enough output
    while result.len() < len {
        let mut hmac_p = <HmacSha256 as KeyInit>::new_from_slice(secret).map_err(|_| {
            // FIX HERE
            TlsError::KeyDerivationError("Invalid HMAC secret length for PRF P_hash".to_string())
        })?;
        hmac_p.update(&a_n); // Use the current A(n)
        let p_output = hmac_p.finalize().into_bytes().to_vec();

        result.extend_from_slice(&p_output);

        if result.len() < len {
            // Calculate A(n+1) = HMAC_hash(secret, A(n)) for the next iteration
            let mut hmac_a_next =
                <HmacSha256 as KeyInit>::new_from_slice(secret).map_err(|_| {
                    // FIX HERE
                    TlsError::KeyDerivationError(
                        "Invalid HMAC secret length for PRF A(i+1)".to_string(),
                    )
                })?;
            hmac_a_next.update(&a_n);
            a_n = hmac_a_next.finalize().into_bytes().to_vec();
        }
    }

    result.truncate(len); // Truncate to the exact desired length
    Ok(result)
}

pub fn derive_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    tls_version: TlsVersion, // Used to select PRF version
) -> Result<Vec<u8>, TlsError> {
    if tls_version != TlsVersion::Tls12 {
        return Err(TlsError::KeyDerivationError(
            "Only TLS 1.2 Master Secret derivation supported for now.".to_string(),
        ));
    }

    let mut seed = Vec::new();
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);

    // Master Secret = PRF(Pre-Master Secret, "master secret", ClientHello.random + ServerHello.random)
    prf_tls12(pre_master_secret, b"master secret", &seed, 48) // Master Secret is always 48 bytes
}

pub fn derive_key_block(
    master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    chosen_cipher_suite: &CipherSuite, // Directly use CipherSuite as imported
    tls_version: TlsVersion,
) -> Result<Vec<u8>, TlsError> {
    if tls_version != TlsVersion::Tls12 {
        return Err(TlsError::KeyDerivationError(
            "Only TLS 1.2 Key Block derivation supported for now.".to_string(),
        ));
    }

    let mut seed = Vec::new();
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let key_len = chosen_cipher_suite.key_length as usize;
    let fixed_iv_len = chosen_cipher_suite.fixed_iv_length as usize;
    let mac_key_len = chosen_cipher_suite.mac_key_length as usize;

    let key_block_len = (mac_key_len * 2) + (key_len * 2) + (fixed_iv_len * 2);

    prf_tls12(master_secret, b"key expansion", &seed, key_block_len)
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

    // TLS Version (e.g., TLS 1.2 is 0x0303, TLS 1.3 is 0x0304)
    let (major, minor) = tls_version.into();
    client_hello.push(major);
    client_hello.push(minor);

    // Client Random (32 bytes)
    client_hello.extend_from_slice(client_random);

    // Session ID (1 byte length + Session ID bytes)
    client_hello.push(0x00); // Session ID length (0 for empty)

    // Cipher Suites (2 bytes length + list of 2-byte cipher suite IDs)
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

// A proper implementation for TLS_ECDHE_..._AES_128_GCM_SHA256
// A proper implementation for TLS_ECDHE_..._AES_128_GCM_SHA256
pub fn encrypt_gcm_message(
    plaintext: &[u8],
    key: &[u8],
    fixed_iv: &[u8],   // The 4-byte part from the key block
    sequence_num: u64, // The record sequence number (starts at 0 for this message)
    content_type: u8,
    tls_version: TlsVersion,
) -> Result<Vec<u8>, TlsError> {
    // Key must be exactly 16 bytes for AES-128
    if key.len() != 16 {
        return Err(TlsError::EncryptionError(format!(
            "Invalid key length for AES128GCM: expected 16, got {}",
            key.len()
        )));
    }
    // Fixed IV must be exactly 4 bytes for TLS 1.2 GCM
    if fixed_iv.len() != 4 {
        return Err(TlsError::EncryptionError(format!(
            "Invalid fixed_iv length for TLS 1.2 GCM: expected 4, got {}",
            fixed_iv.len()
        )));
    }

    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| TlsError::EncryptionError(format!("Failed to create cipher: {}", e)))?;

    // Construct the 12-byte nonce: 4-byte fixed IV + 8-byte explicit nonce (sequence number)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(fixed_iv);
    // The explicit nonce in TLS 1.2 GCM is typically the 8-byte sequence number.
    // Ensure `sequence_num` is correctly converted to 8 bytes.
    nonce_bytes[4..].copy_from_slice(&sequence_num.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Construct the Additional Associated Data (AAD) for TLS 1.2
    // AAD = sequence_number(8) + content_type(1) + version(2) + length(2) = 13 bytes
    let (major, minor) = tls_version.into(); // Assuming TlsVersion has an `into()` or `to_u8_pair()` method
    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&sequence_num.to_be_bytes()); // Opaque sequence number
    aad.push(content_type); // Record content type
    aad.push(major); // TLS version major
    aad.push(minor); // TLS version minor
    aad.extend_from_slice(&(plaintext.len() as u16).to_be_bytes()); // Plaintext length

    // The buffer for encrypt_in_place should contain [explicit_nonce (8 bytes) | plaintext]
    // The GCM tag (16 bytes) will be appended to this buffer by the encryption function.
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&sequence_num.to_be_bytes()); // explicit_nonce part of the *encrypted payload*
    buffer.extend_from_slice(plaintext); // The actual content to encrypt

    println!(
        "GCM Encryption: Plaintext len={}, AAD len={}, Nonce = {:x?}",
        plaintext.len(),
        aad.len(),
        nonce
    );
    println!(
        "GCM Encryption: Key = {:x?}, Fixed IV = {:x?}, Sequence Num = {}",
        key, fixed_iv, sequence_num
    );

    cipher
        .encrypt_in_place(nonce, &aad, &mut buffer)
        .map_err(|e| TlsError::EncryptionError(format!("GCM encryption failed: {:?}", e)))?; // Use {:?} for Display/Debug for AEAD errors

    // The buffer now contains [explicit_nonce (8 bytes) | ciphertext | GCM tag (16 bytes)]
    // This entire `buffer` will be the payload of the TLS record.
    Ok(buffer)
}

pub fn verify_server_key_exchange_signature(
    ske: &ServerKeyExchangeParsed,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    cert_chain: &[Vec<u8>],
) -> Result<(), TlsError> {
    println!("    Attempting to verify ServerKeyExchange signature...");

    let cert_der = cert_chain
        .get(0)
        .ok_or_else(|| TlsError::CertificateError("No server certificate provided.".into()))?;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| TlsError::CertificateError(format!("Failed to parse server cert: {:?}", e)))?;

    let spki_bytes = cert.tbs_certificate.subject_pki.subject_public_key.data;

    let pub_key_point = EncodedPoint::from_bytes(spki_bytes)
        .map_err(|_| TlsError::CertificateError("Invalid SPKI EC point format.".into()))?;

    let verifying_key = VerifyingKey::from_encoded_point(&pub_key_point).map_err(|e| {
        TlsError::CertificateError(format!("Failed to create VerifyingKey from point: {:?}", e))
    })?;

    let mut hasher = sha2::Sha256::new();
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
) -> Result<TlsConnectionState, TlsError> {
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

    let mut handshake_transcript_hash = sha2::Sha256::new();

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

    let client_hello_handshake_message = &client_hello[5..]; // The Handshake message part without record header
    handshake_transcript_hash.update(client_hello_handshake_message);

    stream.write_all(&client_hello)?;
    println!("Sent ClientHello ({} bytes)", client_hello.len());

    let mut server_response_buffer = Vec::new();
    let mut temp_buffer = [0; 4096];

    // ... (rest of reading server response, unchanged) ...
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
                // A better approach for reading records would be to parse
                // records iteratively and only break when expected records are received.
                // For now, this simple read-all might suffice for small handshakes.
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
        handle_server_hello_flight(
            &server_response_buffer,
            tls_version,
            &mut handshake_transcript_hash, // Pass mutable reference to update hasher
        )?;

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
    if let Some(ske_parsed_debug) = &server_key_exchange_parsed {
        println!(
            "Server Key Exchange Payload: {} bytes",
            ske_parsed_debug.public_key.len()
        );
    }

    // --- Certificate Validation ---
    println!("\n--- Phase 2: Performing Certificate Validation & Hostname Verification ---");
    certificate_validator::validate_server_certificate(&certificates, domain)?;
    println!("Server certificate chain and hostname validated successfully!");

    // --- Core Handshake Logic: Based on TLS Version ---
    // This block now sets up and returns all the derived keys as owned Vec<u8>
    let (
        master_secret,
        client_write_key,
        server_write_key,
        client_fixed_iv,
        server_fixed_iv,
        chosen_cipher_suite_struct,
    ) = if tls_version == TlsVersion::Tls12 {
        let ske = server_key_exchange_parsed.ok_or_else(|| {
            TlsError::HandshakeFailed(
                "ServerKeyExchange expected but not received for TLS 1.2 ECDHE cipher suite."
                    .into(),
            )
        })?;

        println!("--- Phase 2.5: Verifying ServerKeyExchange Signature ---");
        verify_server_key_exchange_signature(
            &ske,
            &client_random,
            &server_hello_parsed.server_random,
            &certificates,
        )?;
        println!("✓ ServerKeyExchange signature verified.");

        use p256::{EncodedPoint, PublicKey};

        println!("--- Phase 3.1: Computing Pre-Master Secret ---");

        let server_ephemeral_point = EncodedPoint::from_bytes(&ske.public_key).map_err(|_| {
            TlsError::KeyDerivationError("Invalid server ephemeral public key format".into())
        })?;

        let server_public_key = PublicKey::from_encoded_point(&server_ephemeral_point)
            .into_option()
            .ok_or_else(|| {
                TlsError::KeyDerivationError("Invalid EC point encoding or public key.".into())
            })?;

        let shared_secret = client_ephemeral_secret.diffie_hellman(&server_public_key);
        let pre_master_secret = shared_secret.raw_secret_bytes().to_vec();

        println!(
            "✓ Pre-Master Secret computed ({} bytes)",
            pre_master_secret.len()
        );

        println!("--- Phase 3.2: Deriving Master Secret ---");
        let master_secret = derive_master_secret(
            &pre_master_secret,
            &client_random,
            &server_hello_parsed.server_random,
            tls_version,
        )?;
        println!("✓ Master Secret derived ({} bytes)", master_secret.len());

        println!("--- Phase 3.3: Deriving Key Block ---");

        let chosen_cipher_suite_struct =
            super::tls_parser::get_cipher_suite_by_id(&server_hello_parsed.chosen_cipher_suite)
                .ok_or_else(|| {
                    TlsError::HandshakeFailed("Unsupported cipher suite from server".into())
                })?;

        let key_block = derive_key_block(
            &master_secret,
            &client_random,
            &server_hello_parsed.server_random,
            chosen_cipher_suite_struct,
            tls_version,
        )?;
        println!("Key Block derived ({} bytes)", key_block.len());

        let key_len = chosen_cipher_suite_struct.key_length as usize;
        let fixed_iv_len = chosen_cipher_suite_struct.fixed_iv_length as usize;
        let mac_key_len = chosen_cipher_suite_struct.mac_key_length as usize; // Added this line

        // Clone slices to own the data and return them from the if block
        let client_write_key = key_block[mac_key_len..(mac_key_len + key_len)].to_vec();
        let server_write_key =
            key_block[(mac_key_len + key_len)..(mac_key_len + key_len * 2)].to_vec();
        let client_fixed_iv = key_block
            [(mac_key_len + key_len * 2)..(mac_key_len + key_len * 2 + fixed_iv_len)]
            .to_vec();
        let server_fixed_iv = key_block[(mac_key_len + key_len * 2 + fixed_iv_len)
            ..(mac_key_len + key_len * 2 + fixed_iv_len * 2)]
            .to_vec();

        println!("✓ Extracted individual session keys from Key Block.");

        (
            master_secret,
            client_write_key,
            server_write_key,
            client_fixed_iv,
            server_fixed_iv,
            chosen_cipher_suite_struct,
        )
    } else if tls_version == TlsVersion::Tls13 {
        return Err(TlsError::HandshakeFailed(
            "TLS 1.3 key exchange not yet implemented.".into(),
        ));
    } else {
        return Err(TlsError::HandshakeFailed(
            "Unsupported TLS version or key exchange type.".into(),
        ));
    };

    // --- Phase 4: Client Sends ChangeCipherSpec and Finished ---
    println!("\n--- Phase 4: Client Sending Final Handshake ---");

    // First, get the final hash of all messages up to this point for the client's Finished message
    // We CLONE the hasher because its state is needed for verifying the server's Finished message later.
    let client_finished_hash_input = handshake_transcript_hash.clone().finalize();

    // Second, compute the verify_data using the PRF
    let verify_data = prf_tls12(
        &master_secret,
        b"client finished",
        client_finished_hash_input.as_slice(),
        12, // verify_data is 12 bytes for TLS 1.2
    )?;
    println!("✓ Computed Finished verify_data");

    // Third, construct the plaintext Finished handshake message
    let mut finished_message_plaintext = Vec::new();
    finished_message_plaintext.push(HandshakeMessageType::Finished as u8); // 0x14
    finished_message_plaintext.extend_from_slice(&(12u32.to_be_bytes()[1..])); // Length (12)
    finished_message_plaintext.extend_from_slice(&verify_data);

    // Update the handshake hash with the *plaintext* Finished message
    handshake_transcript_hash.update(&finished_message_plaintext);
    println!("Added plaintext Client Finished message to handshake transcript hash.");

    // Send the ChangeCipherSpec message FIRST (it's not encrypted)
    let change_cipher_spec = build_change_cipher_spec(); // This is a simple 1-byte message for TLS 1.2
    stream.write_all(&change_cipher_spec)?;
    println!("Sent ChangeCipherSpec.");

    // Now, call the real encryption function to get the payload
    let encrypted_finished_payload = encrypt_gcm_message(
        &finished_message_plaintext,
        &client_write_key,                // Borrow reference to the owned Vec<u8>
        &client_fixed_iv,                 // Borrow reference to the owned Vec<u8>
        0, // This is the first encrypted record, so client sequence number is 0
        super::tls_parser::TLS_HANDSHAKE, // Content Type for Finished message
        tls_version,
    )?;
    println!(
        "✓ Encrypted Finished message payload generated ({} bytes).",
        encrypted_finished_payload.len()
    );

    // Wrap the encrypted payload in a TLS record and send it
    let mut encrypted_finished_record = Vec::new();
    encrypted_finished_record.push(super::tls_parser::TLS_HANDSHAKE); // Content Type: Handshake
    let (major, minor) = tls_version.into();
    encrypted_finished_record.push(major);
    encrypted_finished_record.push(minor);
    encrypted_finished_record
        .extend_from_slice(&(encrypted_finished_payload.len() as u16).to_be_bytes());
    encrypted_finished_record.extend_from_slice(&encrypted_finished_payload);

    stream.write_all(&encrypted_finished_record)?;
    println!(
        "Sent Encrypted Finished record ({} bytes).",
        encrypted_finished_record.len()
    );

    // --- Phase 5: Awaiting Server ChangeCipherSpec and Finished ---
    println!("--- Phase 5: Awaiting Server Final Handshake ---");
    let mut final_server_response_buffer = Vec::new();
    // ... (rest of server response reading loop, unchanged for now) ...
    loop {
        match stream.read(&mut temp_buffer) {
            Ok(0) => break, // EOF
            Ok(n) => {
                final_server_response_buffer.extend_from_slice(&temp_buffer[..n]);
                // A robust solution would parse records here and break once expected ones are received.
                // For a simple handshake, an arbitrary length might work.
                if final_server_response_buffer.len() > 100 {
                    // Enough for CCS + Encrypted Finished
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100)); // Wait a bit if no data immediately
            }
            Err(e) => return Err(TlsError::IoError(e)),
        }
    }
    println!(
        "Received server's final handshake bytes. Need to parse ChangeCipherSpec and Finished."
    );

    // TODO: Parse and verify server's ChangeCipherSpec and Finished messages
    // This involves decrypting the Finished message and verifying its content (using server_write_key/IV)
    // and verifying the server's handshake_messages_hash.

    println!("\n✓ TLS Handshake process completed (remaining steps are placeholders).");

    Ok(TlsConnectionState {
        master_secret,
        client_write_key,
        server_write_key,
        client_fixed_iv,
        server_fixed_iv,
        client_sequence_number: 1, // Next client outgoing record will be 1
        server_sequence_number: 0, // Server's first incoming record (Finished) is 0
        negotiated_cipher_suite: *chosen_cipher_suite_struct,
        negotiated_tls_version: tls_version,
        client_random,
        server_random: server_hello_parsed.server_random, // Store server_random for future use
        handshake_hasher: handshake_transcript_hash, // Pass the hasher state for server Finished verification
    })
}

// (The handle_server_hello_flight function would come after perform_tls_handshake_full)
pub fn handle_server_hello_flight(
    response_bytes: &[u8],
    _tls_client_version: TlsVersion,
    handshake_transcript_hash: &mut Sha256,
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

                            handshake_transcript_hash.update(&msg.raw_bytes);
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
