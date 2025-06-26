// Raw TLS handshake (no libraries like rustls or native-tls)
use p256::ecdh::EphemeralSecret; // Used to generate temporary EC key pairs
use p256::elliptic_curve::sec1::ToEncodedPoint; // Convert EC pubkey to byte format
use rand::Rng;
use rand::thread_rng;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

// Basic error types to handle common TLS issues
#[derive(Debug)]
pub enum TlsError {
    ConnectionFailed(String),
    HandshakeFailed(String),
    IoError(std::io::Error),
    InvalidAddress(String),
    KeyGenerationFailed(String),
}

impl From<std::io::Error> for TlsError {
    fn from(e: std::io::Error) -> Self {
        TlsError::IoError(e)
    }
}

// We're only handling TLS 1.2 and 1.3 since TlS 1.0 and 1.1 are deprecated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls1_2,
    Tls1_3,
}

// Opens a TCP connection, sends a ClientHello, and returns the raw server response
pub fn perform_tls_handshake(domain: &str, tls_version: TlsVersion) -> Result<Vec<u8>, TlsError> {
    let addr_str = format!("{}:443", domain);
    let mut addrs_iter = addr_str
        .to_socket_addrs()
        .map_err(|e| TlsError::InvalidAddress(format!("Couldn't resolve address: {}", e)))?;
    let addr = addrs_iter
        .next()
        .ok_or_else(|| TlsError::ConnectionFailed(format!("No address found for {}", domain)))?;

    // Connect to the server (with a 10-second timeout)
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| TlsError::ConnectionFailed(format!("TCP connect failed: {}", e)))?;

    // Also limit how long we'll wait for a response
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    // Build and send the ClientHello message
    let client_hello = build_client_hello(domain, tls_version)?;
    stream.write_all(&client_hello)?;

    // Read back the first part of the server response
    let mut response = vec![0; 4096];
    let n = stream.read(&mut response)?;

    Ok(response[..n].to_vec())
}

// Constructs a valid ClientHello depending on the TLS version
fn build_client_hello(domain: &str, tls_version: TlsVersion) -> Result<Vec<u8>, TlsError> {
    let mut hello: Vec<u8> = vec![];

    // Decide what version values to put in the record layer and legacy fields
    let (record_header_version, client_hello_legacy_version) = match tls_version {
        TlsVersion::Tls1_2 => ([0x03, 0x03], [0x03, 0x03]),
        TlsVersion::Tls1_3 => ([0x03, 0x01], [0x03, 0x03]),
    };

    // TLS Record header
    hello.push(0x16); // Handshake record type
    hello.extend_from_slice(&record_header_version); // TLS version
    hello.extend_from_slice(&[0x00, 0x00]); // Placeholder for record length

    // Handshake header (ClientHello)
    let handshake_start_idx = hello.len();
    hello.push(0x01); // HandshakeType = ClientHello
    hello.extend_from_slice(&[0x00, 0x00, 0x00]); // Placeholder for handshake length

    // Legacy version (still required even in TLS 1.3)
    hello.extend_from_slice(&client_hello_legacy_version);

    // Add 32 random bytes (used as a client random)
    let mut rng = thread_rng();
    let mut random_bytes = [0u8; 32];
    rng.fill(&mut random_bytes);
    hello.extend_from_slice(&random_bytes);

    hello.push(0x00); // Session ID length = 0 (no session resumption)

    // Add cipher suites
    let cipher_suites = match tls_version {
        TlsVersion::Tls1_2 => vec![0x00, 0x2F, 0x00, 0x35, 0xC0, 0x2B],
        TlsVersion::Tls1_3 => vec![0x13, 0x01, 0x13, 0x02, 0x13, 0x03],
    };
    hello.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    hello.extend_from_slice(&cipher_suites);

    // Only null compression (no compression)
    hello.push(0x01);
    hello.push(0x00);

    // ----- Extensions start here -----
    let mut extensions: Vec<u8> = vec![];

    // SNI (Server Name Indication)
    extensions.extend_from_slice(&[0x00, 0x00]); // Extension type
    let sni_data_start_idx = extensions.len();
    extensions.extend_from_slice(&[0x00, 0x00]); // Placeholder for SNI total length
    extensions.extend_from_slice(&[0x00, 0x00]); // Placeholder for ServerName list length
    extensions.push(0x00); // NameType = host_name

    let domain_bytes = domain.as_bytes();
    let domain_len = domain_bytes.len() as u16;
    extensions.extend_from_slice(&domain_len.to_be_bytes());
    extensions.extend_from_slice(domain_bytes);

    // Backfill the length fields for SNI
    let sni_list_len = (domain_len + 3) as u16;
    let sni_total_len = sni_list_len + 2;
    extensions[sni_data_start_idx..sni_data_start_idx + 2]
        .copy_from_slice(&sni_total_len.to_be_bytes());
    extensions[sni_data_start_idx + 2..sni_data_start_idx + 4]
        .copy_from_slice(&sni_list_len.to_be_bytes());

    // Add extra extensions for TLS 1.3
    if tls_version == TlsVersion::Tls1_3 {
        // supported_versions (we say we support TLS 1.3)
        extensions.extend_from_slice(&[0x00, 0x2B]);
        extensions.extend_from_slice(&[0x00, 0x03]);
        extensions.push(0x02);
        extensions.push(0x03);
        extensions.push(0x04);

        // supported_groups (we support P-256 and X25519)
        extensions.extend_from_slice(&[0x00, 0x0A]);
        extensions.extend_from_slice(&[0x00, 0x08]);
        extensions.extend_from_slice(&[0x00, 0x06]);
        extensions.extend_from_slice(&[0x00, 0x17]); // secp256r1
        extensions.extend_from_slice(&[0x00, 0x1D]); // x25519

        // key_share (send a public EC key for P-256)
        extensions.extend_from_slice(&[0x00, 0x33]);
        let key_share_data_start_idx = extensions.len();
        extensions.extend_from_slice(&[0x00, 0x00]); // Placeholder for total key_share length

        let secret = EphemeralSecret::random(&mut rng);
        let public_key = secret.public_key();
        let encoded = public_key.to_encoded_point(false);
        let public_bytes = encoded.as_bytes().to_vec();

        extensions.extend_from_slice(&[0x00, 0x17]); // Group = secp256r1
        extensions.extend_from_slice(&(public_bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&public_bytes);

        let key_share_len = (2 + 2 + public_bytes.len()) as u16;
        let total_key_share_len = key_share_len;
        extensions[key_share_data_start_idx..key_share_data_start_idx + 2]
            .copy_from_slice(&total_key_share_len.to_be_bytes());

        // signature_algorithms (let the server know what sigs we understand)
        extensions.extend_from_slice(&[0x00, 0x0D]);
        extensions.extend_from_slice(&[0x00, 0x0A]);
        extensions.extend_from_slice(&[0x00, 0x08]);
        extensions.extend_from_slice(&[0x08, 0x04]); // rsa_pss_rsae_sha256
        extensions.extend_from_slice(&[0x08, 0x05]); // rsa_pss_pss_sha256
        extensions.extend_from_slice(&[0x04, 0x03]); // ecdsa_secp256r1_sha256
        extensions.extend_from_slice(&[0x05, 0x03]); // ecdsa_secp384r1_sha384
    }

    // Add all extensions to the message
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    // Fill in the handshake length field
    let handshake_len = (hello.len() - handshake_start_idx - 4) as u32;
    hello[handshake_start_idx + 1..handshake_start_idx + 4]
        .copy_from_slice(&(handshake_len.to_be_bytes()[1..]));

    // Fill in the record layer length
    let record_len = (hello.len() - 5) as u16;
    hello[3..5].copy_from_slice(&record_len.to_be_bytes());

    Ok(hello)
}
