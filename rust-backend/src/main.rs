use rust_backend::services::tls_handshake::client_handshake::perform_tls_handshake_full;
use rust_backend::services::tls_parser::TlsVersion;
use tracing::Level;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    println!("=== TLS Handshake Test ===");

    let domain = "tls-v1-2.badssl.com";
    let tls_version = TlsVersion::TLS1_2;

    println!(
        "Testing TLS handshake with {} using {:?}",
        domain, tls_version
    );

    match perform_tls_handshake_full(domain, tls_version) {
        Ok(connection_state) => {
            println!("TLS handshake completed successfully!");
            println!(
                "Negotiated cipher suite: {}",
                connection_state.negotiated_cipher_suite.name
            );
            println!(
                "Negotiated TLS version: {:?}",
                connection_state.negotiated_tls_version
            );
        }
        Err(e) => {
            eprintln!("TLS handshake failed: {:?}", e);
        }
    }
}
