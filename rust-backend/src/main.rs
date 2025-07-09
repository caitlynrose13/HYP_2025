use rust_backend::services::tls_handshake::client_handshake::{
    TlsSecurityLevel, probe_tls_security_level,
};
use tokio::net::TcpListener; //TCP listener
use tracing::{Level, info};

#[tokio::main] // the program entry point using the Tokio async runtime.
async fn main() {
    dotenvy::dotenv().ok(); //loads environment variables

    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    // Test TLS security level probing
    println!("=== TLS Security Level Assessment ===");
    let test_domain = "tls-v1-2.badssl.com"; // Changed for testing
    let security_level = probe_tls_security_level(test_domain);

    match security_level {
        TlsSecurityLevel::Modern => {
            println!("{} - MODERN TLS (1.2/1.3) - SECURE", test_domain);
        }
        TlsSecurityLevel::Deprecated => {
            println!("{} - DEPRECATED TLS (1.0/1.1) - INSECURE", test_domain);
        }
        TlsSecurityLevel::Unknown => {
            println!(" {} - UNKNOWN TLS SUPPORT - UNCERTAIN", test_domain);
        }
    }

    // allow all origins and headers for now - NEED TO CHANGE LATER

    // Build Axum app
    //let app = Router::new().nest("/", routes::assessment_routes::router());

    //tcp listener at port 8080
    let listener = TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("Failed to bind to port 8080");

    info!("Server listening on http://127.0.0.1:8080");

    //axum::serve(listener, app).await.expect("Server error");
}
