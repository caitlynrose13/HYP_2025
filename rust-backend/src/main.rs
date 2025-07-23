use axum::{Router, routing::post};
use rust_backend::handlers::assessment_handler::assess_domain;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

mod services;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Test TLS 1.3 handshake
    println!("--- TLS 1.3 ClientHello test to google.com ---");
    crate::services::tls_handshake::tls13::client::test_send_client_hello_to_google();
    println!("--- Done ---");

    // Test TLS 1.2 handshake
    println!("--- TLS 1.2 handshake test to google.com ---");
    crate::services::tls_handshake::client_handshake::test_tls12_handshake_to_google();
    println!("--- Done ---");

    // Set up CORS for local dev
    let cors = CorsLayer::new().allow_origin(Any);

    // Build the Axum app
    let app = Router::new()
        .route("/assess", post(assess_domain)) //when a post is made, assess_domain is called
        .layer(cors);

    // Start the server
    println!("Backend running on http://127.0.0.1:8080");
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
