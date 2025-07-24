use axum::{Router, routing::post};
use rust_backend::handlers::assessment_handler::assess_domain;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

mod services;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Focus on the core TLS 1.3 decryption issue with one domain
    println!("--- TLS 1.3 modular client test ---");
    if let Err(e) = crate::services::tls_handshake::tls13::client::test_tls13_client() {
        println!("TLS 1.3 client test failed: {}", e);
    }
    println!("--- Done ---");

    // The issue is domain-agnostic, so we don't need to test multiple domains
    // The issue is also not related to rustls comparison since rustls works fine
    // Focus only on our TLS 1.3 record decryption logic

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
