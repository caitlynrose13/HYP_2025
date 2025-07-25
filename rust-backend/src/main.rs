use axum::{
    Router,
    response::Json as AxumJson,
    routing::{get, post},
};
use rust_backend::handlers::assessment_handler::assess_domain;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

async fn health_check() -> AxumJson<serde_json::Value> {
    AxumJson(json!({
        "status": "healthy",
        "message": "TLS Assessment Backend is running"
    }))
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("TLS Assessment Backend Server");
    println!("Ready to assess domains via /assess endpoint");

    // Set up CORS for local dev
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build the Axum app
    let app = Router::new()
        .route("/assess", post(assess_domain)) //when a post is made, assess_domain is called
        .route("/health", get(health_check)) // health check endpoint
        .layer(cors);

    // Start the server
    println!("Backend running on http://127.0.0.1:8080");
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
