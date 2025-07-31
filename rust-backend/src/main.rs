use axum::extract::State;
use axum::{
    Router,
    response::Json as AxumJson,
    routing::{get, post},
};
use rust_backend::AppState; // Add this import at the top
use rust_backend::handlers::assessment_handler::assess_domain;
use rust_backend::handlers::external_scan_handler::external_scan;
use serde_json::json;
use sqlx::SqlitePool;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

pub mod db;

async fn health_check() -> AxumJson<serde_json::Value> {
    AxumJson(json!({
        "status": "healthy",
        "message": "TLS Assessment Backend is running"
    }))
}

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("TLS Assessment Backend Server");
    println!("Ready to assess domains via /assess endpoint");

    // Set up CORS for local dev
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Initialize the database
    let pool = SqlitePool::connect("sqlite://f:/HYP_2025/rust-backend/scans.db").await?;
    db::init_db(&pool).await?;

    // Spawn a background cleanup task
    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60)); // every 24 hours
        loop {
            interval.tick().await;
            if let Err(e) = db::cleanup_old_scans(&cleanup_pool).await {
                eprintln!("Cleanup error: {:?}", e);
            }
        }
    });

    let app_state = AppState { pool: pool.clone() }; // Initialize AppState

    // Build the Axum app
    let app = Router::new()
        .route("/assess", post(assess_domain)) //when a post is made, assess_domain is called
        .route("/health", get(health_check)) // health check endpoint
        .route("/api/observatory", get(external_scan)) //
        .layer(cors)
        .with_state(app_state);

    // Start the server
    println!("Backend running on http://127.0.0.1:8080");
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
    Ok(())
}
