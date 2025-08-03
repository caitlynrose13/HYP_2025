use axum::{
    Router,
    routing::{get, post},
};
use rust_backend::AppState;
use rust_backend::handlers::assessment_handler::assess_domain;
use rust_backend::handlers::external_scan_handler::external_scan;
use sqlx::SqlitePool;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

pub mod db;

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
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

    // Clean up old scans immediately on startup
    db::cleanup_old_scans(&pool).await?;

    let app_state = AppState { pool: pool.clone() }; // Initialize AppState

    // Build the Axum app
    let app = Router::new()
        .route("/assess", post(assess_domain)) //when a post is made, assess_domain is called
        .route("/api/observatory", get(external_scan)) // when a get is made, external_scan is called
        .layer(cors)
        .with_state(app_state);

    // Start the axum server
    println!("Backend running on http://127.0.0.1:8080");
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
    Ok(())
}
