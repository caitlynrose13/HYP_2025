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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TLS Assessment Backend Server");
    println!("Ready to assess domains via /assess endpoint");

    // Create database file if it doesn't exist
    let db_path = "scans.db";
    if !std::path::Path::new(db_path).exists() {
        std::fs::File::create(db_path)?;
        println!("Created new database file: {}", db_path);
    }

    // Set up CORS for local dev
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Connect to SQLite database
    let pool = SqlitePool::connect(&format!("sqlite:{}", db_path)).await?;
    println!("Connected to database successfully");

    // Initialize database
    rust_backend::db::init_db(&pool).await?;
    println!("Database initialized successfully");

    // Clean up old scans immediately on startup
    rust_backend::db::cleanup_old_scans(&pool).await?;

    let app_state = AppState { pool: pool.clone() };

    // Build the Axum app
    let app = Router::new()
        .route("/assess", post(assess_domain))
        .route("/api/observatory", get(external_scan))
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
