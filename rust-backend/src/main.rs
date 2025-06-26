use axum::Router; // web framework for routoing and request handling
use tokio::net::TcpListener; //TCP listener
use tower_http::cors::{Any, CorsLayer}; //configure CORS policies
use tracing::{Level, info};

use rust_backend::routes;

#[tokio::main] // the program entry point using the Tokio async runtime.
async fn main() {
    dotenvy::dotenv().ok(); //loads environment variables

    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    // allow all origins and headers for now - NEED TO CHANGE LATER
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);

    // Build Axum app
    let app = Router::new().nest("/", routes::assessment_routes::router());

    //tcp listener at port 8080
    let listener = TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("Failed to bind to port 8080");

    info!("Server listening on http://127.0.0.1:8080");

    axum::serve(listener, app).await.expect("Server error");
}
