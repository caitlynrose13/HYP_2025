use axum::{Router, routing::post};
use rust_backend::handlers::assessment_handler::assess_domain;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() {
    // Set up CORS for local dev
    let cors = CorsLayer::new().allow_origin(Any);

    // Build the Axum app
    let app = Router::new()
        .route("/assess", post(assess_domain))
        .layer(cors);

    // Start the server
    println!("Backend running on http://127.0.0.1:8080");
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
