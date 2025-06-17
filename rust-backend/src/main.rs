use axum::{Json, Router, routing::post}; // web framework for routoing and request handling
use serde::{Deserialize, Serialize}; // for serializing and deserializing JSON
use tokio::net::TcpListener; //TCP listener
use tower_http::cors::{Any, CorsLayer}; //configure CORS policies
use tracing::{Level, info};
use tracing_subscriber;

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
    let app = Router::new()
        .route("/assess", post(assess_handler))
        .layer(cors); //attatch the CORS to the router

    //tcp listener at port 8080
    let listener = TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("Failed to bind to port 8080");

    info!("Server listening on http://127.0.0.1:8080");

    axum::serve(listener, app).await.expect("Server error");
}

#[derive(Deserialize)]
struct AssessRequest {
    domain: String,
}
//expected input for request

#[derive(Serialize)]
struct AssessResponse {
    status: String,
    domain: String,
    message: String,
}
//Defines the JSON response structure

//The actual handler function - should move it to its own class/file?
async fn assess_handler(Json(payload): Json<AssessRequest>) -> Json<AssessResponse> {
    info!("Received domain: {}", payload.domain); //console message confirming domain received

    //JSON to respond with
    Json(AssessResponse {
        status: "ok".to_string(),
        domain: payload.domain,
        message: "TLS logic coming soon".to_string(), //send to frontend
    })
}
