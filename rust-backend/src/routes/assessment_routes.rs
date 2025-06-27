use crate::handlers::assessment_handler::assess_handler;
use axum::{Router, routing::post};

pub fn router() -> Router {
    Router::new()
        .route("/assess", post(assess_handler))
        .with_state(())
}
