use crate::models::scan_request::AssessmentRequest;
use crate::models::scan_result::ScanResult;
use crate::services::scanner;
use axum::Json;

#[axum::debug_handler]
pub async fn assess_handler(Json(payload): Json<AssessmentRequest>) -> Json<ScanResult> {
    tracing::info!("🔍 Received assessment for domain: {}", payload.domain);

    match scanner::scan_domain(&payload.domain) {
        Ok(result) => Json(result),
        Err(e) => {
            tracing::error!("Scan error: {:?}", e);
            Json(ScanResult {
                domain: payload.domain,
                version: "error".to_string(),
                cert_info: None,
            })
        }
    }
}
