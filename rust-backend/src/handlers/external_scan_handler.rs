use crate::services::mozilla_observatory::fetch_observatory_results;
use crate::services::ssllabs::fetch_ssllabs_results; // Add this import
use axum::{Json, extract::Query};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct ExternalScanQuery {
    pub domain: String,
    pub scan_type: String, // "observatory" or "ssllabs"
}

pub async fn external_scan(Query(params): Query<ExternalScanQuery>) -> Json<serde_json::Value> {
    let domain_to_scan = match Url::parse(&params.domain) {
        Ok(url) => url.host_str().unwrap_or(&params.domain).to_string(),
        Err(_) => params.domain.clone(),
    };

    if domain_to_scan.contains('/') || domain_to_scan.contains('\\') || domain_to_scan.is_empty() {
        return Json(
            serde_json::json!({ "error": "Invalid domain format provided. Please provide a simple domain name (e.g., example.com)." }),
        );
    }

    match params.scan_type.as_str() {
        "observatory" => match fetch_observatory_results(&domain_to_scan).await {
            Ok(result) => Json(serde_json::json!({
                "grade": result.grade,
                "scan_duration": result.scan_duration,
            })),
            Err(e) => {
                println!("Observatory error: {}", e);
                Json(serde_json::json!({ "error": e }))
            }
        },
        "ssllabs" => match fetch_ssllabs_results(&domain_to_scan).await {
            Ok(result) => Json(serde_json::json!({
                "grade": result.grade,
                "scan_duration": result.scan_duration,
            })),
            Err(e) => {
                println!("SSL Labs error: {}", e);
                Json(serde_json::json!({ "error": e }))
            }
        },
        _ => {
            println!("Unknown scan type: {}", params.scan_type);
            Json(serde_json::json!({ "error": "Unknown scan type" }))
        }
    }
}
