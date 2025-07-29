use reqwest::Client;
use serde::Deserialize;
use std::time::Instant;

#[derive(Debug, Deserialize)]
pub struct SsllabsResult {
    pub grade: String,
    pub scan_duration: u64, // milliseconds
}

#[derive(Debug, Deserialize)]
struct SsllabsApiResponse {
    endpoints: Vec<SsllabsEndpoint>,
}

#[derive(Debug, Deserialize)]
struct SsllabsEndpoint {
    grade: Option<String>,
}

pub async fn fetch_ssllabs_results(domain: &str) -> Result<SsllabsResult, String> {
    let client = Client::new();
    let api_url = format!(
        "https://api.ssllabs.com/api/v3/analyze?host={}&publish=off&all=done",
        domain
    );
    let start = Instant::now();

    let resp = client
        .get(&api_url)
        .send()
        .await
        .map_err(|e| format!("Request error: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("SSL Labs API returned status: {}", resp.status()));
    }

    let api_response: SsllabsApiResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    let grade = api_response
        .endpoints
        .get(0)
        .and_then(|ep| ep.grade.clone())
        .unwrap_or_else(|| "Unknown".to_string());

    let scan_duration = start.elapsed().as_millis() as u64;

    Ok(SsllabsResult {
        grade,
        scan_duration,
    })
}
