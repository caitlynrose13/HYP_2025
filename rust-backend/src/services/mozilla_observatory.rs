use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Deserialize)]
pub struct ObservatoryResult {
    pub grade: Option<String>,
    pub scan_duration: Option<String>,
}

// Fetches results from the Mozilla Observatory API for a given domain
pub async fn fetch_observatory_results(domain: &str) -> Result<ObservatoryResult, String> {
    let start_time = std::time::Instant::now();

    let client = Client::builder()
        .timeout(Duration::from_secs(90))
        .build()
        .map_err(|e| format!("Client build error: {}", e))?;

    // Construct the URL for initiating a scan
    let scan_start_url = format!(
        "https://observatory-api.mdn.mozilla.net/api/v2/scan?host={}",
        domain
    );

    let post_resp = client
        .post(&scan_start_url)
        .header("Content-Length", "0")
        .body("")
        .send()
        .await
        .map_err(|e| format!("Scan initiation POST request error: {}", e))?;

    if !post_resp.status().is_success() {
        let status = post_resp.status();
        let error_body = post_resp
            .text()
            .await
            .unwrap_or_else(|_| "No response body".to_string());
        return Err(format!(
            "Observatory API POST failed with status: {}. Body: {}",
            status, error_body
        ));
    }

    let post_json: serde_json::Value = post_resp
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Failed to parse POST response JSON: {}", e))?;

    if let Some(error_obj) = post_json.get("error") {
        if !error_obj.is_null() {
            let error_message = error_obj
                .as_str()
                .unwrap_or("Unknown error in POST response")
                .to_string();
            let message_detail = post_json
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            let detail = if message_detail.is_empty() {
                "".to_string()
            } else {
                format!(" ({})", message_detail)
            };
            return Err(format!(
                "Observatory API POST response indicates an error for domain '{}': {}{}",
                domain, error_message, detail
            ));
        }
    }

    // After parsing post_json, check if scan is already complete
    if let Some(grade) = post_json.get("grade").and_then(|g| g.as_str()) {
        let duration = start_time.elapsed();
        // Scan is already complete, return immediately
        return Ok(ObservatoryResult {
            grade: Some(grade.to_string()),
            scan_duration: Some(format!("{:.2}s", duration.as_secs_f64())),
        });
    }

    // Only proceed with polling if scan is not already complete
    let scan_id = post_json
        .get("id")
        .and_then(|id| id.as_u64())
        .ok_or_else(|| {
            eprintln!(
                "Observatory API: POST response missing 'id' field. Full response: {:?}",
                post_json
            );
            "Failed to get scan_id from Observatory POST response (unexpected format)".to_string()
        })?
        .to_string();

    let expected_api_poll_url = format!(
        "https://observatory-api.mdn.mozilla.net/api/v2/scan/{}",
        scan_id
    );

    println!(
        "Observatory API: Scan initiated successfully, received ID: {}. Will poll: {}",
        scan_id, expected_api_poll_url
    );

    let max_retries = 15;
    let poll_interval_secs = 5;

    for i in 0..max_retries {
        sleep(Duration::from_secs(poll_interval_secs)).await;

        println!(
            "Observatory API: Polling scan status for ID {} (attempt {}/{}) from {}",
            scan_id,
            i + 1,
            max_retries,
            expected_api_poll_url
        );

        let resp = client
            .get(&expected_api_poll_url) // Use the constructed API polling URL
            .send()
            .await
            .map_err(|e| format!("Result fetch GET request error (poll {}): {}", i + 1, e))?;

        if !resp.status().is_success() {
            if resp.status().as_u16() == 502 {
                eprintln!(
                    "Received 502 Bad Gateway during poll {}. Retrying...",
                    i + 1
                );
                continue;
            }
            let status = resp.status();
            let error_body = resp
                .text()
                .await
                .unwrap_or_else(|_| "No response body".to_string());
            return Err(format!(
                "Observatory API GET failed with status: {}. Body: {}",
                status, error_body
            ));
        }

        let resp_text = resp
            .text()
            .await
            .map_err(|e| format!("Failed to get response text during poll: {}", e))?;

        // Try to parse the response as JSON
        let json: serde_json::Value = serde_json::from_str(&resp_text).map_err(|e| {
            format!(
                "Failed to parse JSON from poll response: {}. Raw response was: {}",
                e, resp_text
            )
        })?;

        let state = json
            .get("state")
            .and_then(|s| s.as_str())
            .unwrap_or("UNKNOWN");

        match state {
            "FINISHED" => {
                let duration = start_time.elapsed();
                let grade = json
                    .get("grade")
                    .and_then(|g| g.as_str())
                    .map(|s| s.to_string());
                return Ok(ObservatoryResult {
                    grade,
                    scan_duration: Some(format!("{:.2}s", duration.as_secs_f64())),
                });
            }
            "ERROR" => {
                let error_message = json
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Unknown scan error from Observatory API")
                    .to_string();
                return Err(format!("Observatory scan failed: {}", error_message));
            }
            _ => {
                println!(
                    "Scan for {} (ID {}) is still in state: {}. Waiting to poll again...",
                    domain, scan_id, state
                );
            }
        }
    }

    Err(
        "Observatory scan did not complete in a timely manner within the maximum retries."
            .to_string(),
    )
}
