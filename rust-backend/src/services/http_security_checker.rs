use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpSecurityResults {
    pub https_redirect: bool,
    pub csp_header: bool,
    pub x_frame_options: bool,
    pub x_content_type_options: bool,
    pub expect_ct: bool,
}

pub async fn check_http_security(
    domain: &str,
) -> Result<HttpSecurityResults, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;

    let https_redirect = check_https_redirect(&client, domain).await.unwrap_or(false);

    let https_url = format!("https://{}", domain);
    let headers = match client.get(&https_url).send().await {
        Ok(response) => extract_headers(response.headers()),
        Err(_) => HashMap::new(),
    };

    Ok(HttpSecurityResults {
        https_redirect,
        csp_header: has_header(&headers, "content-security-policy"),
        x_frame_options: has_header(&headers, "x-frame-options"),
        x_content_type_options: has_header(&headers, "x-content-type-options"),
        expect_ct: has_header(&headers, "expect-ct"),
    })
}

async fn check_https_redirect(
    client: &reqwest::Client,
    domain: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let http_url = format!("http://{}", domain);

    match client.get(&http_url).send().await {
        Ok(response) => {
            if response.status().is_redirection() {
                if let Some(location) = response.headers().get("location") {
                    if let Ok(location_str) = location.to_str() {
                        return Ok(location_str.starts_with("https://"));
                    }
                }
            }
            Ok(false)
        }
        Err(_) => Ok(true), // If HTTP fails, assume HTTPS-only
    }
}

fn extract_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str() {
            result.insert(name.as_str().to_lowercase(), value_str.to_string());
        }
    }
    result
}

fn has_header(headers: &HashMap<String, String>, header_name: &str) -> bool {
    headers.contains_key(&header_name.to_lowercase())
}
