use serde::Deserialize;

#[derive(Deserialize)]
pub struct AssessmentRequest {
    pub domain: String,
}
