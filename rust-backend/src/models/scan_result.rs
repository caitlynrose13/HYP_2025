use crate::services::certificate_parser::ParsedCertificate;
use serde::Serialize;

#[derive(Serialize)]
pub struct ScanResult {
    pub domain: String,
    pub version: String,
    pub cert_info: Option<ParsedCertificate>,
}
