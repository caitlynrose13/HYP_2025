// src/services/errors.rs

use crate::services::tls_parser::TlsParserError;
use std::fmt;
use std::io; // Already present
use std::time::SystemTimeError; // Already present
use webpki; // <-- NEW: Added this import for webpki::Error conversion
// Removed: use webpki::TlsServerTrustAnchors; // This import is not needed in errors.rs

#[derive(Debug)]
pub enum TlsError {
    IoError(io::Error), // Correct based on your existing definition
    ConnectionFailed(String),
    InvalidAddress(String),
    HandshakeFailed(String),
    ParserError(TlsParserError),
    CertificateError(String), // Correct based on your existing definition
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::IoError(e) => write!(f, "IO Error: {}", e),
            TlsError::ConnectionFailed(msg) => write!(f, "Connection Failed: {}", msg),
            TlsError::InvalidAddress(msg) => write!(f, "Invalid Address: {}", msg),
            TlsError::HandshakeFailed(msg) => write!(f, "TLS Handshake Failed: {}", msg),
            TlsError::ParserError(e) => write!(f, "Parsing Error: {}", e),
            TlsError::CertificateError(msg) => write!(f, "Certificate Error: {}", msg),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::IoError(e) => Some(e),
            TlsError::ParserError(e) => Some(e),
            _ => None,
        }
    }
}

// Existing From implementations
impl From<io::Error> for TlsError {
    fn from(err: io::Error) -> Self {
        TlsError::IoError(err)
    }
}

impl From<TlsParserError> for TlsError {
    fn from(err: TlsParserError) -> Self {
        TlsError::ParserError(err)
    }
}

// Existing From for TlsParserError (this is fine as is)
impl From<std::io::Error> for TlsParserError {
    fn from(e: std::io::Error) -> Self {
        TlsParserError::GenericError(e.to_string())
    }
}

// **NEW FROM IMPLEMENTATIONS FOR TlsError**

// This is required for `webpki::Error` to convert to `TlsError`
// (used by the '?' operator in `certificate_validator.rs`).
impl From<webpki::Error> for TlsError {
    fn from(err: webpki::Error) -> Self {
        // webpki::Error doesn't directly convert to std::io::Error.
        // We'll map it to TlsError::CertificateError, which takes a String.
        TlsError::CertificateError(format!("Webpki certificate error: {:?}", err))
    }
}

// This is required for `SystemTimeError` to convert to `TlsError`
// (used by the '?' operator in `certificate_validator.rs`).
impl From<SystemTimeError> for TlsError {
    fn from(err: SystemTimeError) -> Self {
        // SystemTimeError does not directly convert to std::io::Error.
        // We create a new std::io::Error with a generic kind and the error message.
        TlsError::IoError(io::Error::new(
            io::ErrorKind::Other,
            format!("System time error: {}", err),
        ))
    }
}
