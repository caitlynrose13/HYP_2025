// src/services/errors.rs

use crate::services::tls_parser::TlsParserError;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum TlsError {
    IoError(io::Error),
    ConnectionFailed(String),
    InvalidAddress(String),
    HandshakeFailed(String),
    ParserError(TlsParserError),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::IoError(e) => write!(f, "IO Error: {}", e),
            TlsError::ConnectionFailed(msg) => write!(f, "Connection Failed: {}", msg),
            TlsError::InvalidAddress(msg) => write!(f, "Invalid Address: {}", msg),
            TlsError::HandshakeFailed(msg) => write!(f, "TLS Handshake Failed: {}", msg),
            TlsError::ParserError(e) => write!(f, "Parsing Error: {}", e),
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

impl From<std::io::Error> for TlsParserError {
    fn from(e: std::io::Error) -> Self {
        TlsParserError::GenericError(e.to_string())
    }
}
