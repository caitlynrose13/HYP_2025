// src/services/errors.rs
use crate::services::tls_parser::TlsParserError;
use std::fmt;
use std::io;
use std::time::SystemTimeError;
use webpki;

#[derive(Debug)]
pub enum TlsError {
    HandshakeError(String),
    IoError(io::Error),
    ConnectionFailed(String),
    InvalidAddress(String),
    HandshakeFailed(String),
    ParserError(TlsParserError),
    CertificateError(String),
    KeyExchangeError(String),       // Added for key exchange errors
    KeyDerivationError(String),     // Added for key derivation errors
    EncryptionError(String),        // Added for encryption errors
    DecryptionError(String),        // Added for decryption errors
    UnsupportedCipherSuite(String), // Added for unsupported cipher suite errors
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
            TlsError::KeyExchangeError(msg) => write!(f, "Key Exchange Error: {}", msg),
            TlsError::KeyDerivationError(msg) => write!(f, "Key Derivation Error: {}", msg),
            TlsError::EncryptionError(msg) => write!(f, "Encryption Error: {}", msg),
            TlsError::DecryptionError(msg) => write!(f, "Decryption Error: {}", msg),
            TlsError::UnsupportedCipherSuite(msg) => write!(f, "Unsupported Cipher Suite: {}", msg),
            TlsError::HandshakeError(msg) => write!(f, "Handshake Error: {}", msg),
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

impl From<webpki::Error> for TlsError {
    fn from(err: webpki::Error) -> Self {
        TlsError::CertificateError(format!("Webpki certificate error: {:?}", err))
    }
}

impl From<SystemTimeError> for TlsError {
    fn from(err: SystemTimeError) -> Self {
        TlsError::IoError(io::Error::new(
            io::ErrorKind::Other,
            format!("System time error: {}", err),
        ))
    }
}
