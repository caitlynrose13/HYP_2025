//! TLS Protocol Parser and Analysis Module
//!
//! This module provides comprehensive parsing capabilities for TLS 1.2 and TLS 1.3 protocols.
//! It handles TLS records, handshake messages, extensions, cipher suites, and alert messages.

use super::errors::TlsError;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};

// TLS Protocol Versions
pub const TLS_1_2_MAJOR: u8 = 0x03;
pub const TLS_1_2_MINOR: u8 = 0x03;

// TLS Alert Levels
pub const TLS_ALERT_LEVEL_WARNING: u8 = 0x01;
pub const TLS_ALERT_LEVEL_FATAL: u8 = 0x02;

// TLS Alert Descriptions
pub const TLS_ALERT_CLOSE_NOTIFY: u8 = 0x00;
pub const TLS_ALERT_HANDSHAKE_FAILURE: u8 = 0x28;
pub const TLS_ALERT_PROTOCOL_VERSION: u8 = 0x46;
pub const TLS_ALERT_INTERNAL_ERROR: u8 = 0x50;

// TLS Extension Types
pub const EXTENSION_TYPE_SERVER_NAME: u16 = 0x0000;
pub const EXTENSION_TYPE_SUPPORTED_GROUPS: u16 = 0x000A;
pub const EXTENSION_TYPE_SIGNATURE_ALGORITHMS: u16 = 0x000D;
pub const EXTENSION_TYPE_SUPPORTED_VERSIONS: u16 = 0x002B;
pub const EXTENSION_TYPE_KEY_SHARE: u16 = 0x0033;

// Server Name Indication (SNI)
pub const SNI_HOSTNAME_TYPE: u8 = 0x00;

// Signature Algorithms
pub const SIG_ALG_ECDSA_SECP256R1_SHA256: [u8; 2] = [0x04, 0x03];
pub const SIG_ALG_RSA_PSS_RSAE_SHA256: [u8; 2] = [0x08, 0x04];
pub const SIG_ALG_RSA_PKCS1_SHA256: [u8; 2] = [0x04, 0x01];

#[derive(Debug)]
pub enum TlsParserError {
    Incomplete { expected: usize, actual: usize },
    InvalidHandshakeType(u8),
    InvalidContentType(u8),
    InvalidLength,
    InvalidVersion(u8, u8),
    InvalidCipherSuite([u8; 2]),
    InvalidSignatureScheme(u16),
    InvalidNamedGroup(u16),
    MalformedClientHello,
    MalformedServerHello,
    MalformedCertificateList,
    MalformedServerKeyExchange,
    MalformedMessage(String),
    GenericError(String),
}

impl std::fmt::Display for TlsParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsParserError::Incomplete { expected, actual } => {
                write!(
                    f,
                    "Incomplete data: expected {} bytes, got {}",
                    expected, actual
                )
            }
            TlsParserError::InvalidHandshakeType(h_type) => {
                write!(f, "Invalid handshake type: 0x{:02X}", h_type)
            }
            TlsParserError::InvalidContentType(c_type) => {
                write!(f, "Invalid content type: 0x{:02X}", c_type)
            }
            TlsParserError::InvalidLength => write!(f, "Invalid length in record or message"),
            TlsParserError::InvalidVersion(maj, min) => {
                write!(f, "Invalid TLS version: 0x{:02X}{:02X}", maj, min)
            }
            TlsParserError::InvalidCipherSuite(cs) => {
                write!(f, "Invalid cipher suite: 0x{:02X}{:02X}", cs[0], cs[1])
            }
            TlsParserError::InvalidSignatureScheme(scheme) => {
                write!(f, "Invalid signature scheme: 0x{:04X}", scheme)
            }
            TlsParserError::InvalidNamedGroup(group) => {
                write!(f, "Invalid named group: 0x{:04X}", group)
            }
            TlsParserError::MalformedClientHello => write!(f, "Malformed ClientHello message"),
            TlsParserError::MalformedServerHello => write!(f, "Malformed ServerHello message"),
            TlsParserError::MalformedCertificateList => write!(f, "Malformed Certificate list"),
            TlsParserError::MalformedServerKeyExchange => {
                write!(f, "Malformed ServerKeyExchange message")
            }
            TlsParserError::MalformedMessage(msg) => write!(f, "Malformed message: {}", msg),
            TlsParserError::GenericError(s) => write!(f, "Parser error: {}", s),
        }
    }
}

impl std::error::Error for TlsParserError {}

// ==========
// CORE TLS ENUMS

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsContentType {
    ChangeCipherSpec = 0x14,
    Alert = 0x15,
    Handshake = 0x16,
    ApplicationData = 0x17,
}

impl TlsContentType {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0x14 => Some(TlsContentType::ChangeCipherSpec),
            0x15 => Some(TlsContentType::Alert),
            0x16 => Some(TlsContentType::Handshake),
            0x17 => Some(TlsContentType::ApplicationData),
            _ => None,
        }
    }
}

impl From<u8> for TlsContentType {
    fn from(value: u8) -> Self {
        TlsContentType::try_from_u8(value)
            .unwrap_or_else(|| panic!("Invalid TlsContentType value: 0x{:02X}", value))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum HandshakeMessageType {
    HelloRequest = 0x00,
    ClientHello = 0x01,
    ServerHello = 0x02,
    NewSessionTicket = 0x04,
    EndOfEarlyData = 0x05,
    EncryptedExtensions = 0x08,
    Certificate = 0x0B,
    ServerKeyExchange = 0x0C,
    CertificateRequest = 0x0D,
    ServerHelloDone = 0x0E,
    CertificateVerify = 0x0F,
    ClientKeyExchange = 0x10,
    Finished = 0x14,
    KeyUpdate = 0x18,
    MessageHash = 0xFE,
}

impl HandshakeMessageType {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(HandshakeMessageType::HelloRequest),
            0x01 => Some(HandshakeMessageType::ClientHello),
            0x02 => Some(HandshakeMessageType::ServerHello),
            0x04 => Some(HandshakeMessageType::NewSessionTicket),
            0x05 => Some(HandshakeMessageType::EndOfEarlyData),
            0x08 => Some(HandshakeMessageType::EncryptedExtensions),
            0x0B => Some(HandshakeMessageType::Certificate),
            0x0C => Some(HandshakeMessageType::ServerKeyExchange),
            0x0D => Some(HandshakeMessageType::CertificateRequest),
            0x0E => Some(HandshakeMessageType::ServerHelloDone),
            0x0F => Some(HandshakeMessageType::CertificateVerify),
            0x10 => Some(HandshakeMessageType::ClientKeyExchange),
            0x14 => Some(HandshakeMessageType::Finished),
            0x18 => Some(HandshakeMessageType::KeyUpdate),
            0xFE => Some(HandshakeMessageType::MessageHash),
            _ => None,
        }
    }
}

impl From<u8> for HandshakeMessageType {
    fn from(value: u8) -> Self {
        HandshakeMessageType::try_from_u8(value)
            .unwrap_or_else(|| panic!("Invalid HandshakeMessageType value: 0x{:02X}", value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    TLS1_0,
    TLS1_1,
    TLS1_2,
    TLS1_3,
    Unknown(u8, u8),
}

impl TlsVersion {
    pub fn from_u8_pair(major: u8, minor: u8) -> Self {
        match (major, minor) {
            (0x03, 0x01) => TlsVersion::TLS1_0,
            (0x03, 0x02) => TlsVersion::TLS1_1,
            (0x03, 0x03) => TlsVersion::TLS1_2,
            (0x03, 0x04) => TlsVersion::TLS1_3,
            _ => TlsVersion::Unknown(major, minor),
        }
    }

    pub fn to_u8_pair(&self) -> (u8, u8) {
        match self {
            TlsVersion::TLS1_0 => (0x03, 0x01),
            TlsVersion::TLS1_1 => (0x03, 0x02),
            TlsVersion::TLS1_2 => (0x03, 0x03),
            TlsVersion::TLS1_3 => (0x03, 0x04),
            TlsVersion::Unknown(maj, min) => (*maj, *min),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    P256,
    P384,
    X25519,
    Unknown(u16),
}

impl NamedGroup {
    pub fn as_bytes(&self) -> [u8; 2] {
        match self {
            NamedGroup::P256 => [0x00, 0x17],
            NamedGroup::P384 => [0x00, 0x18],
            NamedGroup::X25519 => [0x00, 0x1D],
            NamedGroup::Unknown(id) => id.to_be_bytes(),
        }
    }

    pub fn try_from_u16(value: u16) -> Option<Self> {
        match value {
            0x0017 => Some(NamedGroup::P256),
            0x0018 => Some(NamedGroup::P384),
            0x001D => Some(NamedGroup::X25519),
            _ => Some(NamedGroup::Unknown(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

// ==========================================
// TLS STRUCTURES

#[derive(Debug)]
pub struct TlsRecord {
    pub content_type: TlsContentType,
    pub version_major: u8,
    pub version_minor: u8,
    pub length: u16,
    pub payload: Vec<u8>,
}

impl TlsRecord {
    pub fn version_major_minor(&self) -> (u8, u8) {
        (self.version_major, self.version_minor)
    }
}

#[derive(Debug)]
pub struct TlsHandshakeMessage {
    pub msg_type: HandshakeMessageType,
    pub raw_bytes: Vec<u8>,
    pub length: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub extension_type: u16,
    pub payload: Vec<u8>,
}

impl Extension {
    pub fn new(extension_type: u16, payload: &[u8]) -> Self {
        Extension {
            extension_type,
            payload: payload.to_vec(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.extension_type.to_be_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct TlsAlert {
    pub level: u8,
    pub description: u8,
}

impl TlsAlert {
    pub fn new(level: u8, description: u8) -> Self {
        TlsAlert { level, description }
    }

    pub fn get_level_name(&self) -> &'static str {
        match self.level {
            TLS_ALERT_LEVEL_WARNING => "Warning",
            TLS_ALERT_LEVEL_FATAL => "Fatal",
            _ => "Unknown",
        }
    }

    pub fn get_description_name(&self) -> &'static str {
        match self.description {
            TLS_ALERT_CLOSE_NOTIFY => "Close Notify",
            TLS_ALERT_HANDSHAKE_FAILURE => "Handshake Failure",
            TLS_ALERT_PROTOCOL_VERSION => "Protocol Version",
            TLS_ALERT_INTERNAL_ERROR => "Internal Error",
            0x14 => "Bad Record MAC",
            _ => "Unknown Alert",
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "TLS Alert: {} (0x{:02X}) - {} (0x{:02X})",
            self.get_level_name(),
            self.level,
            self.get_description_name(),
            self.description
        )
    }
}

// =============================================
// PARSED MESSAGE STRUCTURES

#[derive(Debug, Clone)]
pub struct ServerHelloParsed {
    pub negotiated_tls_version: (u8, u8),
    pub server_random: [u8; 32],
    pub chosen_cipher_suite: [u8; 2],
    pub server_key_share_public: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct ServerHello13Parsed {
    pub legacy_version: (u8, u8),
    pub server_random: [u8; 32],
    pub session_id: Vec<u8>,
    pub chosen_cipher_suite: [u8; 2],
    pub legacy_compression_method: u8,
    pub extensions: Vec<Extension>,
    pub negotiated_tls_version: Option<TlsVersion>,
    pub server_key_share_public: Option<Vec<u8>>,
    pub selected_named_group: Option<NamedGroup>,
}

#[derive(Debug, Clone)]
pub struct ServerKeyExchangeParsed {
    pub curve_type: u8,
    pub named_curve: u16,
    pub public_key: Vec<u8>,
    pub signature_algorithm: [u8; 2],
    pub signature: Vec<u8>,
    pub params_raw: Vec<u8>,
}

// =============================================
// CIPHER SUITE DEFINITIONS

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuite {
    pub id: [u8; 2],
    pub name: &'static str,
    pub key_length: u8,
    pub fixed_iv_length: u8,
    pub mac_key_length: u8,
    pub hash_algorithm: HashAlgorithm,
}

impl CipherSuite {
    pub const fn new(id0: u8, id1: u8) -> Self {
        let id = [id0, id1];
        match id {
            // TLS 1.3 Cipher Suites
            [0x13, 0x01] => CipherSuite {
                id,
                name: "TLS_AES_128_GCM_SHA256",
                key_length: 16,
                fixed_iv_length: 12,
                mac_key_length: 0,
                hash_algorithm: HashAlgorithm::Sha256,
            },
            [0x13, 0x02] => CipherSuite {
                id,
                name: "TLS_AES_256_GCM_SHA384",
                key_length: 32,
                fixed_iv_length: 12,
                mac_key_length: 0,
                hash_algorithm: HashAlgorithm::Sha384,
            },
            [0x13, 0x03] => CipherSuite {
                id,
                name: "TLS_CHACHA20_POLY1305_SHA256",
                key_length: 32,
                fixed_iv_length: 12,
                mac_key_length: 0,
                hash_algorithm: HashAlgorithm::Sha256,
            },
            // TLS 1.2 ECDHE RSA Cipher Suites
            [0xc0, 0x2f] => CipherSuite {
                id,
                name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                key_length: 16,
                fixed_iv_length: 4,
                mac_key_length: 0,
                hash_algorithm: HashAlgorithm::Sha256,
            },
            [0xc0, 0x30] => CipherSuite {
                id,
                name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                key_length: 32,
                fixed_iv_length: 4,
                mac_key_length: 0,
                hash_algorithm: HashAlgorithm::Sha384,
            },
            // TLS 1.2 ECDHE ECDSA Cipher Suites (ADD THESE!)
            [0xc0, 0x2b] => CipherSuite {
                id,
                name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                key_length: 16,
                fixed_iv_length: 4,
                mac_key_length: 0,
                hash_algorithm: HashAlgorithm::Sha256,
            },
            [0xc0, 0x2c] => CipherSuite {
                id,
                name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                key_length: 32,
                fixed_iv_length: 4,
                mac_key_length: 0,
                hash_algorithm: HashAlgorithm::Sha384,
            },
            // CHACHA20 Cipher Suites (ADD THESE!)
            [0xcc, 0xa8] => CipherSuite {
                id,
                name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                key_length: 32,
                fixed_iv_length: 4,
                mac_key_length: 0,
                hash_algorithm: HashAlgorithm::Sha256,
            },
            [0xcc, 0xa9] => CipherSuite {
                id,
                name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                key_length: 32,
                fixed_iv_length: 4,
                mac_key_length: 0,
                hash_algorithm: HashAlgorithm::Sha256,
            },
            // Default for unknown cipher suites
            _ => CipherSuite {
                id: [0x00, 0x00],
                name: "UNKNOWN",
                key_length: 0,
                fixed_iv_length: 0,
                mac_key_length: 0,
                hash_algorithm: HashAlgorithm::Sha256,
            },
        }
    }
}

// Predefined Cipher Suite Constants
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite::new(0xc0, 0x2f);
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite::new(0xc0, 0x30);
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
    id: [0xCC, 0xA8],
    name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    key_length: 32,
    fixed_iv_length: 4,
    mac_key_length: 0,
    hash_algorithm: HashAlgorithm::Sha256,
};
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
    id: [0xCC, 0xA9],
    name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    key_length: 32,
    fixed_iv_length: 4,
    mac_key_length: 0,
    hash_algorithm: HashAlgorithm::Sha256,
};

// =============================================================================
// CIPHER SUITE UTILITY FUNCTIONS
// =============================================================================

pub fn get_cipher_suite_name(suite: &[u8; 2]) -> String {
    match suite {
        // TLS 1.3 cipher suites
        [0x13, 0x01] => "TLS_AES_128_GCM_SHA256".to_string(),
        [0x13, 0x02] => "TLS_AES_256_GCM_SHA384".to_string(),
        [0x13, 0x03] => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        [0x13, 0x04] => "TLS_AES_128_CCM_SHA256".to_string(),
        [0x13, 0x05] => "TLS_AES_128_CCM_8_SHA256".to_string(),

        // TLS 1.2 ECDHE GCM cipher suites
        [0xc0, 0x2f] => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        [0xc0, 0x30] => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        [0xc0, 0x2b] => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
        [0xc0, 0x2c] => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
        [0xcc, 0xa8] => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
        [0xcc, 0xa9] => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),

        // TLS 1.2 ECDHE CBC cipher suites
        [0xc0, 0x27] => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256".to_string(),
        [0xc0, 0x28] => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384".to_string(),
        [0xc0, 0x23] => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256".to_string(),
        [0xc0, 0x24] => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384".to_string(),
        [0xc0, 0x13] => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".to_string(),
        [0xc0, 0x14] => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".to_string(),
        [0xc0, 0x09] => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".to_string(),
        [0xc0, 0x0a] => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA".to_string(),

        // DHE cipher suites
        [0x00, 0x9e] => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        [0x00, 0x9f] => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        [0x00, 0x67] => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256".to_string(),
        [0x00, 0x6b] => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256".to_string(),
        [0x00, 0x33] => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA".to_string(),
        [0x00, 0x39] => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA".to_string(),

        // RSA cipher suites
        [0x00, 0x9c] => "TLS_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        [0x00, 0x9d] => "TLS_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        [0x00, 0x3c] => "TLS_RSA_WITH_AES_128_CBC_SHA256".to_string(),
        [0x00, 0x3d] => "TLS_RSA_WITH_AES_256_CBC_SHA256".to_string(),
        [0x00, 0x2f] => "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
        [0x00, 0x35] => "TLS_RSA_WITH_AES_256_CBC_SHA".to_string(),

        // Unknown cipher suites
        _ => format!("Unknown ({:02x}{:02x})", suite[0], suite[1]),
    }
}

pub fn get_cipher_suite_by_id(id: &[u8; 2]) -> Option<CipherSuite> {
    match *id {
        // TLS 1.3 cipher suites
        [0x13, 0x01] | [0x13, 0x02] | [0x13, 0x03] => Some(CipherSuite::new(id[0], id[1])),
        // TLS 1.2 ECDHE cipher suites
        [0xc0, 0x2f] | [0xc0, 0x30] | [0xc0, 0x2b] | [0xc0, 0x2c] => {
            Some(CipherSuite::new(id[0], id[1]))
        }
        [0xcc, 0xa8] => Some(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
        [0xcc, 0xa9] => Some(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
        _ => None,
    }
}

// ============================================
// SIGNATURE ALGORITHM FUNCTIONS

pub fn parse_signature_algorithm(sig_alg: &[u8; 2]) -> Result<String, TlsError> {
    match sig_alg {
        [0x08, 0x04] => Ok("rsa_pss_rsae_sha256".to_string()),
        [0x08, 0x05] => Ok("rsa_pss_rsae_sha384".to_string()),
        [0x08, 0x06] => Ok("rsa_pss_rsae_sha512".to_string()),
        [0x08, 0x09] => Ok("rsa_pss_pss_sha256".to_string()),
        [0x08, 0x0a] => Ok("rsa_pss_pss_sha384".to_string()),
        [0x08, 0x0b] => Ok("rsa_pss_pss_sha512".to_string()),
        [0x04, 0x03] => Ok("ecdsa_secp256r1_sha256".to_string()),
        [0x04, 0x01] => Ok("rsa_pkcs1_sha256".to_string()),
        [0x05, 0x01] => Ok("rsa_pkcs1_sha384".to_string()),
        [0x06, 0x01] => Ok("rsa_pkcs1_sha512".to_string()),
        _ => Err(TlsError::HandshakeFailed(format!(
            "Unsupported signature algorithm: 0x{:02x}{:02x}",
            sig_alg[0], sig_alg[1]
        ))),
    }
}

// ========================
// PARSING FUNCTIONS

/// Parse a TLS record from the given reader
pub fn parse_tls_record(reader: &mut Cursor<&[u8]>) -> Result<Option<TlsRecord>, TlsError> {
    let current_pos = reader.position() as usize;
    let remaining_len = reader.get_ref().len() - current_pos;

    // Check if we have enough bytes for the TLS record header
    if remaining_len < 5 {
        return Ok(None);
    }

    let content_type_byte = reader.read_u8()?;
    let version_major = reader.read_u8()?;
    let version_minor = reader.read_u8()?;
    let length = reader.read_u16::<BigEndian>()?;

    // Check if we have enough bytes for the complete record
    if remaining_len < 5 + length as usize {
        reader.set_position(current_pos as u64);
        return Ok(None);
    }

    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload)?;

    Ok(Some(TlsRecord {
        content_type: TlsContentType::try_from_u8(content_type_byte).ok_or(
            TlsError::ParserError(TlsParserError::InvalidContentType(content_type_byte)),
        )?,
        version_major,
        version_minor,
        length,
        payload,
    }))
}

/// Parse handshake messages from the given data
pub fn parse_handshake_messages(data: &[u8]) -> Result<Vec<TlsHandshakeMessage>, TlsError> {
    let mut cursor = Cursor::new(data);
    let mut messages = Vec::new();

    while (cursor.position() as usize) < data.len() {
        let start_pos = cursor.position() as usize;

        // Check for minimum handshake message header size
        if data.len() - start_pos < 4 {
            return Err(TlsError::ParserError(TlsParserError::Incomplete {
                expected: 4,
                actual: data.len() - start_pos,
            }));
        }

        let msg_type_byte = cursor.read_u8()?;

        // Handle TLS 1.3 encrypted handshake messages
        if msg_type_byte > 0x18 || msg_type_byte == 0x07 || msg_type_byte == 0x70 {
            println!(
                "[DEBUG] Encountered encrypted handshake data (type: 0x{:02X}), stopping parsing",
                msg_type_byte
            );
            break;
        }

        let msg_type = HandshakeMessageType::try_from_u8(msg_type_byte).ok_or(
            TlsError::ParserError(TlsParserError::InvalidHandshakeType(msg_type_byte)),
        )?;

        let length = ReadBytesExt::read_u24::<BigEndian>(&mut cursor)?;

        // Sanity check for unreasonably large lengths
        if length > 65536 {
            println!(
                "[DEBUG] Unreasonably large handshake message length: {}, likely encrypted data",
                length
            );
            break;
        }

        // Check if we have enough data for the complete message
        if (cursor.position() as usize) + length as usize > data.len() {
            return Err(TlsError::ParserError(TlsParserError::Incomplete {
                expected: length as usize,
                actual: data.len() - (cursor.position() as usize),
            }));
        }

        let mut payload = vec![0; length as usize];
        cursor.read_exact(&mut payload)?;

        let end_pos = cursor.position() as usize;
        let raw_bytes = data[start_pos..end_pos].to_vec();

        messages.push(TlsHandshakeMessage {
            msg_type,
            length,
            payload,
            raw_bytes,
        });
    }

    Ok(messages)
}

/// Parse a TLS extension from the given cursor
pub fn parse_tls_extension(cursor: &mut Cursor<&[u8]>) -> Result<Extension, TlsParserError> {
    let initial_pos = cursor.position() as usize;
    let remaining_bytes = cursor.get_ref().len() - initial_pos;

    if remaining_bytes < 4 {
        return Err(TlsParserError::Incomplete {
            expected: 4,
            actual: remaining_bytes,
        });
    }

    let ext_type = cursor.read_u16::<BigEndian>()?;
    let ext_len = cursor.read_u16::<BigEndian>()? as usize;

    if remaining_bytes < 4 + ext_len {
        return Err(TlsParserError::Incomplete {
            expected: 4 + ext_len,
            actual: remaining_bytes,
        });
    }

    let mut payload = vec![0u8; ext_len];
    cursor.read_exact(&mut payload)?;

    Ok(Extension {
        extension_type: ext_type,
        payload,
    })
}

/// Parse ServerHello message content
pub fn parse_server_hello_content(payload: &[u8]) -> Result<ServerHelloParsed, TlsParserError> {
    let mut cursor = Cursor::new(payload);

    // Parse version (2 bytes)
    if payload.len() < 2 {
        return Err(TlsParserError::MalformedServerHello);
    }
    let negotiated_tls_version = (cursor.read_u8()?, cursor.read_u8()?);

    // Parse server random (32 bytes)
    if payload.len() < 34 {
        return Err(TlsParserError::MalformedServerHello);
    }
    let mut server_random = [0u8; 32];
    cursor.read_exact(&mut server_random)?;

    // Parse session ID
    let session_id_len = cursor.read_u8()? as usize;
    cursor.set_position(cursor.position() + session_id_len as u64);

    // Parse cipher suite (2 bytes)
    let mut chosen_cipher_suite = [0u8; 2];
    cursor.read_exact(&mut chosen_cipher_suite)?;

    // Skip compression method (1 byte)
    cursor.read_u8()?;

    // Parse extensions (optional)
    let mut server_key_share_public = None;
    if cursor.position() as usize + 2 <= payload.len() {
        let extensions_len = cursor.read_u16::<BigEndian>()? as usize;

        if cursor.position() as usize + extensions_len <= payload.len() {
            let extensions_start = cursor.position() as usize;
            let extensions_data = &payload[extensions_start..extensions_start + extensions_len];
            let mut ext_cursor = Cursor::new(extensions_data);

            while ext_cursor.position() as usize + 4 <= extensions_len {
                let ext_type = ext_cursor.read_u16::<BigEndian>()?;
                let ext_len = ext_cursor.read_u16::<BigEndian>()? as usize;

                if ext_cursor.position() as usize + ext_len > extensions_len {
                    break;
                }

                let mut ext_data = vec![0u8; ext_len];
                ext_cursor.read_exact(&mut ext_data)?;

                // Parse Key Share extension (0x0033)
                if ext_type == EXTENSION_TYPE_KEY_SHARE && ext_len >= 4 {
                    let key_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                    if ext_len >= 4 + key_len {
                        server_key_share_public = Some(ext_data[4..4 + key_len].to_vec());
                    }
                }
            }
        }
    }

    Ok(ServerHelloParsed {
        negotiated_tls_version,
        server_random,
        chosen_cipher_suite,
        server_key_share_public,
    })
}

/// Parse TLS 1.3 ServerHello payload
pub fn parse_tls13_server_hello_payload(
    payload: &[u8],
) -> Result<ServerHello13Parsed, TlsParserError> {
    let mut cursor = Cursor::new(payload);
    let mut parsed_sh = ServerHello13Parsed::default();

    // Parse legacy version (2 bytes)
    parsed_sh.legacy_version = (cursor.read_u8()?, cursor.read_u8()?);

    // Parse server random (32 bytes)
    cursor.read_exact(&mut parsed_sh.server_random)?;

    // Parse session ID
    let session_id_len = cursor.read_u8()? as usize;
    parsed_sh.session_id.resize(session_id_len, 0);
    cursor.read_exact(&mut parsed_sh.session_id)?;

    // Parse chosen cipher suite (2 bytes)
    cursor.read_exact(&mut parsed_sh.chosen_cipher_suite)?;

    // Parse legacy compression method (1 byte)
    parsed_sh.legacy_compression_method = cursor.read_u8()?;

    // Parse extensions (optional)
    if cursor.position() as usize + 2 <= payload.len() {
        let extensions_len = cursor.read_u16::<BigEndian>()? as usize;

        if cursor.position() as usize + extensions_len > payload.len() {
            return Err(TlsParserError::MalformedServerHello);
        }

        let extensions_start = cursor.position() as usize;
        let extensions_end = extensions_start + extensions_len;
        let extensions_slice = &payload[extensions_start..extensions_end];
        let mut ext_cursor = Cursor::new(extensions_slice);

        while (ext_cursor.position() as usize) < extensions_len {
            let extension = parse_tls_extension(&mut ext_cursor)?;
            parsed_sh.extensions.push(extension);
        }

        cursor.set_position(extensions_end as u64);
    }

    // Process parsed extensions
    for ext in &parsed_sh.extensions {
        match ext.extension_type {
            EXTENSION_TYPE_SUPPORTED_VERSIONS => {
                if ext.payload.len() == 2 {
                    parsed_sh.negotiated_tls_version =
                        Some(TlsVersion::from_u8_pair(ext.payload[0], ext.payload[1]));
                }
            }
            EXTENSION_TYPE_KEY_SHARE => {
                if ext.payload.len() >= 4 {
                    let mut key_cursor = Cursor::new(&ext.payload);
                    let named_group_id = key_cursor.read_u16::<BigEndian>()?;
                    parsed_sh.selected_named_group = NamedGroup::try_from_u16(named_group_id);

                    let key_len = key_cursor.read_u16::<BigEndian>()? as usize;
                    if ext.payload.len() >= 4 + key_len {
                        let mut public_key = vec![0u8; key_len];
                        key_cursor.read_exact(&mut public_key)?;
                        parsed_sh.server_key_share_public = Some(public_key);
                    }
                }
            }
            _ => {} // Ignore other extensions
        }
    }

    Ok(parsed_sh)
}

/// Parse certificate list from Certificate handshake message
pub fn parse_certificate_list(payload: &[u8]) -> Result<Vec<Vec<u8>>, TlsParserError> {
    let mut cursor = Cursor::new(payload);

    if payload.len() < 3 {
        return Err(TlsParserError::MalformedCertificateList);
    }

    let total_certs_len = ReadBytesExt::read_u24::<BigEndian>(&mut cursor)? as usize;

    if total_certs_len != payload.len() - 3 {
        return Err(TlsParserError::MalformedMessage(format!(
            "Certificate list length mismatch: expected {}, got {}",
            total_certs_len,
            payload.len() - 3
        )));
    }

    let mut certificates = Vec::new();
    while (cursor.position() as usize) < payload.len() {
        if cursor.position() as usize + 3 > payload.len() {
            return Err(TlsParserError::MalformedCertificateList);
        }

        let cert_len = ReadBytesExt::read_u24::<BigEndian>(&mut cursor)? as usize;

        if cursor.position() as usize + cert_len > payload.len() {
            return Err(TlsParserError::MalformedMessage(format!(
                "Certificate length exceeds bounds: {} > {}",
                cert_len,
                payload.len() - cursor.position() as usize
            )));
        }

        let mut cert_bytes = vec![0; cert_len];
        cursor.read_exact(&mut cert_bytes)?;
        certificates.push(cert_bytes);
    }

    Ok(certificates)
}

/// Parse ServerKeyExchange message content
pub fn parse_server_key_exchange_content(
    payload: &[u8],
) -> Result<ServerKeyExchangeParsed, TlsParserError> {
    let mut cursor = Cursor::new(payload);
    let start_params = 0;

    // Parse curve type (must be 0x03 for named curve)
    let curve_type = cursor.read_u8()?;
    if curve_type != 0x03 {
        return Err(TlsParserError::InvalidNamedGroup(curve_type as u16));
    }

    // Parse named curve
    let named_curve = cursor.read_u16::<BigEndian>()?;
    if NamedGroup::try_from_u16(named_curve).is_none() {
        return Err(TlsParserError::InvalidNamedGroup(named_curve));
    }

    // Parse public key
    let public_key_len = cursor.read_u8()? as usize;
    let mut public_key = vec![0; public_key_len];
    cursor.read_exact(&mut public_key)?;

    let end_params = cursor.position() as usize;
    let params_raw = payload[start_params..end_params].to_vec();

    // Parse signature algorithm
    let mut signature_algorithm = [0; 2];
    cursor.read_exact(&mut signature_algorithm)?;

    // Parse signature
    let signature_len = cursor.read_u16::<BigEndian>()? as usize;
    let mut signature = vec![0; signature_len];
    cursor.read_exact(&mut signature)?;

    if cursor.position() as usize != payload.len() {
        return Err(TlsParserError::MalformedMessage(
            "ServerKeyExchange has trailing data".to_string(),
        ));
    }

    Ok(ServerKeyExchangeParsed {
        curve_type,
        named_curve,
        public_key,
        signature_algorithm,
        signature,
        params_raw,
    })
}

/// Parse TLS alert message
pub fn parse_tls_alert(payload: &[u8]) -> Result<TlsAlert, TlsParserError> {
    if payload.len() < 2 {
        return Err(TlsParserError::MalformedMessage(
            "Alert payload too short".to_string(),
        ));
    }

    Ok(TlsAlert::new(payload[0], payload[1]))
}
