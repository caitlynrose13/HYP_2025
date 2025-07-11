// src/services/tls_parser.rs

use super::errors::TlsError; // Make sure TlsError is imported correctly
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};

// --- Public Constants for TLS Protocol Values (moved from messages.rs) ---
// TLS Versions
pub const TLS_1_2_MAJOR: u8 = 0x03;
pub const TLS_1_2_MINOR: u8 = 0x03;

// ClientHello specific
pub const SESSION_ID_LEN_EMPTY: u8 = 0x00;
pub const COMPRESSION_METHOD_NULL: u8 = 0x00;
pub const COMPRESSION_METHODS_LEN: u8 = 0x01; // Length of the list of compression methods

// Extension Types (2 bytes)
pub const EXTENSION_TYPE_SERVER_NAME: u16 = 0x0000;
pub const EXTENSION_TYPE_SUPPORTED_GROUPS: u16 = 0x000A;
pub const EXTENSION_TYPE_KEY_SHARE: u16 = 0x0033;
pub const EXTENSION_TYPE_SUPPORTED_VERSIONS: u16 = 0x002B;
pub const EXTENSION_TYPE_SIGNATURE_ALGORITHMS: u16 = 0x000D;

// Server Name Indication (SNI)
pub const SNI_HOSTNAME_TYPE: u8 = 0x00;

// Signature Algorithms (2 bytes each)
pub const SIG_ALG_ECDSA_SECP256R1_SHA256: [u8; 2] = [0x04, 0x03];
pub const SIG_ALG_RSA_PSS_RSAE_SHA256: [u8; 2] = [0x08, 0x04];
pub const SIG_ALG_RSA_PSS_RSAE_SHA512: [u8; 2] = [0x08, 0x05];
pub const SIG_ALG_RSA_PKCS1_SHA256: [u8; 2] = [0x04, 0x01];

#[derive(Debug)]
pub enum TlsParserError {
    Incomplete { expected: usize, actual: usize },
    InvalidHandshakeType(u8),
    InvalidContentType(u8),
    InvalidLength,
    InvalidVersion(u8, u8),
    InvalidCipherSuite([u8; 2]),
    MalformedClientHello,
    MalformedServerHello,
    MalformedCertificateList,
    MalformedMessage(String),
    MalformedServerKeyExchange,
    InvalidSignatureScheme(u16),
    InvalidNamedGroup(u16),
    GenericError(String),
}

impl std::fmt::Display for TlsParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsParserError::Incomplete { expected, actual } => write!(
                f,
                "Incomplete data: expected {} bytes, got {}",
                expected, actual
            ),
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
            TlsParserError::MalformedClientHello => write!(f, "Malformed ClientHello message"),
            TlsParserError::MalformedServerHello => write!(f, "Malformed ServerHello message"),
            TlsParserError::MalformedCertificateList => write!(f, "Malformed Certificate list"),
            TlsParserError::MalformedServerKeyExchange => {
                write!(f, "Malformed ServerKeyExchange message")
            }
            TlsParserError::InvalidSignatureScheme(scheme) => {
                write!(f, "Invalid signature scheme: 0x{:04X}", scheme)
            }
            TlsParserError::InvalidNamedGroup(group) => {
                write!(f, "Invalid named group: 0x{:04X}", group)
            }
            TlsParserError::GenericError(s) => write!(f, "Parser error: {}", s),
            TlsParserError::MalformedMessage(msg) => write!(f, "Malformed message: {}", msg),
        }
    }
}

impl std::error::Error for TlsParserError {}

// *** REMOVED: impl From<std::io::Error> for TlsParserError block from here ***

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)] // Ensures the enum variants correspond directly to their u8 values
pub enum TlsContentType {
    ChangeCipherSpec = 0x14,
    Alert = 0x15,
    Handshake = 0x16,
    ApplicationData = 0x17,
    // Heartbeat = 0x18, // If you need TLS 1.2 Heartbeat, uncomment this
}

impl TlsContentType {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    // A more robust conversion from u8 that returns Option or Result
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0x14 => Some(TlsContentType::ChangeCipherSpec),
            0x15 => Some(TlsContentType::Alert),
            0x16 => Some(TlsContentType::Handshake),
            0x17 => Some(TlsContentType::ApplicationData),
            // 0x18 => Some(TlsContentType::Heartbeat), // Uncomment if Heartbeat is added
            _ => None, // Return None for unknown values
        }
    }
}

// The From<u8> for TlsContentType should now use try_from_u8 and handle the None case
impl From<u8> for TlsContentType {
    fn from(value: u8) -> Self {
        TlsContentType::try_from_u8(value).unwrap_or_else(|| {
            // If try_from_u8 returns None, we map to a GenericError
            // This approach ensures that we don't have an "Unknown" variant for construction,
            // only for parsing if you truly need to represent an unknown type.
            // For a strict client, mapping to an error is often better.
            panic!("Invalid TlsContentType value: 0x{:02X}", value); // Or a specific error handling
        })
    }
}

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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum HandshakeMessageType {
    HelloRequest = 0x00,
    ClientHello = 0x01,
    ServerHello = 0x02,
    NewSessionTicket = 0x04,    // TLS 1.2/1.3
    EndOfEarlyData = 0x05,      // TLS 1.3
    EncryptedExtensions = 0x08, // TLS 1.3
    Certificate = 0x0B,
    ServerKeyExchange = 0x0C, // TLS 1.2
    CertificateRequest = 0x0D,
    ServerHelloDone = 0x0E, // TLS 1.2
    CertificateVerify = 0x0F,
    ClientKeyExchange = 0x10, // TLS 1.2
    Finished = 0x14,
    KeyUpdate = 0x18,   // TLS 1.3
    MessageHash = 0xFE, // TLS 1.3
}

impl HandshakeMessageType {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    // A more robust conversion from u8 that returns Option or Result
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

// Adjusted From<u8> for HandshakeMessageType to use try_from_u8
impl From<u8> for HandshakeMessageType {
    fn from(value: u8) -> Self {
        HandshakeMessageType::try_from_u8(value).unwrap_or_else(|| {
            panic!("Invalid HandshakeMessageType value: 0x{:02X}", value);
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    TLS1_0, // 0x0301
    TLS1_1, // 0x0302
    TLS1_2, // 0x0303
    TLS1_3, // 0x0304
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

// --- New: NamedGroup Enum ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NamedGroup {
    P256 = 0x0017,
    P384 = 0x0018,
    Unknown(u16),
}

impl NamedGroup {
    pub fn as_bytes(&self) -> [u8; 2] {
        match self {
            NamedGroup::P256 => [0x00, 0x17],
            NamedGroup::P384 => [0x00, 0x18],
            NamedGroup::Unknown(id) => id.to_be_bytes(),
        }
    }

    pub fn try_from_u16(value: u16) -> Option<Self> {
        match value {
            0x0017 => Some(NamedGroup::P256),
            0x0018 => Some(NamedGroup::P384),
            _ => None,
        }
    }
}

// --- New: Extension Struct ---
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
        bytes.extend_from_slice(&self.extension_type.to_be_bytes()); // 2 bytes for type
        bytes.extend_from_slice(&(self.payload.len() as u16).to_be_bytes()); // 2 bytes for length
        bytes.extend_from_slice(&self.payload); // Payload
        bytes
    }
}

#[derive(Debug)]
pub struct TlsHandshakeMessage {
    pub msg_type: HandshakeMessageType,
    pub raw_bytes: Vec<u8>, // Raw bytes of the handshake message (type + length + payload)
    pub length: u32,        // Length of the message payload
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ServerHelloParsed {
    pub negotiated_tls_version: (u8, u8),
    pub server_random: [u8; 32],
    pub chosen_cipher_suite: [u8; 2],
    pub server_key_share_public: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ServerKeyExchangeParsed {
    pub curve_type: u8,
    pub named_curve: u16,
    pub public_key: Vec<u8>,
    pub signature_algorithm: [u8; 2],
    pub signature: Vec<u8>,
    pub params_raw: Vec<u8>, // NEW: raw bytes from curve_type through public_key
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuite {
    pub id: [u8; 2],
    pub name: &'static str,
    pub key_length: u8,
    pub fixed_iv_length: u8,
    pub mac_key_length: u8,
    pub hash_algorithm: HashAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    // Add other hash algorithms as needed
}

// cipher suite
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
    id: [0xC0, 0x2F],
    name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    key_length: 16,     // AES-128 uses 16-byte key
    fixed_iv_length: 4, // GCM uses a 4-byte fixed_iv for TLS 1.2
    mac_key_length: 0,  // GCM is an AEAD cipher, MAC is integrated, so 0 separate MAC key
    hash_algorithm: HashAlgorithm::Sha256,
};

// Add AES-256-GCM suite
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
    id: [0xC0, 0x30],
    name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    key_length: 32,                        // AES-256 uses 32-byte key
    fixed_iv_length: 4,                    // GCM uses a 4-byte fixed_iv for TLS 1.2
    mac_key_length: 0, // GCM is an AEAD cipher, MAC is integrated, so 0 separate MAC key
    hash_algorithm: HashAlgorithm::Sha256, // Should be Sha384 for full correctness, but keep as Sha256 if only Sha256 is implemented
};

pub fn get_cipher_suite_by_id(id: &[u8; 2]) -> Option<&'static CipherSuite> {
    if id == &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.id {
        Some(&TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    } else if id == &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.id {
        Some(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
    } else {
        None
    }
}

// -- functions --
pub fn parse_tls_record(reader: &mut Cursor<&[u8]>) -> Result<Option<TlsRecord>, TlsError> {
    let current_pos = reader.position() as usize;
    let remaining_len = reader.get_ref().len() - current_pos;

    if remaining_len < 5 {
        // 1 byte type + 2 bytes version + 2 bytes length
        return Ok(None);
    }

    let content_type_byte = reader.read_u8()?;
    let version_major = reader.read_u8()?;
    let version_minor = reader.read_u8()?;
    let length = reader.read_u16::<BigEndian>()?;

    if remaining_len < 5 + length as usize {
        reader.set_position(current_pos as u64); // Rewind cursor
        return Ok(None); // Return Ok(None) to indicate more data is needed
    }

    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload)?;

    Ok(Some(TlsRecord {
        content_type: TlsContentType::try_from_u8(content_type_byte).ok_or(
            TlsError::ParserError(TlsParserError::InvalidContentType(content_type_byte)),
        )?, // Map to TlsError here
        version_major,
        version_minor,
        length,
        payload,
    }))
}

pub fn parse_handshake_messages(data: &[u8]) -> Result<Vec<TlsHandshakeMessage>, TlsError> {
    let mut cursor = Cursor::new(data);
    let mut messages = Vec::new();

    while (cursor.position() as usize) < data.len() {
        let start_pos = cursor.position() as usize;

        // Ensure there are enough bytes for handshake header (1 type + 3 length)
        if data.len() - start_pos < 4 {
            return Err(TlsError::ParserError(TlsParserError::Incomplete {
                expected: 4,
                actual: data.len() - start_pos,
            }));
        }

        let msg_type_byte = cursor.read_u8()?;
        let msg_type = HandshakeMessageType::try_from_u8(msg_type_byte).ok_or(
            TlsError::ParserError(TlsParserError::InvalidHandshakeType(msg_type_byte)),
        )?;

        let length = cursor.read_u24::<BigEndian>()?; // Changed to read_u24 for 3-byte length

        if (cursor.position() as usize) + length as usize > data.len() {
            return Err(TlsError::ParserError(TlsParserError::Incomplete {
                expected: length as usize,
                actual: data.len() - (cursor.position() as usize),
            }));
        }

        let mut payload = vec![0; length as usize];
        cursor.read_exact(&mut payload)?;

        let end_pos = cursor.position() as usize;
        let raw_bytes_for_this_message = data[start_pos..end_pos].to_vec();

        // --- DEBUG OUTPUT ---
        println!(
            "[parse_handshake_messages] Parsed handshake message: type={:?} (0x{:02X}), len={}, raw={}",
            msg_type,
            msg_type.as_u8(),
            length,
            hex::encode(&raw_bytes_for_this_message)
        );
        // --- END DEBUG OUTPUT ---

        messages.push(TlsHandshakeMessage {
            msg_type,
            length,
            payload,
            raw_bytes: raw_bytes_for_this_message,
        });
    }
    Ok(messages)
}

pub fn parse_server_hello_content(payload: &[u8]) -> Result<ServerHelloParsed, TlsParserError> {
    let mut cursor = Cursor::new(payload);

    if payload.len() < 38 {
        return Err(TlsParserError::MalformedServerHello);
    }

    let negotiated_tls_version = (cursor.read_u8()?, cursor.read_u8()?);
    let mut server_random_bytes = [0u8; 32];
    cursor.read_exact(&mut server_random_bytes)?;

    let session_id_len = cursor.read_u8()? as usize;

    if cursor.position() as usize + session_id_len + 3 > payload.len() {
        return Err(TlsParserError::MalformedServerHello);
    }
    cursor.set_position(cursor.position() + session_id_len as u64); // Move cursor past session ID

    let chosen_cipher_suite = [cursor.read_u8()?, cursor.read_u8()?];
    let _chosen_compression_method = cursor.read_u8()?;

    let mut server_key_share_public: Option<Vec<u8>> = None;

    // Check if there are extensions
    if (cursor.position() as usize) < payload.len() {
        let extensions_len = cursor.read_u16::<BigEndian>()? as usize;
        let extensions_start_pos = cursor.position() as usize;

        if extensions_start_pos + extensions_len > payload.len() {
            return Err(TlsParserError::MalformedMessage(
                "ServerHello extensions length mismatch.".to_string(),
            ));
        }

        let extensions_data_end = extensions_start_pos + extensions_len;
        let mut ext_cursor = Cursor::new(&payload[extensions_start_pos..extensions_data_end]);

        while (ext_cursor.position() as usize) + 4 <= ext_cursor.get_ref().len() {
            let ext_type = ext_cursor.read_u16::<BigEndian>()?;
            let ext_len = ext_cursor.read_u16::<BigEndian>()? as usize;

            if (ext_cursor.position() as usize) + ext_len > ext_cursor.get_ref().len() {
                return Err(TlsParserError::MalformedMessage(
                    "ServerHello extension data length mismatch.".to_string(),
                ));
            }

            let ext_content_start = ext_cursor.position() as usize;
            let ext_content_end = ext_content_start + ext_len;
            let ext_content = &ext_cursor.get_ref()[ext_content_start..ext_content_end];

            if negotiated_tls_version.0 == 0x03 && negotiated_tls_version.1 == 0x04 {
                if ext_type == EXTENSION_TYPE_KEY_SHARE {
                    // Using the new constant
                    if ext_content.len() < 4 {
                        // Group (2 bytes) + Key Exchange Length (2 bytes)
                        return Err(TlsParserError::MalformedMessage(
                            "Malformed key_share extension".to_string(),
                        ));
                    }
                    let group_id = u16::from_be_bytes([ext_content[0], ext_content[1]]);
                    let key_exchange_len =
                        u16::from_be_bytes([ext_content[2], ext_content[3]]) as usize;

                    if 4 + key_exchange_len > ext_content.len() {
                        return Err(TlsParserError::MalformedMessage(
                            "Key exchange data length mismatch in key_share".to_string(),
                        ));
                    }

                    if NamedGroup::try_from_u16(group_id).is_some() {
                        server_key_share_public =
                            Some(ext_content[4..4 + key_exchange_len].to_vec());
                    } else {
                        println!(
                            "Warning: Server offered unsupported key_share group: 0x{:04X}",
                            group_id
                        );
                    }
                }
            }

            ext_cursor.set_position(ext_content_end as u64); // Move cursor past this extension's content
        }
        cursor.set_position(extensions_data_end as u64); // Move main cursor past all extensions
    }

    Ok(ServerHelloParsed {
        negotiated_tls_version,
        server_random: server_random_bytes,
        chosen_cipher_suite,
        server_key_share_public,
    })
}

pub fn parse_certificate_list(payload: &[u8]) -> Result<Vec<Vec<u8>>, TlsParserError> {
    let mut cursor = Cursor::new(payload);

    if payload.len() < 3 {
        return Err(TlsParserError::MalformedCertificateList);
    }

    let total_certs_len = cursor.read_u24::<BigEndian>()? as usize;

    if total_certs_len != payload.len() - (cursor.position() as usize) {
        return Err(TlsParserError::MalformedMessage(format!(
            "Certificate list declared length ({}) does not match actual remaining payload ({}).",
            total_certs_len,
            payload.len() - (cursor.position() as usize)
        )));
    }

    let mut certificates = Vec::new();
    while (cursor.position() as usize) < payload.len() {
        if (cursor.position() as usize) + 3 > payload.len() {
            return Err(TlsParserError::MalformedCertificateList);
        }
        let cert_len = cursor.read_u24::<BigEndian>()? as usize;

        if (cursor.position() as usize) + cert_len > payload.len() {
            return Err(TlsParserError::MalformedMessage(format!(
                "Individual certificate length ({}) exceeds list bounds. Remaining payload: {}",
                cert_len,
                payload.len() - (cursor.position() as usize)
            )));
        }

        let mut cert_bytes = vec![0; cert_len];
        cursor.read_exact(&mut cert_bytes)?;
        certificates.push(cert_bytes);
    }

    if (cursor.position() as usize) != payload.len() {
        return Err(TlsParserError::MalformedMessage(
            "Trailing data found after certificate list parsing.".to_string(),
        ));
    }

    Ok(certificates)
}

pub fn parse_server_key_exchange_content(
    payload: &[u8],
) -> Result<ServerKeyExchangeParsed, TlsParserError> {
    // Log the complete raw ServerKeyExchange message
    println!(
        "    Complete raw ServerKeyExchange message (hex): {}",
        hex::encode(payload)
    );
    println!(
        "    ServerKeyExchange message length: {} bytes",
        payload.len()
    );

    let mut cursor = Cursor::new(payload);
    let start_params = 0;
    let curve_type = cursor.read_u8()?;
    if curve_type != 0x03 {
        return Err(TlsParserError::InvalidNamedGroup(curve_type as u16));
    }
    let named_curve = cursor.read_u16::<BigEndian>()?;
    if NamedGroup::try_from_u16(named_curve).is_none() {
        return Err(TlsParserError::InvalidNamedGroup(named_curve));
    }
    let public_key_len = cursor.read_u8()? as usize;
    let mut public_key_bytes = vec![0; public_key_len];
    cursor.read_exact(&mut public_key_bytes)?;
    let end_params = cursor.position() as usize;
    let params_raw = payload[start_params..end_params].to_vec();
    let mut signature_algorithm = [0; 2];
    cursor.read_exact(&mut signature_algorithm)?;
    let signature_len = cursor.read_u16::<BigEndian>()? as usize;
    let mut signature_bytes = vec![0; signature_len];
    cursor.read_exact(&mut signature_bytes)?;
    if cursor.position() as usize != payload.len() {
        return Err(TlsParserError::MalformedMessage(
            "ServerKeyExchange payload has unread trailing data".to_string(),
        ));
    }

    // Log signature algorithm
    println!(
        "    Signature algorithm: 0x{:02X}{:02X}",
        signature_algorithm[0], signature_algorithm[1]
    );
    println!("    Signature length: {} bytes", signature_bytes.len());

    Ok(ServerKeyExchangeParsed {
        curve_type,
        named_curve,
        public_key: public_key_bytes,
        signature_algorithm,
        signature: signature_bytes,
        params_raw, // NEW
    })
}
