// src/services/tls_parser.rs

// Corrected imports for byteorder traits and types
use byteorder::{BigEndian, ReadBytesExt}; // ReadBytesExt for read_u8, read_u16, read_u24
use std::io::{Cursor, Read}; // Read trait for read_exact

// contants for TLS record types
pub const TLS_HANDSHAKE: u8 = 0x16;
pub const TLS_ALERT: u8 = 0x15;
pub const TLS_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const TLS_APPLICATION_DATA: u8 = 0x17;

//constants for TLS handshake message types
pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
pub const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
pub const HANDSHAKE_CERTIFICATE: u8 = 0x0B;
pub const HANDSHAKE_SERVER_KEY_EXCHANGE: u8 = 0x0C;
pub const HANDSHAKE_SERVER_HELLO_DONE: u8 = 0x0E;
pub const HANDSHAKE_FINISHED: u8 = 0x14;

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

#[derive(Debug, Clone)]
pub enum TlsContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Unknown(u8),
}

impl From<u8> for TlsContentType {
    fn from(value: u8) -> Self {
        match value {
            TLS_CHANGE_CIPHER_SPEC => TlsContentType::ChangeCipherSpec,
            TLS_ALERT => TlsContentType::Alert,
            TLS_HANDSHAKE => TlsContentType::Handshake,
            TLS_APPLICATION_DATA => TlsContentType::ApplicationData,
            _ => TlsContentType::Unknown(value),
        }
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

#[derive(Debug)]
pub enum HandshakeMessageType {
    ClientHello,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    ServerHelloDone,
    Finished,
    Unknown(u8),
}

impl From<u8> for HandshakeMessageType {
    fn from(value: u8) -> Self {
        match value {
            HANDSHAKE_CLIENT_HELLO => HandshakeMessageType::ClientHello,
            HANDSHAKE_SERVER_HELLO => HandshakeMessageType::ServerHello,
            HANDSHAKE_CERTIFICATE => HandshakeMessageType::Certificate,
            HANDSHAKE_SERVER_KEY_EXCHANGE => HandshakeMessageType::ServerKeyExchange,
            HANDSHAKE_SERVER_HELLO_DONE => HandshakeMessageType::ServerHelloDone,
            HANDSHAKE_FINISHED => HandshakeMessageType::Finished,
            _ => HandshakeMessageType::Unknown(value),
        }
    }
}

#[derive(Debug)]
pub struct TlsHandshakeMessage {
    pub msg_type: HandshakeMessageType,
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
}

// -- functions --
pub fn parse_tls_record(reader: &mut Cursor<&[u8]>) -> Result<Option<TlsRecord>, TlsParserError> {
    let current_pos = reader.position() as usize;
    let remaining_len = reader.get_ref().len() - current_pos;

    if remaining_len < 5 {
        return Ok(None);
    }

    // Using ReadBytesExt methods
    let content_type_byte = reader
        .read_u8()
        .map_err(|e| TlsParserError::GenericError(format!("Failed to read content type: {}", e)))?;
    let version_major = reader.read_u8().map_err(|e| {
        TlsParserError::GenericError(format!("Failed to read version major: {}", e))
    })?;
    let version_minor = reader.read_u8().map_err(|e| {
        TlsParserError::GenericError(format!("Failed to read version minor: {}", e))
    })?;
    let length = reader
        .read_u16::<BigEndian>()
        .map_err(|e| TlsParserError::GenericError(format!("Failed to read length: {}", e)))?;

    if remaining_len < 5 + length as usize {
        reader.set_position(current_pos as u64);
        return Ok(None); // Return Ok(None) to indicate more data is needed, not an error
    }

    let mut payload = vec![0u8; length as usize];
    reader
        .read_exact(&mut payload)
        .map_err(|e| TlsParserError::GenericError(format!("Failed to read payload: {}", e)))?;

    Ok(Some(TlsRecord {
        content_type: content_type_byte.into(),
        version_major,
        version_minor,
        length,
        payload,
    }))
}

pub fn parse_handshake_messages(
    payload: &[u8],
) -> Result<Vec<TlsHandshakeMessage>, TlsParserError> {
    let mut cursor = Cursor::new(payload);
    let mut messages = Vec::new();

    while (cursor.position() as usize) < payload.len() {
        let msg_type_byte = cursor.read_u8().map_err(|e| {
            TlsParserError::MalformedMessage(format!(
                "Failed to read handshake message type: {}",
                e
            ))
        })?;
        // Use read_u24 from byteorder
        let msg_len = cursor.read_u24::<BigEndian>().map_err(|e| {
            TlsParserError::MalformedMessage(format!(
                "Failed to read handshake message length: {}",
                e
            ))
        })?;

        let body_start = cursor.position() as usize; // Current position after reading header
        let body_end = body_start + msg_len as usize;

        if body_end > payload.len() {
            return Err(TlsParserError::MalformedMessage(format!(
                "Handshake message length ({}) exceeds record payload size ({}). Offset: {}",
                msg_len,
                payload.len(),
                body_start
            )));
        }

        let mut msg_payload = vec![0; msg_len as usize];
        cursor.read_exact(&mut msg_payload).map_err(|e| {
            TlsParserError::MalformedMessage(format!(
                "Failed to read handshake message payload: {}",
                e
            ))
        })?;

        messages.push(TlsHandshakeMessage {
            msg_type: msg_type_byte.into(),
            payload: msg_payload,
        });
    }
    Ok(messages)
}

pub fn parse_server_hello_content(payload: &[u8]) -> Result<ServerHelloParsed, TlsParserError> {
    let mut cursor = Cursor::new(payload);

    if payload.len() < 38 {
        // Minimum length for version, random, session ID length (0), cipher suite, compression
        return Err(TlsParserError::MalformedServerHello);
    }

    let negotiated_tls_version = (
        cursor
            .read_u8()
            .map_err(|e| TlsParserError::MalformedServerHello.into_generic(e))?,
        cursor
            .read_u8()
            .map_err(|e| TlsParserError::MalformedServerHello.into_generic(e))?,
    );
    let mut server_random_bytes = [0u8; 32];
    cursor
        .read_exact(&mut server_random_bytes)
        .map_err(|e| TlsParserError::MalformedServerHello.into_generic(e))?;

    let session_id_len = cursor
        .read_u8()
        .map_err(|e| TlsParserError::MalformedServerHello.into_generic(e))?
        as usize;
    // Skip session ID bytes if present
    cursor.set_position(cursor.position() + session_id_len as u64); // Move cursor past session ID

    if cursor.position() as usize + 3 > payload.len() {
        // 2 bytes for cipher suite, 1 for compression
        return Err(TlsParserError::MalformedServerHello);
    }
    let chosen_cipher_suite = [
        cursor
            .read_u8()
            .map_err(|e| TlsParserError::MalformedServerHello.into_generic(e))?,
        cursor
            .read_u8()
            .map_err(|e| TlsParserError::MalformedServerHello.into_generic(e))?,
    ];
    let _chosen_compression_method = cursor
        .read_u8()
        .map_err(|e| TlsParserError::MalformedServerHello.into_generic(e))?;

    let mut server_key_share_public: Option<Vec<u8>> = None;

    // Check if there are extensions
    if (cursor.position() as usize) < payload.len() {
        let extensions_len = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| TlsParserError::MalformedServerHello.into_generic(e))?
            as usize;
        let extensions_start_pos = cursor.position() as usize;

        if extensions_start_pos + extensions_len > payload.len() {
            return Err(TlsParserError::MalformedMessage(
                "ServerHello extensions length mismatch.".to_string(),
            ));
        }

        let extensions_data_end = extensions_start_pos + extensions_len;
        let mut ext_cursor = Cursor::new(&payload[extensions_start_pos..extensions_data_end]);

        while (ext_cursor.position() as usize) + 4 <= ext_cursor.get_ref().len() {
            let ext_type = ext_cursor
                .read_u16::<BigEndian>()
                .map_err(|e| TlsParserError::MalformedServerHello.into_generic(e))?;
            let ext_len = ext_cursor
                .read_u16::<BigEndian>()
                .map_err(|e| TlsParserError::MalformedServerHello.into_generic(e))?
                as usize;

            if (ext_cursor.position() as usize) + ext_len > ext_cursor.get_ref().len() {
                return Err(TlsParserError::MalformedMessage(
                    "ServerHello extension data length mismatch.".to_string(),
                ));
            }

            let ext_content_start = ext_cursor.position() as usize;
            let ext_content_end = ext_content_start + ext_len;
            let ext_content = &ext_cursor.get_ref()[ext_content_start..ext_content_end];

            // Handle key_share extension for TLS 1.3
            // Note: This is specifically for TLS 1.3's key_share.
            // TLS 1.2 would use ServerKeyExchange message for ephemeral keys.
            if negotiated_tls_version.0 == 0x03 && negotiated_tls_version.1 == 0x04 {
                if ext_type == 0x0033 {
                    // key_share extension
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

                    if group_id == 0x0017 || group_id == 0x001D {
                        // secp256r1 or x25519
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

// --- Helper function for certificate list parsing (for Certificate message payload) ---
pub fn parse_certificate_list(payload: &[u8]) -> Result<Vec<Vec<u8>>, TlsParserError> {
    let mut cursor = Cursor::new(payload);

    if payload.len() < 3 {
        return Err(TlsParserError::MalformedCertificateList);
    }

    // Read total length of certificate list (3 bytes)
    let total_certs_len = cursor.read_u24::<BigEndian>().map_err(|e| {
        TlsParserError::MalformedMessage(format!("Failed to read certificate list length: {}", e))
    })? as usize;

    // The total_certs_len should match the remaining payload length
    // after reading the 3-byte length field.
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
            return Err(TlsParserError::MalformedCertificateList); // Not enough bytes for next cert length
        }
        // Read individual certificate length (3 bytes)
        let cert_len = cursor.read_u24::<BigEndian>().map_err(|e| {
            TlsParserError::MalformedMessage(format!("Failed to read certificate length: {}", e))
        })? as usize;

        if (cursor.position() as usize) + cert_len > payload.len() {
            return Err(TlsParserError::MalformedMessage(format!(
                "Individual certificate length ({}) exceeds list bounds. Remaining payload: {}",
                cert_len,
                payload.len() - (cursor.position() as usize)
            )));
        }

        let mut cert_bytes = vec![0; cert_len];
        cursor.read_exact(&mut cert_bytes).map_err(|e| {
            TlsParserError::MalformedMessage(format!("Failed to read certificate bytes: {}", e))
        })?;
        certificates.push(cert_bytes);
    }

    // After parsing all certs, the cursor should be at the end of the payload
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
    // Changed error type to TlsParserError
    let mut cursor = Cursor::new(payload);

    // 1. EC Curve Type (1 byte) - always 0x03 for named_curve
    let curve_type = cursor
        .read_u8()
        .map_err(|e| TlsParserError::MalformedServerKeyExchange.into_generic(e))?;
    if curve_type != 0x03 {
        return Err(TlsParserError::InvalidNamedGroup(curve_type as u16)); // More specific error
    }

    // 2. Named Curve (2 bytes) - e.g., secp256r1 (0x0017)
    let named_curve = cursor
        .read_u16::<BigEndian>()
        .map_err(|e| TlsParserError::MalformedServerKeyExchange.into_generic(e))?;

    // 3. Public Key Length (1 byte)
    let public_key_len = cursor
        .read_u8()
        .map_err(|e| TlsParserError::MalformedServerKeyExchange.into_generic(e))?
        as usize;

    // 4. Public Key (variable length)
    let mut public_key_bytes = vec![0; public_key_len];
    cursor
        .read_exact(&mut public_key_bytes)
        .map_err(|e| TlsParserError::MalformedServerKeyExchange.into_generic(e))?;

    // 5. Signature Algorithm (2 bytes)
    let mut signature_algorithm = [0; 2];
    cursor
        .read_exact(&mut signature_algorithm)
        .map_err(|e| TlsParserError::MalformedServerKeyExchange.into_generic(e))?;

    // 6. Signature Length (2 bytes)
    let signature_len = cursor
        .read_u16::<BigEndian>()
        .map_err(|e| TlsParserError::MalformedServerKeyExchange.into_generic(e))?
        as usize;

    // 7. Signature (variable length)
    let mut signature_bytes = vec![0; signature_len];
    cursor
        .read_exact(&mut signature_bytes)
        .map_err(|e| TlsParserError::MalformedServerKeyExchange.into_generic(e))?;

    if cursor.position() as usize != payload.len() {
        return Err(TlsParserError::MalformedMessage(
            "ServerKeyExchange payload has unread trailing data".to_string(),
        ));
    }

    Ok(ServerKeyExchangeParsed {
        curve_type,
        named_curve,
        public_key: public_key_bytes,
        signature_algorithm,
        signature: signature_bytes, // FIXED: Matches struct definition (Vec<u8>)
    })
}

// Helper trait to convert std::io::Error to TlsParserError::GenericError
trait IntoGenericError<T> {
    fn into_generic(self, context: T) -> TlsParserError;
}

impl<E: std::fmt::Display> IntoGenericError<E> for TlsParserError {
    fn into_generic(self, context: E) -> TlsParserError {
        match self {
            TlsParserError::MalformedServerHello => TlsParserError::MalformedMessage(format!(
                "Malformed ServerHello message: {}",
                context
            )),
            TlsParserError::MalformedServerKeyExchange => TlsParserError::MalformedMessage(
                format!("Malformed ServerKeyExchange message: {}", context),
            ),
            TlsParserError::MalformedCertificateList => {
                TlsParserError::MalformedMessage(format!("Malformed Certificate list: {}", context))
            }
            _ => TlsParserError::GenericError(format!("Parser error: {}", context)),
        }
    }
}
