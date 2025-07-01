//meant to read the server's handshake messages
use std::io::{Cursor, Read};

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
    // ... add any other error variants you have in your actual code
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

// -- functions --
pub fn parse_tls_record(reader: &mut Cursor<&[u8]>) -> Result<Option<TlsRecord>, TlsParserError> {
    let current_pos = reader.position() as usize;
    let remaining_len = reader.get_ref().len() - current_pos;

    if remaining_len < 5 {
        return Ok(None);
    }

    let mut header_buf = [0u8; 5];
    reader.read_exact(&mut header_buf)?;

    let content_type_byte = header_buf[0];
    let version_major = header_buf[1];
    let version_minor = header_buf[2];
    let length = u16::from_be_bytes([header_buf[3], header_buf[4]]);

    if remaining_len < 5 + length as usize {
        reader.set_position(current_pos as u64);
        return Ok(None);
    }

    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload)?;

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
    let mut messages = Vec::new();
    let mut offset = 0;

    while offset + 4 <= payload.len() {
        let msg_type_byte = payload[offset];
        let msg_len = ((payload[offset + 1] as u32) << 16)
            | ((payload[offset + 2] as u32) << 8)
            | (payload[offset + 3] as u32);

        let body_start = offset + 4;
        let body_end = body_start + msg_len as usize;

        if body_end > payload.len() {
            return Err(TlsParserError::MalformedMessage(format!(
                "Handshake message length ({}) exceeds record payload size ({}). Offset: {}",
                msg_len,
                payload.len(),
                offset
            )));
        }

        let msg_payload = payload[body_start..body_end].to_vec();

        messages.push(TlsHandshakeMessage {
            msg_type: msg_type_byte.into(),
            payload: msg_payload,
        });

        offset = body_end;
    }
    Ok(messages)
}

pub fn parse_server_hello_content(payload: &[u8]) -> Result<ServerHelloParsed, TlsParserError> {
    if payload.len() < 38 {
        return Err(TlsParserError::MalformedMessage(
            "ServerHello payload too short.".to_string(),
        ));
    }

    let negotiated_tls_version = (payload[0], payload[1]);
    let mut server_random_bytes = [0u8; 32];
    server_random_bytes.copy_from_slice(&payload[2..34]);

    let session_id_len = payload[34] as usize;
    let mut current_offset = 35 + session_id_len;

    if current_offset + 2 > payload.len() {
        return Err(TlsParserError::MalformedMessage(
            "ServerHello payload too short for cipher suite.".to_string(),
        ));
    }
    let chosen_cipher_suite = [payload[current_offset], payload[current_offset + 1]];
    current_offset += 2;

    if current_offset + 1 > payload.len() {
        return Err(TlsParserError::MalformedMessage(
            "ServerHello payload too short for compression method.".to_string(),
        ));
    }
    current_offset += 1;

    let mut server_key_share_public: Option<Vec<u8>> = None;
    // Check if there are extensions
    if current_offset + 2 <= payload.len() {
        let extensions_len =
            u16::from_be_bytes([payload[current_offset], payload[current_offset + 1]]) as usize;
        current_offset += 2;

        if current_offset + extensions_len > payload.len() {
            return Err(TlsParserError::MalformedMessage(
                "ServerHello extensions length mismatch.".to_string(),
            ));
        }

        let mut ext_offset = 0;
        let extensions_data = &payload[current_offset..current_offset + extensions_len];

        while ext_offset + 4 <= extensions_data.len() {
            let ext_type =
                u16::from_be_bytes([extensions_data[ext_offset], extensions_data[ext_offset + 1]]);
            let ext_len = u16::from_be_bytes([
                extensions_data[ext_offset + 2],
                extensions_data[ext_offset + 3],
            ]) as usize;
            ext_offset += 4;

            if ext_offset + ext_len > extensions_data.len() {
                return Err(TlsParserError::MalformedMessage(
                    "ServerHello extension data length mismatch.".to_string(),
                ));
            }

            let ext_content = &extensions_data[ext_offset..ext_offset + ext_len];

            if negotiated_tls_version.0 == 0x03 && negotiated_tls_version.1 == 0x04 {
                // TLS 1.3
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

            ext_offset += ext_len;
        }
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
    let mut certificates = Vec::new();
    let mut offset = 0;

    if payload.len() < 3 {
        return Err(TlsParserError::MalformedMessage(
            "Certificate message payload too short for list length".to_string(),
        ));
    }

    let total_certs_len =
        ((payload[0] as usize) << 16) | ((payload[1] as usize) << 8) | (payload[2] as usize);
    offset += 3;

    if total_certs_len > payload.len() - 3 {
        return Err(TlsParserError::MalformedMessage(format!(
            "Certificate list declared length ({}) exceeds actual message payload ({} remaining)",
            total_certs_len,
            payload.len() - 3
        )));
    }

    while offset + 3 <= payload.len() {
        let cert_len = ((payload[offset] as usize) << 16)
            | ((payload[offset + 1] as usize) << 8)
            | (payload[offset + 2] as usize);
        offset += 3;

        if offset + cert_len > payload.len() {
            return Err(TlsParserError::MalformedMessage(format!(
                "Individual certificate length ({}) exceeds list bounds. Offset: {}, Remaining payload: {}",
                cert_len,
                offset,
                payload.len() - offset
            )));
        }

        certificates.push(payload[offset..offset + cert_len].to_vec());
        offset += cert_len;
    }

    // After parsing all certs, the offset should match the total_certs_len + 3
    if offset != total_certs_len + 3 {
        return Err(TlsParserError::MalformedMessage(format!(
            "Mismatched certificate list length. Parsed: {}, Declared: {}",
            offset - 3,
            total_certs_len
        )));
    }

    Ok(certificates)
}

pub fn parse_server_key_exchange_content(payload: &[u8]) -> Result<Vec<u8>, TlsParserError> {
    // later need to:
    //Identify the group (e.g., Diffie-Hellman or ECDH parameters).
    // Extract the server's ephemeral public key.
    //  Extract the signature algorithm used.
    // Extract the signature itself.
    if payload.is_empty() {
        Err(TlsParserError::MalformedMessage(
            "ServerKeyExchange payload is empty".to_string(),
        ))
    } else {
        Ok(payload.to_vec())
    }
}
