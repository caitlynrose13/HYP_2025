pub struct TlsServerInfo {
    pub negotiated_version: String,
    pub cert_der: Option<Vec<u8>>,
}

pub fn parse_tls_response(response: &[u8]) -> Result<TlsServerInfo, String> {
    if response.len() < 5 {
        return Err("Response too short, must be at least 5 bytes!".into());
    }

    let content_type = response[0];
    let version_major = response[1];
    let version_minor = response[2];
    let tls_version = format!("TLS {},{}", version_major - 2, version_minor);

    if content_type != 0x16 {
        return Err("Invalid content type, expected Handshake (0x16)".into());
    }

    let handshake_type = response[5];
    if handshake_type != 0x02 {
        return Err(format!(
            "Expected ServerHello (0x02), got: 0x{:02X}",
            handshake_type
        ));
    }

    let mut offset = 5;
    let mut cert_der: Option<Vec<u8>> = None;

    while offset < response.len() {
        let msg_type = response[offset];
        let msg_len = ((response[offset + 1] as u32) << 16)
            | ((response[offset + 2] as u32) << 8)
            | (response[offset + 3] as u32);
        let msg_body = &response[offset + 4..offset + 4 + msg_len as usize];

        if msg_type == 0x0b {
            // Certificate message found!
            let cert_list_len = ((msg_body[0] as usize) << 16)
                | ((msg_body[1] as usize) << 8)
                | msg_body[2] as usize;

            let cert_len = ((msg_body[3] as usize) << 16)
                | ((msg_body[4] as usize) << 8)
                | msg_body[5] as usize;

            cert_der = Some(msg_body[6..6 + cert_len].to_vec());
            break;
        }

        offset += 4 + msg_len as usize;
    }

    Ok(TlsServerInfo {
        negotiated_version: tls_version,
        cert_der,
    })
}
