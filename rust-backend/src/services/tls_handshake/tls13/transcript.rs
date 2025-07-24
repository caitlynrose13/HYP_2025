// TLS 1.3 transcript hash management

use sha2::{Digest, Sha256};

pub struct TranscriptHash {
    hasher: Sha256,
}

impl TranscriptHash {
    pub fn new() -> Self {
        TranscriptHash {
            hasher: Sha256::new(),
        }
    }

    /// Update transcript with raw handshake message bytes
    /// RFC 8446: The transcript hash includes the handshake message header (4 bytes) + payload
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Add a complete handshake message to the transcript
    /// This ensures the 4-byte handshake header is included
    pub fn update_handshake_message(&mut self, msg_type: u8, payload: &[u8]) {
        // RFC 8446: Handshake message format:
        // struct {
        //     HandshakeType msg_type;    /* handshake type */
        //     uint24 length;             /* bytes in message */
        //     select (Handshake.msg_type) {
        //         ...
        //     };
        // } Handshake;

        let length = payload.len() as u32;
        let mut message = Vec::with_capacity(4 + payload.len());

        // Add handshake message header (4 bytes)
        message.push(msg_type); // msg_type (1 byte)
        message.extend_from_slice(&length.to_be_bytes()[1..]); // length (3 bytes, big-endian)
        message.extend_from_slice(payload); // payload

        self.hasher.update(&message);
    }

    /// Get the current transcript hash without consuming the hasher
    pub fn clone_hash(&self) -> [u8; 32] {
        let hasher = self.hasher.clone();
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    }

    /// Finalize and consume the hasher
    pub fn finalize(self) -> [u8; 32] {
        let result = self.hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    }

    /// Reset the transcript hash (useful for debugging)
    pub fn reset(&mut self) {
        self.hasher = Sha256::new();
    }
}
