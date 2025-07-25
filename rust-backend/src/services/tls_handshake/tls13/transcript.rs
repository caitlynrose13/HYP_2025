// TLS 1.3 transcript hash management

use sha2::{Digest, Sha256, Sha384};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptHashAlgorithm {
    Sha256,
    Sha384,
}

#[derive(Clone)]
pub struct TranscriptHash {
    hash_alg: TranscriptHashAlgorithm,
    sha256: Option<Sha256>,
    sha384: Option<Sha384>,
}

impl TranscriptHash {
    pub fn new(hash_alg: TranscriptHashAlgorithm) -> Self {
        match hash_alg {
            TranscriptHashAlgorithm::Sha256 => TranscriptHash {
                hash_alg,
                sha256: Some(Sha256::new()),
                sha384: None,
            },
            TranscriptHashAlgorithm::Sha384 => TranscriptHash {
                hash_alg,
                sha256: None,
                sha384: Some(Sha384::new()),
            },
        }
    }

    /// Update transcript with raw handshake message bytes
    /// RFC 8446: The transcript hash includes the handshake message header (4 bytes) + payload
    pub fn update(&mut self, data: &[u8]) {
        match self.hash_alg {
            TranscriptHashAlgorithm::Sha256 => self.sha256.as_mut().unwrap().update(data),
            TranscriptHashAlgorithm::Sha384 => self.sha384.as_mut().unwrap().update(data),
        }
    }

    /// Add a complete handshake message to the transcript using RFC 8446 header + body
    /// This ensures the 4-byte handshake header is included and hashed correctly
    pub fn update_handshake_message(&mut self, msg_type: u8, payload: &[u8]) {
        let mut header = [0u8; 4];
        header[0] = msg_type;
        let len = payload.len();
        header[1..].copy_from_slice(&(len as u32).to_be_bytes()[1..]); // 3 bytes
        self.update(&header);
        self.update(payload);
    }

    /// Get the current transcript hash without consuming the hasher
    pub fn clone_hash(&self) -> Result<Vec<u8>, &'static str> {
        match self.hash_alg {
            TranscriptHashAlgorithm::Sha256 => {
                if let Some(hasher) = self.sha256.as_ref() {
                    let result = hasher.clone().finalize();
                    Ok(result.to_vec())
                } else {
                    log::error!("[TRANSCRIPT] ERROR: Sha256 hasher not initialized!");
                    Err("Sha256 hasher not initialized")
                }
            }
            TranscriptHashAlgorithm::Sha384 => {
                if let Some(hasher) = self.sha384.as_ref() {
                    let result = hasher.clone().finalize();
                    Ok(result.to_vec())
                } else {
                    log::error!("[TRANSCRIPT] ERROR: Sha384 hasher not initialized!");
                    Err("Sha384 hasher not initialized")
                }
            }
        }
    }

    /// Finalize and consume the hasher
    pub fn finalize(self) -> Vec<u8> {
        match self.hash_alg {
            TranscriptHashAlgorithm::Sha256 => self.sha256.unwrap().finalize().to_vec(),
            TranscriptHashAlgorithm::Sha384 => self.sha384.unwrap().finalize().to_vec(),
        }
    }

    /// Reset the transcript hash (useful for debugging)
    pub fn reset(&mut self) {
        match self.hash_alg {
            TranscriptHashAlgorithm::Sha256 => self.sha256 = Some(Sha256::new()),
            TranscriptHashAlgorithm::Sha384 => self.sha384 = Some(Sha384::new()),
        }
    }
}
