//TLS 1.3 Transcript Hash Management

use sha2::{Digest, Sha256, Sha384};

//This file manages the TLS 1.3 transcript hash,
//which is a running hash of all handshake messages exchanged between client and server.

/// Hash algorithms supported for TLS 1.3 transcript hashing
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptHashAlgorithm {
    Sha256,
    Sha384,
}

/// TLS 1.3 transcript hash state manager
#[derive(Clone)]
pub struct TranscriptHash {
    /// The hash algorithm being used for this transcript
    hash_alg: TranscriptHashAlgorithm,
    /// SHA-256 hasher (used when hash_alg is Sha256)
    sha256: Option<Sha256>,
    /// SHA-384 hasher (used when hash_alg is Sha384)
    sha384: Option<Sha384>,
}

// =================================
// IMPLEMENTATION

impl TranscriptHash {
    /// Creates a new transcript hash with the specified algorithm
    pub fn new(hash_alg: TranscriptHashAlgorithm) -> Self {
        match hash_alg {
            TranscriptHashAlgorithm::Sha256 => Self {
                hash_alg,
                sha256: Some(Sha256::new()),
                sha384: None,
            },
            TranscriptHashAlgorithm::Sha384 => Self {
                hash_alg,
                sha256: None,
                sha384: Some(Sha384::new()),
            },
        }
    }

    /// Updates the transcript with raw byte data.
    pub fn update(&mut self, data: &[u8]) {
        match self.hash_alg {
            TranscriptHashAlgorithm::Sha256 => {
                self.sha256
                    .as_mut()
                    .expect("SHA-256 hasher should be initialized")
                    .update(data);
            }
            TranscriptHashAlgorithm::Sha384 => {
                self.sha384
                    .as_mut()
                    .expect("SHA-384 hasher should be initialized")
                    .update(data);
            }
        }
    }

    /// Adds a complete handshake message to the transcrip

    pub fn update_handshake_message(&mut self, msg_type: u8, payload: &[u8]) {
        // Construct the 4-byte handshake header per RFC 8446
        let mut header = [0u8; 4];
        header[0] = msg_type; // Message type (1 byte)

        // Message length (3 bytes, big-endian)
        let length_bytes = (payload.len() as u32).to_be_bytes();
        header[1..4].copy_from_slice(&length_bytes[1..4]);

        // Hash header followed by payload
        self.update(&header);
        self.update(payload);
    }

    /// Gets the current transcript hash without consuming the hasher
    pub fn clone_hash(&self) -> Result<Vec<u8>, &'static str> {
        match self.hash_alg {
            TranscriptHashAlgorithm::Sha256 => self
                .sha256
                .as_ref()
                .ok_or("SHA-256 hasher not initialized")
                .map(|hasher| hasher.clone().finalize().to_vec()),
            TranscriptHashAlgorithm::Sha384 => self
                .sha384
                .as_ref()
                .ok_or("SHA-384 hasher not initialized")
                .map(|hasher| hasher.clone().finalize().to_vec()),
        }
    }

    /// Finalizes and consumes the transcript hasher
    pub fn finalize(self) -> Vec<u8> {
        match self.hash_alg {
            TranscriptHashAlgorithm::Sha256 => self
                .sha256
                .expect("SHA-256 hasher should be initialized")
                .finalize()
                .to_vec(),
            TranscriptHashAlgorithm::Sha384 => self
                .sha384
                .expect("SHA-384 hasher should be initialized")
                .finalize()
                .to_vec(),
        }
    }

    /// Returns the hash algorithm being used
    pub fn algorithm(&self) -> TranscriptHashAlgorithm {
        self.hash_alg
    }

    /// Returns the expected hash output length in bytes
    pub fn hash_length(&self) -> usize {
        match self.hash_alg {
            TranscriptHashAlgorithm::Sha256 => 32,
            TranscriptHashAlgorithm::Sha384 => 48,
        }
    }

    /// Checks if the transcript hasher is properly initialized
    pub fn is_initialized(&self) -> bool {
        match self.hash_alg {
            TranscriptHashAlgorithm::Sha256 => self.sha256.is_some(),
            TranscriptHashAlgorithm::Sha384 => self.sha384.is_some(),
        }
    }
}

// =================================================
// UTILITY IMPLEMENTATIONS

impl TranscriptHashAlgorithm {
    /// Returns the hash output length in bytes
    pub fn hash_length(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    /// Returns the algorithm name as a string
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
        }
    }

    /// Creates a TranscriptHash instance using this algorithm
    pub fn create_transcript(self) -> TranscriptHash {
        TranscriptHash::new(self)
    }
}

impl std::fmt::Display for TranscriptHashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Default for TranscriptHashAlgorithm {
    /// Default to SHA-256 as it's the most widely supported
    fn default() -> Self {
        Self::Sha256
    }
}
