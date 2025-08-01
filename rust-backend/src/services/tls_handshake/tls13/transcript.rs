//TLS 1.3 Transcript Hash Management
//
//This module provides transcript hash functionality for TLS 1.3 handshakes as specified
//in RFC 8446. The transcript hash is a running hash of all handshake messages, including
//their 4-byte headers, and is critical for key derivation and message authentication.

use sha2::{Digest, Sha256, Sha384};

/// Hash algorithms supported for TLS 1.3 transcript hashing
///
/// Per RFC 8446:
/// - SHA-256 is used with cipher suites like TLS_AES_128_GCM_SHA256
/// - SHA-384 is used with cipher suites like TLS_AES_256_GCM_SHA384
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptHashAlgorithm {
    /// SHA-256 hash algorithm (32-byte output)
    Sha256,
    /// SHA-384 hash algorithm (48-byte output)
    Sha384,
}

/// TLS 1.3 transcript hash state manager
///
/// Maintains a running cryptographic hash of all handshake messages in the order
/// they are sent/received. This transcript is used for:
/// - Key derivation (client/server handshake traffic secrets)
/// - Finished message verification
/// - Certificate verification context
///
/// RFC 8446: The transcript includes the handshake message header (4 bytes) + payload.
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
    ///
    /// The hasher is initialized and ready to accept handshake message data.
    /// Only one hasher is active based on the chosen algorithm.
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

    /// Updates the transcript with raw byte data

    /// This is a low-level function that directly feeds bytes to the hasher.
    /// For handshake messages, prefer `update_handshake_message()` which handles
    /// the RFC 8446 message format automatically.
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

    /// Adds a complete handshake message to the transcript
    ///
    /// RFC 8446 Section 4.4.1: The transcript hash includes the handshake message
    /// header (4 bytes: type + 3-byte length) followed by the message payload.
    ///
    /// This function automatically constructs the proper header format and ensures
    /// both header and payload are hashed in the correct order.

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
    ///
    /// This function clones the internal hasher state, finalizes the clone,
    /// and returns the hash value while preserving the original hasher for
    /// additional updates.
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
    ///
    /// This function consumes the TranscriptHash instance and returns the final
    /// hash value. After calling this function, the hasher cannot be used for
    /// additional updates.
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
    /// Useful for determining the expected hash output length and for
    /// selecting the appropriate HKDF parameters in key derivation.
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
