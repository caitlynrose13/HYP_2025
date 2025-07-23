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
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
    pub fn finalize(self) -> [u8; 32] {
        let result = self.hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    }
    pub fn clone_hash(&self) -> [u8; 32] {
        let hasher = self.hasher.clone();
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    }
}
