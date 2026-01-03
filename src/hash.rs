//! BLAKE3 hashing utilities for document signing.

use crate::error::Result;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// The size of a BLAKE3 hash output in bytes.
pub const HASH_SIZE: usize = 32;

/// A BLAKE3 hash of document content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentHash([u8; HASH_SIZE]);

impl DocumentHash {
    /// Create a hash from raw bytes.
    pub fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of the hash.
    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    /// Encode the hash as a base64 string.
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Decode a hash from a base64 string.
    pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        if bytes.len() != HASH_SIZE {
            return Err(crate::error::SignError::InvalidFormat(format!(
                "Invalid hash length: expected {}, got {}",
                HASH_SIZE,
                bytes.len()
            )));
        }
        let mut arr = [0u8; HASH_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Encode the hash as a hexadecimal string.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Compute the BLAKE3 hash of a byte slice.
pub fn hash_bytes(data: &[u8]) -> DocumentHash {
    let hash = blake3::hash(data);
    DocumentHash(*hash.as_bytes())
}

/// Compute the BLAKE3 hash of a file using streaming (memory efficient).
pub fn hash_file<P: AsRef<Path>>(path: P) -> Result<DocumentHash> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    hash_reader(&mut reader)
}

/// Compute the BLAKE3 hash from any reader using streaming.
pub fn hash_reader<R: Read>(reader: &mut R) -> Result<DocumentHash> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 8192];
    
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    let hash = hasher.finalize();
    Ok(DocumentHash(*hash.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes() {
        let data = b"Hello, World!";
        let hash = hash_bytes(data);
        
        // Verify hash is consistent
        let hash2 = hash_bytes(data);
        assert_eq!(hash, hash2);
        
        // Different data should produce different hash
        let hash3 = hash_bytes(b"Different data");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Test data for hashing";
        let hash = hash_bytes(data);
        
        let encoded = hash.to_base64();
        let decoded = DocumentHash::from_base64(&encoded).unwrap();
        
        assert_eq!(hash, decoded);
    }

    #[test]
    fn test_hex_encoding() {
        let data = b"Test";
        let hash = hash_bytes(data);
        let hex = hash.to_hex();
        
        // Hex string should be 64 characters (32 bytes * 2)
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

