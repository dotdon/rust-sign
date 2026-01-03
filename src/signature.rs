//! Signature data structures and JSON serialization.

use crate::error::{Result, SignError};
use crate::hash::DocumentHash;
use crate::keys::{KeyPair, PublicKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// The current version of the signature format.
pub const FORMAT_VERSION: &str = "1.0";

/// A signed document containing one or more signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSignature {
    /// Format version for compatibility.
    pub version: String,
    
    /// The BLAKE3 hash of the document (base64 encoded).
    pub document_hash: String,
    
    /// List of signatures on this document.
    pub signatures: Vec<SignatureEntry>,
}

/// A single signature entry with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEntry {
    /// Optional identifier for the signer (e.g., email, name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,
    
    /// The public key that created this signature (base64 encoded).
    pub public_key: String,
    
    /// The Ed25519 signature bytes (base64 encoded).
    pub signature: String,
    
    /// Timestamp when the signature was created.
    pub timestamp: DateTime<Utc>,
    
    /// Optional additional metadata.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl DocumentSignature {
    /// Create a new document signature for the given hash.
    pub fn new(document_hash: DocumentHash) -> Self {
        Self {
            version: FORMAT_VERSION.to_string(),
            document_hash: document_hash.to_base64(),
            signatures: Vec::new(),
        }
    }

    /// Get the document hash.
    pub fn get_hash(&self) -> Result<DocumentHash> {
        DocumentHash::from_base64(&self.document_hash)
    }

    /// Add a signature to this document.
    pub fn add_signature(
        &mut self,
        keypair: &KeyPair,
        signer_id: Option<String>,
    ) -> Result<()> {
        self.add_signature_with_metadata(keypair, signer_id, HashMap::new())
    }

    /// Add a signature with custom metadata.
    pub fn add_signature_with_metadata(
        &mut self,
        keypair: &KeyPair,
        signer_id: Option<String>,
        metadata: HashMap<String, String>,
    ) -> Result<()> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;

        // Get the hash bytes
        let hash = self.get_hash()?;
        
        // Sign the hash
        let signature_bytes = keypair.sign(hash.as_bytes());
        
        let entry = SignatureEntry {
            signer_id,
            public_key: keypair.public_key().to_base64(),
            signature: engine.encode(signature_bytes),
            timestamp: Utc::now(),
            metadata,
        };
        
        self.signatures.push(entry);
        Ok(())
    }

    /// Save the signature to a JSON file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load a signature from a JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let sig: Self = serde_json::from_str(&content)?;
        Ok(sig)
    }

    /// Parse a signature from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        let sig: Self = serde_json::from_str(json)?;
        Ok(sig)
    }

    /// Serialize the signature to a JSON string.
    pub fn to_json(&self) -> Result<String> {
        let json = serde_json::to_string_pretty(self)?;
        Ok(json)
    }

    /// Get the number of signatures.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Check if there are any signatures.
    pub fn has_signatures(&self) -> bool {
        !self.signatures.is_empty()
    }
}

impl SignatureEntry {
    /// Get the public key from this entry.
    pub fn get_public_key(&self) -> Result<PublicKey> {
        PublicKey::from_base64(&self.public_key)
    }

    /// Get the signature bytes.
    pub fn get_signature_bytes(&self) -> Result<[u8; 64]> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        
        let bytes = engine.decode(&self.signature)?;
        if bytes.len() != 64 {
            return Err(SignError::InvalidFormat(format!(
                "Invalid signature length: expected 64, got {}",
                bytes.len()
            )));
        }
        
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Verify this signature against a document hash.
    pub fn verify(&self, document_hash: &DocumentHash) -> Result<()> {
        let public_key = self.get_public_key()?;
        let signature = self.get_signature_bytes()?;
        public_key.verify(document_hash.as_bytes(), &signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_bytes;

    #[test]
    fn test_create_and_sign() {
        let keypair = KeyPair::generate();
        let data = b"Test document content";
        let hash = hash_bytes(data);
        
        let mut doc_sig = DocumentSignature::new(hash);
        doc_sig.add_signature(&keypair, Some("alice@example.com".to_string())).unwrap();
        
        assert_eq!(doc_sig.signature_count(), 1);
        assert!(doc_sig.has_signatures());
    }

    #[test]
    fn test_multiple_signatures() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let data = b"Test document content";
        let hash = hash_bytes(data);
        
        let mut doc_sig = DocumentSignature::new(hash);
        doc_sig.add_signature(&keypair1, Some("alice@example.com".to_string())).unwrap();
        doc_sig.add_signature(&keypair2, Some("bob@example.com".to_string())).unwrap();
        
        assert_eq!(doc_sig.signature_count(), 2);
    }

    #[test]
    fn test_json_roundtrip() {
        let keypair = KeyPair::generate();
        let data = b"Test document content";
        let hash = hash_bytes(data);
        
        let mut doc_sig = DocumentSignature::new(hash);
        doc_sig.add_signature(&keypair, Some("alice@example.com".to_string())).unwrap();
        
        let json = doc_sig.to_json().unwrap();
        let restored = DocumentSignature::from_json(&json).unwrap();
        
        assert_eq!(doc_sig.document_hash, restored.document_hash);
        assert_eq!(doc_sig.signature_count(), restored.signature_count());
    }

    #[test]
    fn test_verify_signature() {
        let keypair = KeyPair::generate();
        let data = b"Test document content";
        let hash = hash_bytes(data);
        
        let mut doc_sig = DocumentSignature::new(hash.clone());
        doc_sig.add_signature(&keypair, None).unwrap();
        
        // Verification should succeed
        let result = doc_sig.signatures[0].verify(&hash);
        assert!(result.is_ok());
        
        // Verification with wrong hash should fail
        let wrong_hash = hash_bytes(b"Different content");
        let result = doc_sig.signatures[0].verify(&wrong_hash);
        assert!(result.is_err());
    }
}

