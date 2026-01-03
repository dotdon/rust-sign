//! Document signing functionality.

use crate::error::Result;
use crate::hash::{hash_bytes, hash_file, hash_reader};
use crate::keys::KeyPair;
use crate::signature::DocumentSignature;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

/// A builder for creating document signatures.
#[derive(Debug)]
pub struct Signer<'a> {
    keypair: &'a KeyPair,
    signer_id: Option<String>,
    metadata: HashMap<String, String>,
}

impl<'a> Signer<'a> {
    /// Create a new signer with the given keypair.
    pub fn new(keypair: &'a KeyPair) -> Self {
        Self {
            keypair,
            signer_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Set the signer ID (e.g., email address, name).
    pub fn with_signer_id<S: Into<String>>(mut self, signer_id: S) -> Self {
        self.signer_id = Some(signer_id.into());
        self
    }

    /// Add a metadata key-value pair.
    pub fn with_metadata<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Sign a byte slice.
    pub fn sign_bytes(&self, data: &[u8]) -> Result<DocumentSignature> {
        let hash = hash_bytes(data);
        let mut doc_sig = DocumentSignature::new(hash);
        doc_sig.add_signature_with_metadata(
            self.keypair,
            self.signer_id.clone(),
            self.metadata.clone(),
        )?;
        Ok(doc_sig)
    }

    /// Sign a file.
    pub fn sign_file<P: AsRef<Path>>(&self, path: P) -> Result<DocumentSignature> {
        let hash = hash_file(path)?;
        let mut doc_sig = DocumentSignature::new(hash);
        doc_sig.add_signature_with_metadata(
            self.keypair,
            self.signer_id.clone(),
            self.metadata.clone(),
        )?;
        Ok(doc_sig)
    }

    /// Sign data from a reader (streaming).
    pub fn sign_reader<R: Read>(&self, reader: &mut R) -> Result<DocumentSignature> {
        let hash = hash_reader(reader)?;
        let mut doc_sig = DocumentSignature::new(hash);
        doc_sig.add_signature_with_metadata(
            self.keypair,
            self.signer_id.clone(),
            self.metadata.clone(),
        )?;
        Ok(doc_sig)
    }

    /// Add a signature to an existing document signature.
    pub fn cosign(&self, doc_sig: &mut DocumentSignature) -> Result<()> {
        doc_sig.add_signature_with_metadata(
            self.keypair,
            self.signer_id.clone(),
            self.metadata.clone(),
        )
    }
}

/// Convenience function to sign bytes with a keypair.
pub fn sign_bytes(keypair: &KeyPair, data: &[u8]) -> Result<DocumentSignature> {
    Signer::new(keypair).sign_bytes(data)
}

/// Convenience function to sign a file with a keypair.
pub fn sign_file<P: AsRef<Path>>(keypair: &KeyPair, path: P) -> Result<DocumentSignature> {
    Signer::new(keypair).sign_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_bytes() {
        let keypair = KeyPair::generate();
        let data = b"Test document content";
        
        let doc_sig = Signer::new(&keypair)
            .with_signer_id("test@example.com")
            .sign_bytes(data)
            .unwrap();
        
        assert_eq!(doc_sig.signature_count(), 1);
        assert_eq!(
            doc_sig.signatures[0].signer_id,
            Some("test@example.com".to_string())
        );
    }

    #[test]
    fn test_sign_with_metadata() {
        let keypair = KeyPair::generate();
        let data = b"Test document content";
        
        let doc_sig = Signer::new(&keypair)
            .with_signer_id("test@example.com")
            .with_metadata("purpose", "testing")
            .with_metadata("version", "1.0")
            .sign_bytes(data)
            .unwrap();
        
        assert_eq!(doc_sig.signatures[0].metadata.get("purpose"), Some(&"testing".to_string()));
        assert_eq!(doc_sig.signatures[0].metadata.get("version"), Some(&"1.0".to_string()));
    }

    #[test]
    fn test_cosign() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let data = b"Test document content";
        
        let mut doc_sig = Signer::new(&keypair1)
            .with_signer_id("alice@example.com")
            .sign_bytes(data)
            .unwrap();
        
        Signer::new(&keypair2)
            .with_signer_id("bob@example.com")
            .cosign(&mut doc_sig)
            .unwrap();
        
        assert_eq!(doc_sig.signature_count(), 2);
    }

    #[test]
    fn test_convenience_functions() {
        let keypair = KeyPair::generate();
        let data = b"Test document content";
        
        let doc_sig = sign_bytes(&keypair, data).unwrap();
        assert_eq!(doc_sig.signature_count(), 1);
    }
}

