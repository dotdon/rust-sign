//! Signature verification functionality.

use crate::error::{Result, SignError};
use crate::hash::{hash_bytes, hash_file, hash_reader, DocumentHash};
use crate::signature::DocumentSignature;
use chrono::{DateTime, Utc};
use std::io::Read;
use std::path::Path;

/// Result of verifying a single signature.
#[derive(Debug, Clone)]
pub struct SignatureResult {
    /// The index of this signature in the document.
    pub index: usize,
    
    /// Whether the signature is valid.
    pub valid: bool,
    
    /// The signer ID, if present.
    pub signer_id: Option<String>,
    
    /// The timestamp of the signature.
    pub timestamp: DateTime<Utc>,
    
    /// Error message if verification failed.
    pub error: Option<String>,
}

/// Result of verifying all signatures on a document.
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether all signatures are valid.
    pub all_valid: bool,
    
    /// The document hash that was verified.
    pub document_hash: DocumentHash,
    
    /// Results for each individual signature.
    pub signatures: Vec<SignatureResult>,
}

impl VerificationResult {
    /// Get the number of valid signatures.
    pub fn valid_count(&self) -> usize {
        self.signatures.iter().filter(|s| s.valid).count()
    }

    /// Get the number of invalid signatures.
    pub fn invalid_count(&self) -> usize {
        self.signatures.iter().filter(|s| !s.valid).count()
    }

    /// Get all valid signer IDs.
    pub fn valid_signers(&self) -> Vec<Option<String>> {
        self.signatures
            .iter()
            .filter(|s| s.valid)
            .map(|s| s.signer_id.clone())
            .collect()
    }
}

/// Verifier for document signatures.
pub struct Verifier;

impl Verifier {
    /// Verify signatures on a byte slice.
    pub fn verify_bytes(data: &[u8], doc_sig: &DocumentSignature) -> Result<VerificationResult> {
        let actual_hash = hash_bytes(data);
        Self::verify_with_hash(actual_hash, doc_sig)
    }

    /// Verify signatures on a file.
    pub fn verify_file<P: AsRef<Path>>(
        path: P,
        signature_path: P,
    ) -> Result<VerificationResult> {
        let doc_sig = DocumentSignature::load(signature_path)?;
        let actual_hash = hash_file(path)?;
        Self::verify_with_hash(actual_hash, &doc_sig)
    }

    /// Verify signatures using a reader (streaming).
    pub fn verify_reader<R: Read>(
        reader: &mut R,
        doc_sig: &DocumentSignature,
    ) -> Result<VerificationResult> {
        let actual_hash = hash_reader(reader)?;
        Self::verify_with_hash(actual_hash, doc_sig)
    }

    /// Verify signatures against a known hash.
    pub fn verify_with_hash(
        actual_hash: DocumentHash,
        doc_sig: &DocumentSignature,
    ) -> Result<VerificationResult> {
        // Check that document hash matches
        let expected_hash = doc_sig.get_hash()?;
        if actual_hash != expected_hash {
            return Err(SignError::HashMismatch {
                expected: expected_hash.to_hex(),
                actual: actual_hash.to_hex(),
            });
        }

        if doc_sig.signatures.is_empty() {
            return Err(SignError::NoSignatures);
        }

        // Verify each signature
        let mut results = Vec::new();
        let mut all_valid = true;

        for (index, entry) in doc_sig.signatures.iter().enumerate() {
            let (valid, error) = match entry.verify(&actual_hash) {
                Ok(()) => (true, None),
                Err(e) => {
                    all_valid = false;
                    (false, Some(e.to_string()))
                }
            };

            results.push(SignatureResult {
                index,
                valid,
                signer_id: entry.signer_id.clone(),
                timestamp: entry.timestamp,
                error,
            });
        }

        Ok(VerificationResult {
            all_valid,
            document_hash: actual_hash,
            signatures: results,
        })
    }

    /// Quick check if all signatures are valid for bytes.
    pub fn is_valid_bytes(data: &[u8], doc_sig: &DocumentSignature) -> bool {
        Self::verify_bytes(data, doc_sig)
            .map(|r| r.all_valid)
            .unwrap_or(false)
    }

    /// Quick check if all signatures are valid for a file.
    pub fn is_valid_file<P: AsRef<Path>>(path: P, signature_path: P) -> bool {
        Self::verify_file(path, signature_path)
            .map(|r| r.all_valid)
            .unwrap_or(false)
    }
}

/// Convenience function to verify bytes against a signature.
pub fn verify_bytes(data: &[u8], doc_sig: &DocumentSignature) -> Result<VerificationResult> {
    Verifier::verify_bytes(data, doc_sig)
}

/// Convenience function to verify a file against its signature file.
pub fn verify_file<P: AsRef<Path>>(path: P, signature_path: P) -> Result<VerificationResult> {
    Verifier::verify_file(path, signature_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use crate::signer::Signer;

    #[test]
    fn test_verify_valid_signature() {
        let keypair = KeyPair::generate();
        let data = b"Test document content";
        
        let doc_sig = Signer::new(&keypair)
            .with_signer_id("test@example.com")
            .sign_bytes(data)
            .unwrap();
        
        let result = Verifier::verify_bytes(data, &doc_sig).unwrap();
        
        assert!(result.all_valid);
        assert_eq!(result.valid_count(), 1);
        assert_eq!(result.invalid_count(), 0);
    }

    #[test]
    fn test_verify_multiple_signatures() {
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
        
        let result = Verifier::verify_bytes(data, &doc_sig).unwrap();
        
        assert!(result.all_valid);
        assert_eq!(result.valid_count(), 2);
    }

    #[test]
    fn test_verify_tampered_document() {
        let keypair = KeyPair::generate();
        let original_data = b"Original content";
        let tampered_data = b"Tampered content";
        
        let doc_sig = Signer::new(&keypair).sign_bytes(original_data).unwrap();
        
        // Verification should fail with tampered data
        let result = Verifier::verify_bytes(tampered_data, &doc_sig);
        assert!(result.is_err());
        
        if let Err(SignError::HashMismatch { .. }) = result {
            // Expected error
        } else {
            panic!("Expected HashMismatch error");
        }
    }

    #[test]
    fn test_is_valid_convenience() {
        let keypair = KeyPair::generate();
        let data = b"Test document content";
        
        let doc_sig = Signer::new(&keypair).sign_bytes(data).unwrap();
        
        assert!(Verifier::is_valid_bytes(data, &doc_sig));
        assert!(!Verifier::is_valid_bytes(b"wrong data", &doc_sig));
    }

    #[test]
    fn test_valid_signers() {
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
        
        let result = Verifier::verify_bytes(data, &doc_sig).unwrap();
        let signers = result.valid_signers();
        
        assert!(signers.contains(&Some("alice@example.com".to_string())));
        assert!(signers.contains(&Some("bob@example.com".to_string())));
    }
}

