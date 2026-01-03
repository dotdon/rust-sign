//! Key generation and management for Ed25519 signing.

use crate::error::{Result, SignError};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer as DalekSigner};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

/// An Ed25519 keypair for signing documents.
#[derive(Debug)]
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create a keypair from raw secret key bytes (32 bytes).
    pub fn from_bytes(secret_bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret_bytes);
        Self { signing_key }
    }

    /// Get the secret key bytes.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Sign a message and return the signature bytes.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature = self.signing_key.sign(message);
        signature.to_bytes()
    }

    /// Save the keypair to a file.
    /// 
    /// The file format is:
    /// - Line 1: "RUST-SIGN PRIVATE KEY"
    /// - Line 2: Base64-encoded secret key
    /// - Line 3: Base64-encoded public key
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        
        let secret_b64 = engine.encode(self.signing_key.to_bytes());
        let public_b64 = engine.encode(self.public_key().as_bytes());
        
        let content = format!(
            "RUST-SIGN PRIVATE KEY\n{}\n{}\n",
            secret_b64, public_b64
        );
        
        fs::write(path, content)?;
        Ok(())
    }

    /// Load a keypair from a file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        
        let content = fs::read_to_string(path)?;
        let lines: Vec<&str> = content.lines().collect();
        
        if lines.len() < 2 || lines[0] != "RUST-SIGN PRIVATE KEY" {
            return Err(SignError::InvalidKey(
                "Invalid key file format".to_string(),
            ));
        }
        
        let secret_bytes = engine.decode(lines[1])?;
        if secret_bytes.len() != 32 {
            return Err(SignError::InvalidKey(format!(
                "Invalid secret key length: expected 32, got {}",
                secret_bytes.len()
            )));
        }
        
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&secret_bytes);
        Ok(Self::from_bytes(&arr))
    }
}

/// An Ed25519 public key for verifying signatures.
#[derive(Debug, Clone)]
pub struct PublicKey {
    verifying_key: VerifyingKey,
}

impl PublicKey {
    /// Create a public key from raw bytes (32 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(SignError::InvalidKey(format!(
                "Invalid public key length: expected 32, got {}",
                bytes.len()
            )));
        }
        
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        let verifying_key = VerifyingKey::from_bytes(&arr)?;
        Ok(Self { verifying_key })
    }

    /// Get the raw bytes of the public key.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Encode the public key as base64.
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.as_bytes())
    }

    /// Decode a public key from base64.
    pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(s)?;
        Self::from_bytes(&bytes)
    }

    /// Verify a signature on a message.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        use ed25519_dalek::Signature;
        let sig = Signature::from_bytes(signature);
        self.verifying_key.verify_strict(message, &sig)?;
        Ok(())
    }

    /// Save the public key to a file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        
        let public_b64 = engine.encode(self.as_bytes());
        let content = format!("RUST-SIGN PUBLIC KEY\n{}\n", public_b64);
        
        fs::write(path, content)?;
        Ok(())
    }

    /// Load a public key from a file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        
        let content = fs::read_to_string(path)?;
        let lines: Vec<&str> = content.lines().collect();
        
        if lines.len() < 2 || lines[0] != "RUST-SIGN PUBLIC KEY" {
            return Err(SignError::InvalidKey(
                "Invalid public key file format".to_string(),
            ));
        }
        
        let public_bytes = engine.decode(lines[1])?;
        Self::from_bytes(&public_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();
        let public_key = keypair.public_key();
        
        // Verify we can sign and verify
        let message = b"Test message";
        let signature = keypair.sign(message);
        
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_keypair_roundtrip() {
        let keypair = KeyPair::generate();
        let secret_bytes = keypair.secret_bytes();
        
        let restored = KeyPair::from_bytes(&secret_bytes);
        assert_eq!(keypair.secret_bytes(), restored.secret_bytes());
    }

    #[test]
    fn test_invalid_signature_fails() {
        let keypair = KeyPair::generate();
        let other_keypair = KeyPair::generate();
        
        let message = b"Test message";
        let signature = other_keypair.sign(message);
        
        // Signature from different key should fail
        assert!(keypair.public_key().verify(message, &signature).is_err());
    }

    #[test]
    fn test_public_key_base64_roundtrip() {
        let keypair = KeyPair::generate();
        let public_key = keypair.public_key();
        
        let encoded = public_key.to_base64();
        let decoded = PublicKey::from_base64(&encoded).unwrap();
        
        assert_eq!(public_key.as_bytes(), decoded.as_bytes());
    }
}

