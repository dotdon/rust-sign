//! Integration tests for rust-sign library.

use rust_sign::{
    DocumentSignature, KeyPair, PublicKey, SignError, Signer, Verifier,
    hash_bytes, sign_bytes, verify_bytes,
};
use std::io::Cursor;

#[test]
fn test_full_signing_workflow() {
    // Generate keypair
    let keypair = KeyPair::generate();
    
    // Sign a document
    let document = b"This is an important legal document.";
    let signature = Signer::new(&keypair)
        .with_signer_id("legal@company.com")
        .with_metadata("document_type", "contract")
        .with_metadata("version", "1.0")
        .sign_bytes(document)
        .unwrap();
    
    // Verify JSON output structure
    let json = signature.to_json().unwrap();
    assert!(json.contains("\"version\": \"1.0\""));
    assert!(json.contains("\"document_hash\""));
    assert!(json.contains("\"signatures\""));
    assert!(json.contains("legal@company.com"));
    
    // Verify signature
    let result = Verifier::verify_bytes(document, &signature).unwrap();
    assert!(result.all_valid);
    assert_eq!(result.valid_count(), 1);
}

#[test]
fn test_multi_party_signing() {
    // Create multiple keypairs
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let charlie = KeyPair::generate();
    
    let document = b"Multi-party agreement document";
    
    // Alice initiates signing
    let mut signature = Signer::new(&alice)
        .with_signer_id("alice@example.com")
        .sign_bytes(document)
        .unwrap();
    
    // Bob and Charlie co-sign
    Signer::new(&bob)
        .with_signer_id("bob@example.com")
        .cosign(&mut signature)
        .unwrap();
    
    Signer::new(&charlie)
        .with_signer_id("charlie@example.com")
        .cosign(&mut signature)
        .unwrap();
    
    // Verify all signatures
    let result = Verifier::verify_bytes(document, &signature).unwrap();
    assert!(result.all_valid);
    assert_eq!(result.valid_count(), 3);
    
    // Check signers
    let signers = result.valid_signers();
    assert!(signers.contains(&Some("alice@example.com".to_string())));
    assert!(signers.contains(&Some("bob@example.com".to_string())));
    assert!(signers.contains(&Some("charlie@example.com".to_string())));
}

#[test]
fn test_json_roundtrip() {
    let keypair = KeyPair::generate();
    let document = b"Document for JSON roundtrip test";
    
    let signature = Signer::new(&keypair)
        .with_signer_id("test@example.com")
        .sign_bytes(document)
        .unwrap();
    
    // Serialize to JSON
    let json = signature.to_json().unwrap();
    
    // Deserialize from JSON
    let restored = DocumentSignature::from_json(&json).unwrap();
    
    // Verify restored signature
    let result = Verifier::verify_bytes(document, &restored).unwrap();
    assert!(result.all_valid);
}

#[test]
fn test_tamper_detection() {
    let keypair = KeyPair::generate();
    let original = b"Original document content";
    let tampered = b"Tampered document content";
    
    let signature = sign_bytes(&keypair, original).unwrap();
    
    // Verification with original should succeed
    assert!(Verifier::is_valid_bytes(original, &signature));
    
    // Verification with tampered content should fail
    assert!(!Verifier::is_valid_bytes(tampered, &signature));
    
    // Check the specific error type
    let result = verify_bytes(tampered, &signature);
    assert!(matches!(result, Err(SignError::HashMismatch { .. })));
}

#[test]
fn test_streaming_signature() {
    let keypair = KeyPair::generate();
    let document = b"Large document content that would be streamed";
    
    // Create a cursor to simulate a reader
    let mut reader = Cursor::new(document);
    
    let signature = Signer::new(&keypair)
        .sign_reader(&mut reader)
        .unwrap();
    
    // Verify against bytes
    let result = Verifier::verify_bytes(document, &signature).unwrap();
    assert!(result.all_valid);
}

#[test]
fn test_public_key_extraction() {
    let keypair = KeyPair::generate();
    let public_key = keypair.public_key();
    
    // Sign with keypair
    let message = b"Test message";
    let signature_bytes = keypair.sign(message);
    
    // Verify with extracted public key
    assert!(public_key.verify(message, &signature_bytes).is_ok());
    
    // Test base64 roundtrip
    let encoded = public_key.to_base64();
    let decoded = PublicKey::from_base64(&encoded).unwrap();
    assert_eq!(public_key.as_bytes(), decoded.as_bytes());
}

#[test]
fn test_keypair_bytes_roundtrip() {
    let original = KeyPair::generate();
    let secret_bytes = original.secret_bytes();
    
    let restored = KeyPair::from_bytes(&secret_bytes);
    
    // Verify they produce the same signatures
    let message = b"Test message";
    let sig1 = original.sign(message);
    let sig2 = restored.sign(message);
    
    assert_eq!(sig1, sig2);
}

#[test]
fn test_hash_consistency() {
    let data = b"Consistent hashing test data";
    
    let hash1 = hash_bytes(data);
    let hash2 = hash_bytes(data);
    
    assert_eq!(hash1, hash2);
    assert_eq!(hash1.to_base64(), hash2.to_base64());
    assert_eq!(hash1.to_hex(), hash2.to_hex());
}

#[test]
fn test_signature_timestamps() {
    let keypair = KeyPair::generate();
    let document = b"Document with timestamp";
    
    let signature = Signer::new(&keypair)
        .sign_bytes(document)
        .unwrap();
    
    // Check that timestamp is present and recent
    let entry = &signature.signatures[0];
    let now = chrono::Utc::now();
    let diff = now - entry.timestamp;
    
    // Signature should have been created within the last minute
    assert!(diff.num_seconds() < 60);
}

#[test]
fn test_empty_signer_id() {
    let keypair = KeyPair::generate();
    let document = b"Document without signer ID";
    
    // Sign without signer ID
    let signature = Signer::new(&keypair)
        .sign_bytes(document)
        .unwrap();
    
    assert!(signature.signatures[0].signer_id.is_none());
    
    // Verify should still work
    let result = Verifier::verify_bytes(document, &signature).unwrap();
    assert!(result.all_valid);
}

#[test]
fn test_metadata_preservation() {
    let keypair = KeyPair::generate();
    let document = b"Document with metadata";
    
    let signature = Signer::new(&keypair)
        .with_metadata("key1", "value1")
        .with_metadata("key2", "value2")
        .sign_bytes(document)
        .unwrap();
    
    // Roundtrip through JSON
    let json = signature.to_json().unwrap();
    let restored = DocumentSignature::from_json(&json).unwrap();
    
    let metadata = &restored.signatures[0].metadata;
    assert_eq!(metadata.get("key1"), Some(&"value1".to_string()));
    assert_eq!(metadata.get("key2"), Some(&"value2".to_string()));
}

