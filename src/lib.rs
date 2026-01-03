//! # rust-sign
//!
//! A document signing library using BLAKE3 hashing and Ed25519 signatures.
//!
//! ## Features
//!
//! - **BLAKE3 hashing** for fast, secure document fingerprinting
//! - **Ed25519 signatures** for compact, secure digital signatures
//! - **Multiple signatures** support for multi-party signing
//! - **JSON output** with timestamps and metadata
//! - **Streaming** support for large files
//!
//! ## Quick Start
//!
//! ### Generate a Keypair
//!
//! ```rust
//! use rust_sign::KeyPair;
//!
//! let keypair = KeyPair::generate();
//! // Save to file (optional)
//! // keypair.save_to_file("my_key.pem").unwrap();
//! ```
//!
//! ### Sign a Document
//!
//! ```rust
//! use rust_sign::{KeyPair, Signer};
//!
//! let keypair = KeyPair::generate();
//! let document = b"Important document content";
//!
//! let signature = Signer::new(&keypair)
//!     .with_signer_id("alice@example.com")
//!     .with_metadata("purpose", "contract")
//!     .sign_bytes(document)
//!     .unwrap();
//!
//! // Save signature to file
//! // signature.save("document.sig").unwrap();
//! println!("{}", signature.to_json().unwrap());
//! ```
//!
//! ### Verify a Signature
//!
//! ```rust
//! use rust_sign::{KeyPair, Signer, Verifier};
//!
//! let keypair = KeyPair::generate();
//! let document = b"Important document content";
//!
//! let signature = Signer::new(&keypair).sign_bytes(document).unwrap();
//!
//! let result = Verifier::verify_bytes(document, &signature).unwrap();
//! assert!(result.all_valid);
//! println!("All {} signatures valid!", result.valid_count());
//! ```
//!
//! ### Multiple Signatures
//!
//! ```rust
//! use rust_sign::{KeyPair, Signer, Verifier};
//!
//! let alice = KeyPair::generate();
//! let bob = KeyPair::generate();
//! let document = b"Contract requiring multiple signatures";
//!
//! // Alice signs first
//! let mut signature = Signer::new(&alice)
//!     .with_signer_id("alice@example.com")
//!     .sign_bytes(document)
//!     .unwrap();
//!
//! // Bob co-signs
//! Signer::new(&bob)
//!     .with_signer_id("bob@example.com")
//!     .cosign(&mut signature)
//!     .unwrap();
//!
//! // Verify all signatures
//! let result = Verifier::verify_bytes(document, &signature).unwrap();
//! assert!(result.all_valid);
//! assert_eq!(result.valid_count(), 2);
//! ```

pub mod error;
pub mod hash;
pub mod keys;
pub mod signature;
pub mod signer;
pub mod verifier;

// Re-export main types for convenience
pub use error::{Result, SignError};
pub use hash::{hash_bytes, hash_file, hash_reader, DocumentHash};
pub use keys::{KeyPair, PublicKey};
pub use signature::{DocumentSignature, SignatureEntry};
pub use signer::{sign_bytes, sign_file, Signer};
pub use verifier::{verify_bytes, verify_file, SignatureResult, VerificationResult, Verifier};

