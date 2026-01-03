//! Error types for the rust-sign library.

use thiserror::Error;

/// The main error type for rust-sign operations.
#[derive(Error, Debug)]
pub enum SignError {
    /// Error reading or writing files.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Error with JSON serialization/deserialization.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Error with base64 encoding/decoding.
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Error with Ed25519 signature operations.
    #[error("Signature error: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),

    /// Invalid key format or length.
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Signature verification failed.
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Document hash mismatch.
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// No signatures present in document.
    #[error("No signatures found in document")]
    NoSignatures,

    /// Invalid signature format or structure.
    #[error("Invalid signature format: {0}")]
    InvalidFormat(String),
}

/// Result type alias for rust-sign operations.
pub type Result<T> = std::result::Result<T, SignError>;

