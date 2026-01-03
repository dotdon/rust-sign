# rust-sign

A Rust library for document signing using BLAKE3 hashing and Ed25519 digital signatures.

## Features

- **Fast & Secure Hashing**: Uses BLAKE3 for lightning-fast, cryptographically secure document fingerprinting
- **Ed25519 Signatures**: Modern, compact digital signatures (64 bytes)
- **Multi-Signature Support**: Multiple parties can sign the same document
- **JSON Output**: Human-readable signature format with timestamps and metadata
- **Streaming Support**: Efficiently sign large files without loading them entirely into memory
- **Key Management**: Generate, save, and load keypairs

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust-sign = "0.1.0"
```

## Quick Start

### Generate a Keypair

```rust
use rust_sign::KeyPair;

let keypair = KeyPair::generate();

// Optionally save to file
keypair.save_to_file("my_key.pem")?;

// Load later
let keypair = KeyPair::load_from_file("my_key.pem")?;
```

### Sign a Document

```rust
use rust_sign::{KeyPair, Signer};

let keypair = KeyPair::generate();
let document = b"Important document content";

let signature = Signer::new(&keypair)
    .with_signer_id("alice@example.com")
    .with_metadata("purpose", "contract")
    .sign_bytes(document)?;

// Save signature to file
signature.save("document.sig")?;

// Or get as JSON string
println!("{}", signature.to_json()?);
```

### Sign a File

```rust
use rust_sign::{KeyPair, Signer};

let keypair = KeyPair::generate();

let signature = Signer::new(&keypair)
    .with_signer_id("alice@example.com")
    .sign_file("document.pdf")?;

signature.save("document.pdf.sig")?;
```

### Verify a Signature

```rust
use rust_sign::{Verifier, DocumentSignature};

// Verify bytes
let result = Verifier::verify_bytes(document, &signature)?;

if result.all_valid {
    println!("All {} signatures verified!", result.valid_count());
    for signer in result.valid_signers() {
        println!("  Signed by: {:?}", signer);
    }
} else {
    println!("Verification failed!");
}

// Verify file against signature file
let result = Verifier::verify_file("document.pdf", "document.pdf.sig")?;
```

### Multiple Signatures

```rust
use rust_sign::{KeyPair, Signer, Verifier};

let alice = KeyPair::generate();
let bob = KeyPair::generate();
let document = b"Contract requiring multiple signatures";

// Alice signs first
let mut signature = Signer::new(&alice)
    .with_signer_id("alice@example.com")
    .sign_bytes(document)?;

// Bob co-signs
Signer::new(&bob)
    .with_signer_id("bob@example.com")
    .cosign(&mut signature)?;

// Verify all signatures
let result = Verifier::verify_bytes(document, &signature)?;
assert!(result.all_valid);
assert_eq!(result.valid_count(), 2);
```

## Signature Format

Signatures are stored as JSON:

```json
{
  "version": "1.0",
  "document_hash": "base64-encoded-blake3-hash",
  "signatures": [
    {
      "signer_id": "alice@example.com",
      "public_key": "base64-encoded-public-key",
      "signature": "base64-encoded-ed25519-signature",
      "timestamp": "2026-01-02T10:30:00Z",
      "metadata": {
        "purpose": "contract"
      }
    }
  ]
}
```

## Security Notes

- **Private Keys**: Keep your private key files secure. Anyone with access can sign documents as you.
- **BLAKE3**: Provides 256-bit security level, faster than SHA-256 while being just as secure.
- **Ed25519**: Well-audited, fast signature scheme. 64-byte signatures, 32-byte public keys.
- **Verification**: Always verify signatures before trusting document authenticity.

## API Reference

### Core Types

| Type | Description |
|------|-------------|
| `KeyPair` | Ed25519 signing keypair |
| `PublicKey` | Ed25519 public key for verification |
| `Signer` | Builder for creating signatures |
| `Verifier` | Signature verification utilities |
| `DocumentSignature` | Signed document container |
| `SignatureEntry` | Individual signature with metadata |
| `DocumentHash` | BLAKE3 hash wrapper |

### Error Handling

All operations return `Result<T, SignError>`. Error types include:

- `SignError::Io` - File I/O errors
- `SignError::Json` - JSON serialization errors
- `SignError::Signature` - Cryptographic signature errors
- `SignError::InvalidKey` - Invalid key format
- `SignError::HashMismatch` - Document was modified
- `SignError::NoSignatures` - No signatures in document

## License

MIT

