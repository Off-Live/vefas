//! # VEFAS Crypto Native
//!
//! Production-grade std-only cryptographic implementation for VEFAS (Verifiable Execution Framework for Agents).
//! This crate provides comprehensive implementations of all VEFAS cryptographic traits using high-performance
//! host-side cryptography libraries optimized for std environments.
//!
//! ## Purpose
//!
//! This crate serves as:
//! - **Host-side crypto provider** for VEFAS applications running outside zkVMs
//! - **Reference implementation** for VEFAS cryptographic operations
//! - **Development and testing provider** with full std library support
//! - **Performance baseline** using optimized crypto libraries like ring and OpenSSL
//!
//! ## Architecture
//!
//! ```text
//! NativeCryptoProvider (std-only)
//! ├── Hash (SHA-256/384, HMAC, BLAKE3) - using ring/openssl
//! ├── Aead (AES-GCM, ChaCha20Poly1305) - using ring/aesni
//! ├── KeyExchange (X25519, P-256 ECDH) - using ring/openssl
//! ├── Signature (ECDSA P-256/secp256k1, Ed25519, RSA) - using ring/openssl
//! ├── Kdf (HKDF, Argon2, TLS 1.3 key derivation) - using ring
//! └── VefasCrypto (provider metadata)
//! ```
//!
//! ## Features
//!
//! - **std-only Design**: Leverages full std library for maximum performance
//! - **Heavy Dependencies**: Uses ring, OpenSSL, and other optimized libraries
//! - **Hardware Acceleration**: Automatic use of AES-NI, AVX2, and other CPU features
//! - **Production Quality**: RFC-compliant implementations with proper error handling
//! - **Complete API**: Implements all VEFAS cryptographic traits fully
//! - **Memory Safe**: Uses `#![forbid(unsafe_code)]` in application code
//! - **Well Tested**: Comprehensive test suite with RFC test vectors
//! - **Threading Support**: Parallel crypto operations using rayon
//!
//! ## Example Usage
//!
//! ```rust
//! use vefas_crypto::traits::{Hash, Aead, VefasCrypto, KeyExchange};
//! use vefas_crypto_native::NativeCryptoProvider;
//!
//! let provider = NativeCryptoProvider::new();
//!
//! // Hash operations using hardware acceleration
//! let hash = provider.sha256(b"hello world");
//! assert_eq!(hash.len(), 32);
//!
//! // AEAD encryption with AES-NI
//! let key = [0u8; 32];
//! let nonce = [0u8; 12];
//! let ciphertext = provider.aes_256_gcm_encrypt(&key, &nonce, b"", b"plaintext")?;
//!
//! // Key generation with hardware RNG
//! let (private, public) = provider.x25519_generate_keypair();
//! # Ok::<(), vefas_types::VefasError>(())
//! ```

// This crate is std-only by design for maximum performance
#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![warn(missing_debug_implementations)]

// Re-export core dependencies for convenience
pub use vefas_crypto::traits;
pub use vefas_types;

// Internal modules
pub mod aead;
pub mod crypto_provider;
pub mod hash;
pub mod kdf;
pub mod key_exchange;
mod provider;
pub mod signature;
pub mod tls_utils;

// Public API
pub use provider::NativeCryptoProvider;
pub use crypto_provider::NativeCryptoProviderImpl;
pub use tls_utils::{compute_ecdhe_shared_secret, derive_aead_nonce, verify_session_keys};

// Convenience function
/// Create a new native crypto provider instance
///
/// This is the main entry point for creating a native cryptographic provider
/// that implements all VEFAS traits using standard Rust crypto libraries.
pub fn create_provider() -> NativeCryptoProvider {
    NativeCryptoProvider::new()
}
