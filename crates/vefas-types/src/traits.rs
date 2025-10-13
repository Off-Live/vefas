//! Trait definitions for VEFAS types
//!
//! This module defines core traits used throughout the VEFAS system,
//! particularly for cryptographic operations and platform abstraction.

use alloc::vec::Vec;

/// Trait for hash operations
///
/// This trait provides a platform-agnostic interface for cryptographic
/// hashing operations, allowing different implementations for different
/// environments (native, RISC0, SP1, etc.).
pub trait Hash {
    /// Compute SHA256 hash of the input data
    ///
    /// # Arguments
    /// * `data` - The input data to hash
    ///
    /// # Returns
    /// A vector containing the 32-byte SHA256 hash
    fn sha256(&self, data: &[u8]) -> Vec<u8>;
}

/// Trait for key derivation functions (KDF)
///
/// This trait provides a platform-agnostic interface for key derivation
/// operations used in TLS handshake processing.
pub trait Kdf {
    /// Derive a key using HKDF (RFC 5869)
    ///
    /// # Arguments
    /// * `secret` - The input key material
    /// * `salt` - The salt value
    /// * `info` - The info parameter
    /// * `length` - The desired output length
    ///
    /// # Returns
    /// A vector containing the derived key material
    fn hkdf_expand(&self, secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8>;
}

/// Trait for key exchange operations
///
/// This trait provides a platform-agnostic interface for key exchange
/// operations used in TLS handshake processing.
pub trait KeyExchange {
    /// Perform ECDH key exchange
    ///
    /// # Arguments
    /// * `private_key` - The private key
    /// * `public_key` - The peer's public key
    ///
    /// # Returns
    /// A vector containing the shared secret
    fn ecdh(&self, private_key: &[u8], public_key: &[u8]) -> Vec<u8>;
}
