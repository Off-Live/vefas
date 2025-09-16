//! Native hash functions for platform-agnostic cryptography
//!
//! This module provides standard hash implementations using the
//! `sha2` crate for maximum compatibility across platforms.

use sha2::{Digest, Sha256, Sha384};

/// Compute SHA-256 hash of input data
///
/// # Arguments
/// * `input` - The data to hash
///
/// # Returns
/// 32-byte SHA-256 digest
///
/// # Example
/// ```rust
/// use zktls_crypto::hash::sha256;
/// let digest = sha256(b"hello world");
/// assert_eq!(digest.len(), 32);
/// ```
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Compute SHA-384 hash of input data
///
/// # Arguments
/// * `input` - The data to hash
///
/// # Returns
/// 48-byte SHA-384 digest
///
/// # Example
/// ```rust
/// use zktls_crypto::hash::sha384;
/// let digest = sha384(b"hello world");
/// assert_eq!(digest.len(), 48);
/// ```
pub fn sha384(input: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(input);
    hasher.finalize().into()
}