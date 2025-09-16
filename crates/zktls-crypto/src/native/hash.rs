//! Native hash implementations using the sha2 crate
//!
//! This module provides SHA-256 and SHA-384 implementations using the well-tested
//! `sha2` crate. These implementations are used as fallbacks when zkVM precompiles
//! are not available and serve as the baseline for performance comparisons.
//!
//! # Security
//!
//! All implementations use constant-time algorithms from the `sha2` crate which
//! has been extensively audited and is used throughout the Rust cryptographic
//! ecosystem.
//!
//! # Performance
//!
//! These implementations are optimized for general-purpose use and provide
//! excellent performance on standard hardware. They automatically benefit from
//! hardware acceleration (e.g., Intel SHA extensions) when available.

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
/// use zktls_crypto::native::hash::sha256;
/// 
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
/// use zktls_crypto::native::hash::sha384;
/// 
/// let digest = sha384(b"hello world");
/// assert_eq!(digest.len(), 48);
/// ```
pub fn sha384(input: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    
    #[cfg(feature = "no_std")]
    use alloc::vec;

    #[test]
    fn test_sha256_basic() {
        let result = sha256(b"test");
        // Verify it produces a 32-byte output
        assert_eq!(result.len(), 32);
        
        // Known test vector
        let expected = hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_sha384_basic() {
        let result = sha384(b"test");
        // Verify it produces a 48-byte output
        assert_eq!(result.len(), 48);
        
        // Known test vector
        let expected = hex!(
            "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9"
        );
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_empty_input() {
        let sha256_result = sha256(&[]);
        let sha384_result = sha384(&[]);
        
        // Verify correct lengths
        assert_eq!(sha256_result.len(), 32);
        assert_eq!(sha384_result.len(), 48);
        
        // Verify against known empty string hashes
        let expected_sha256 = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let expected_sha384 = hex!(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        
        assert_eq!(sha256_result, expected_sha256);
        assert_eq!(sha384_result, expected_sha384);
    }
    
    #[test]
    fn test_deterministic() {
        let input = b"deterministic test";
        
        // Multiple calls should produce identical results
        assert_eq!(sha256(input), sha256(input));
        assert_eq!(sha384(input), sha384(input));
    }
    
    #[test]
    fn test_large_input() {
        // Test with large input to ensure proper handling
        let large_input = vec![0u8; 10000];
        
        let result256 = sha256(&large_input);
        let result384 = sha384(&large_input);
        
        assert_eq!(result256.len(), 32);
        assert_eq!(result384.len(), 48);
        
        // Results should be deterministic
        assert_eq!(result256, sha256(&large_input));
        assert_eq!(result384, sha384(&large_input));
    }
}