//! Hash function implementations
//!
//! This module provides production-grade implementations of hash functions
//! including SHA-256, SHA-384, and HMAC-SHA256 using the RustCrypto `sha2` and `hmac` crates.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

type HmacSha256 = Hmac<Sha256>;

/// Compute SHA-256 hash
///
/// # Arguments
/// * `input` - Data to hash
///
/// # Returns
/// 32-byte SHA-256 hash
///
/// # Example
/// ```rust
/// use vefas_crypto_native::hash::sha256;
///
/// let hash = sha256(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Compute SHA-384 hash
///
/// # Arguments
/// * `input` - Data to hash
///
/// # Returns
/// 48-byte SHA-384 hash
///
/// # Example
/// ```rust
/// use vefas_crypto_native::hash::sha384;
///
/// let hash = sha384(b"hello world");
/// assert_eq!(hash.len(), 48);
/// ```
pub fn sha384(input: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Compute HMAC-SHA256
///
/// # Arguments
/// * `key` - HMAC key
/// * `data` - Data to authenticate
///
/// # Returns
/// 32-byte HMAC-SHA256 output
///
/// # Example
/// ```rust
/// use vefas_crypto_native::hash::hmac_sha256;
///
/// let hmac = hmac_sha256(b"secret_key", b"hello world");
/// assert_eq!(hmac.len(), 32);
/// ```
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Compute HMAC-SHA384
///
/// # Arguments
/// * `key` - HMAC key
/// * `data` - Data to authenticate
///
/// # Returns
/// 48-byte HMAC-SHA384 output
///
/// # Example
/// ```rust
/// use vefas_crypto_native::hash::hmac_sha384;
///
/// let hmac = hmac_sha384(b"secret_key", b"hello world");
/// assert_eq!(hmac.len(), 48);
/// ```
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    type HmacSha384 = Hmac<Sha384>;
    let mut mac = HmacSha384::new_from_slice(key).expect("HMAC can take keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha384_empty() {
        let hash = sha384(b"");
        let expected = [
            0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1,
            0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf,
            0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a,
            0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha384_abc() {
        let hash = sha384(b"abc");
        let expected = [
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6,
            0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a,
            0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba,
            0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_test_case_1() {
        // RFC 4231 Test Case 1
        let key = [0x0b; 20];
        let data = b"Hi There";
        let hmac = hmac_sha256(&key, data);
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(hmac, expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_test_case_2() {
        // RFC 4231 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let hmac = hmac_sha256(key, data);
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(hmac, expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_test_case_6() {
        // RFC 4231 Test Case 6 (long key)
        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let hmac = hmac_sha256(&key, data);
        let expected = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ];
        assert_eq!(hmac, expected);
    }

    #[test]
    fn test_hash_lengths() {
        assert_eq!(sha256(b"test").len(), 32);
        assert_eq!(sha384(b"test").len(), 48);
        assert_eq!(hmac_sha256(b"key", b"data").len(), 32);
        assert_eq!(hmac_sha384(b"key", b"data").len(), 48);
    }

    #[test]
    fn test_hash_deterministic() {
        let input = b"deterministic test";
        let key = b"test key";

        // Multiple calls should produce identical results
        assert_eq!(sha256(input), sha256(input));
        assert_eq!(sha384(input), sha384(input));
        assert_eq!(hmac_sha256(key, input), hmac_sha256(key, input));
        assert_eq!(hmac_sha384(key, input), hmac_sha384(key, input));
    }

    #[test]
    fn test_hmac_sha384_rfc4231_test_case_1() {
        // RFC 4231 Test Case 1 (adapted for SHA-384)
        let key = [0x0b; 20];
        let data = b"Hi There";
        let hmac = hmac_sha384(&key, data);
        let expected = [
            0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46,
            0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6, 0x82, 0xaa, 0x03, 0x4c,
            0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1,
            0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6,
        ];
        assert_eq!(hmac, expected);
    }
}
