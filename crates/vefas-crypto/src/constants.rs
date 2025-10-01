//! Constants for VEFAS cryptographic operations
//!
//! This module defines various limits and constants used throughout
//! the cryptographic system for validation and security.

/// Maximum certificate chain length (reasonable for TLS)
pub const MAX_CERT_CHAIN_LEN: usize = 10;

/// Maximum individual certificate size (2MB)
pub const MAX_CERT_SIZE: usize = 2 * 1024 * 1024;

/// Maximum HKDF output length (RFC 5869 limit for SHA-256)
pub const MAX_HKDF_OUTPUT_LEN: usize = 255 * 32; // 8160 bytes

/// Standard TLS 1.3 key sizes
pub const TLS13_KEY_SIZE: usize = 32;
pub const TLS13_IV_SIZE: usize = 12;
pub const TLS13_TAG_SIZE: usize = 16;

/// Standard hash output sizes
pub const SHA256_OUTPUT_SIZE: usize = 32;
pub const SHA384_OUTPUT_SIZE: usize = 48;
pub const SHA512_OUTPUT_SIZE: usize = 64;

/// Standard key sizes for symmetric algorithms
pub const AES128_KEY_SIZE: usize = 16;
pub const AES256_KEY_SIZE: usize = 32;
pub const CHACHA20_KEY_SIZE: usize = 32;

/// Standard nonce/IV sizes
pub const AES_GCM_NONCE_SIZE: usize = 12;
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// ECDSA key and signature sizes
pub const P256_PRIVATE_KEY_SIZE: usize = 32;
pub const P256_PUBLIC_KEY_SIZE: usize = 65; // Uncompressed
pub const P256_COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;
pub const SECP256K1_PRIVATE_KEY_SIZE: usize = 32;
pub const SECP256K1_PUBLIC_KEY_SIZE: usize = 65; // Uncompressed
pub const MAX_ECDSA_SIGNATURE_SIZE: usize = 72; // DER-encoded

/// Ed25519 key and signature sizes
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// X25519 key sizes
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// RSA key sizes (in bytes)
pub const RSA_2048_KEY_SIZE: usize = 256;
pub const RSA_3072_KEY_SIZE: usize = 384;
pub const RSA_4096_KEY_SIZE: usize = 512;

/// Maximum signature sizes for various algorithms
pub const MAX_RSA_SIGNATURE_SIZE: usize = RSA_4096_KEY_SIZE;
pub const MAX_SIGNATURE_SIZE: usize = MAX_RSA_SIGNATURE_SIZE;

/// TLS 1.3 specific constants
pub const TLS13_LABEL_PREFIX: &[u8] = b"tls13 ";
pub const TLS13_MAX_LABEL_SIZE: usize = 255;

/// zkVM specific limits
pub const MAX_ZKVM_MEMORY: usize = 32 * 1024 * 1024; // 32MB
pub const MAX_ZKVM_CYCLES: u64 = 100_000_000; // 100M cycles

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_size_constants() {
        assert_eq!(AES128_KEY_SIZE, 16);
        assert_eq!(AES256_KEY_SIZE, 32);
        assert_eq!(CHACHA20_KEY_SIZE, 32);
        assert_eq!(P256_PRIVATE_KEY_SIZE, 32);
        assert_eq!(ED25519_SIGNATURE_SIZE, 64);
    }

    #[test]
    fn test_hash_size_constants() {
        assert_eq!(SHA256_OUTPUT_SIZE, 32);
        assert_eq!(SHA384_OUTPUT_SIZE, 48);
        assert_eq!(SHA512_OUTPUT_SIZE, 64);
    }

    #[test]
    fn test_tls13_constants() {
        assert_eq!(TLS13_KEY_SIZE, 32);
        assert_eq!(TLS13_IV_SIZE, 12);
        assert_eq!(TLS13_TAG_SIZE, 16);
        assert_eq!(TLS13_LABEL_PREFIX, b"tls13 ");
    }

    #[test]
    fn test_limits() {
        assert!(MAX_CERT_CHAIN_LEN > 0);
        assert!(MAX_CERT_SIZE > 1024);
        assert!(MAX_HKDF_OUTPUT_LEN > 1000);
        assert!(MAX_ZKVM_MEMORY > 1024 * 1024);
    }
}
