//! Cryptographic types and test vectors
//!
//! This module contains all cryptographic-related types including
//! test vectors, operation types, and crypto-specific structures.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Individual cryptographic operation test vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoTestVector {
    /// Test case name
    pub name: &'static str,
    /// Operation type
    pub operation: CryptoOperation,
}

/// Cryptographic operation types with test vectors  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoOperation {
    /// HKDF-SHA256 key derivation
    HkdfSha256 {
        /// Input key material
        ikm: &'static [u8],
        /// Salt value
        salt: &'static [u8],
        /// Info context
        info: &'static [u8],
        /// Output key material
        okm: &'static [u8],
    },
    /// AES-128-GCM encryption/decryption
    Aes128Gcm {
        /// 128-bit key
        key: [u8; 16],
        /// 96-bit nonce
        nonce: [u8; 12],
        /// Additional authenticated data
        aad: &'static [u8],
        /// Plaintext
        plaintext: &'static [u8],
        /// Ciphertext
        ciphertext: &'static [u8],
        /// Authentication tag
        tag: [u8; 16],
    },
    /// ECDSA P-256 signature verification
    EcdsaP256 {
        /// Public key (uncompressed, 65 bytes)
        #[serde(with = "BigArray")]
        public_key: [u8; 65],
        /// Message hash (SHA-256, 32 bytes)
        message_hash: [u8; 32],
        /// Signature (r || s, 64 bytes)
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        /// Expected verification result
        valid: bool,
    },
    /// SHA-256 hash computation
    Sha256 {
        /// Input message
        message: &'static [u8],
        /// Expected hash output
        hash: [u8; 32],
    },
}
