//! Cryptographic data types for VEFAS
//!
//! This module defines the data structures used across the cryptographic
//! trait system for type safety and consistent interfaces.

use alloc::vec::Vec;

use core::mem::size_of;
use serde::{Deserialize, Serialize};
use vefas_types::{errors::CryptoErrorType, VefasError, VefasResult};

/// Hash output (typically SHA-256)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashOutput {
    /// Hash bytes
    bytes: Vec<u8>,
}

impl HashOutput {
    /// Create a new hash output
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the hash bytes as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the hash bytes as a vector
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Get the length of the hash
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the hash is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Validate that this is a valid SHA-256 hash
    pub fn validate_sha256(&self) -> VefasResult<()> {
        if self.bytes.len() != 32 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::HashFailed,
                "invalid SHA-256 hash length",
            ));
        }
        Ok(())
    }
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for HashOutput {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<[u8; 32]> for HashOutput {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes.to_vec())
    }
}

/// ECDSA signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdsaSignature {
    /// Signature bytes (DER-encoded)
    bytes: Vec<u8>,
}

impl EcdsaSignature {
    /// Create a new ECDSA signature
    pub fn new(bytes: Vec<u8>) -> VefasResult<Self> {
        if bytes.is_empty() {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidSignature,
                "signature cannot be empty",
            ));
        }

        // Basic DER format validation
        if bytes.len() < 8 || bytes[0] != 0x30 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidSignature,
                "invalid DER signature format",
            ));
        }

        Ok(Self { bytes })
    }

    /// Create an ECDSA signature without validation (unsafe)
    pub fn new_unchecked(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the signature bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the signature bytes as a vector
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Get the length of the signature
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the signature is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Validate DER encoding format
    pub fn validate_der(&self) -> VefasResult<()> {
        if self.bytes.len() < 8 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidSignature,
                "signature too short",
            ));
        }

        if self.bytes[0] != 0x30 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidSignature,
                "invalid DER sequence tag",
            ));
        }

        // Further DER validation would go here
        Ok(())
    }
}

impl AsRef<[u8]> for EcdsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<Vec<u8>> for EcdsaSignature {
    type Error = VefasError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

/// Public key for ECDSA verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    /// Public key bytes (uncompressed format: 0x04 || x || y)
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Create a new public key
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create a P-256 public key with validation
    pub fn new_p256(bytes: Vec<u8>) -> VefasResult<Self> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidEcPoint,
                "invalid P-256 public key format",
            ));
        }
        Ok(Self { bytes })
    }

    /// Create a secp256k1 public key with validation
    pub fn new_secp256k1(bytes: Vec<u8>) -> VefasResult<Self> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidEcPoint,
                "invalid secp256k1 public key format",
            ));
        }
        Ok(Self { bytes })
    }

    /// Get the public key bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the public key bytes as a vector
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Get the length of the public key
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the public key is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Check if this is an uncompressed public key
    pub fn is_uncompressed(&self) -> bool {
        !self.bytes.is_empty() && self.bytes[0] == 0x04
    }

    /// Get the x coordinate for uncompressed keys
    pub fn x_coordinate(&self) -> VefasResult<&[u8]> {
        if !self.is_uncompressed() || self.bytes.len() != 65 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidEcPoint,
                "not a valid uncompressed public key",
            ));
        }
        Ok(&self.bytes[1..33])
    }

    /// Get the y coordinate for uncompressed keys
    pub fn y_coordinate(&self) -> VefasResult<&[u8]> {
        if !self.is_uncompressed() || self.bytes.len() != 65 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidEcPoint,
                "not a valid uncompressed public key",
            ));
        }
        Ok(&self.bytes[33..65])
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for PublicKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

/// Private key for ECDSA signing (when needed)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKey {
    /// Private key bytes
    bytes: Vec<u8>,
}

impl PrivateKey {
    /// Create a new private key
    pub fn new(bytes: Vec<u8>) -> VefasResult<Self> {
        if bytes.is_empty() {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidKeyLength,
                "private key cannot be empty",
            ));
        }

        if bytes.len() != 32 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidKeyLength,
                "invalid private key length",
            ));
        }

        Ok(Self { bytes })
    }

    /// Create a private key without validation (unsafe)
    pub fn new_unchecked(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the private key bytes (be careful with this!)
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the private key
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the private key is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Zero out the private key bytes (for secure cleanup)
    pub fn zeroize(&mut self) {
        self.bytes.fill(0);
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// AEAD encryption key
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadKey {
    /// Key bytes
    bytes: Vec<u8>,
}

impl AeadKey {
    /// Create a new AEAD key
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create an AES-128 key with validation
    pub fn new_aes128(bytes: Vec<u8>) -> VefasResult<Self> {
        if bytes.len() != 16 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidKeyLength,
                "AES-128 key must be 16 bytes",
            ));
        }
        Ok(Self { bytes })
    }

    /// Create an AES-256 key with validation
    pub fn new_aes256(bytes: Vec<u8>) -> VefasResult<Self> {
        if bytes.len() != 32 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidKeyLength,
                "AES-256 key must be 32 bytes",
            ));
        }
        Ok(Self { bytes })
    }

    /// Create a ChaCha20 key with validation
    pub fn new_chacha20(bytes: Vec<u8>) -> VefasResult<Self> {
        if bytes.len() != 32 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidKeyLength,
                "ChaCha20 key must be 32 bytes",
            ));
        }
        Ok(Self { bytes })
    }

    /// Get the key bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the key bytes as a vector
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Get the length of the key
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the key is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Check if this is a valid AES key
    pub fn is_aes_key(&self) -> bool {
        matches!(self.bytes.len(), 16 | 32)
    }

    /// Check if this is a valid ChaCha20 key
    pub fn is_chacha20_key(&self) -> bool {
        self.bytes.len() == 32
    }
}

impl AsRef<[u8]> for AeadKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for AeadKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

/// AEAD nonce/IV
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadNonce {
    /// Nonce bytes
    bytes: Vec<u8>,
}

impl AeadNonce {
    /// Create a new AEAD nonce
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create an AES-GCM nonce with validation
    pub fn new_aes_gcm(bytes: Vec<u8>) -> VefasResult<Self> {
        if bytes.len() != 12 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidNonceLength,
                "AES-GCM nonce must be 12 bytes",
            ));
        }
        Ok(Self { bytes })
    }

    /// Create a ChaCha20Poly1305 nonce with validation
    pub fn new_chacha20_poly1305(bytes: Vec<u8>) -> VefasResult<Self> {
        if bytes.len() != 12 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::InvalidNonceLength,
                "ChaCha20Poly1305 nonce must be 12 bytes",
            ));
        }
        Ok(Self { bytes })
    }

    /// Get the nonce bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the nonce bytes as a vector
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Get the length of the nonce
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the nonce is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for AeadNonce {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for AeadNonce {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

/// HKDF salt
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HkdfSalt {
    /// Salt bytes
    bytes: Vec<u8>,
}

impl HkdfSalt {
    /// Create a new HKDF salt
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create an empty salt
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Get the salt bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the salt bytes as a vector
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Get the length of the salt
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the salt is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for HkdfSalt {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for HkdfSalt {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

/// HKDF info parameter
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HkdfInfo {
    /// Info bytes
    bytes: Vec<u8>,
}

impl HkdfInfo {
    /// Create a new HKDF info
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create empty info
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Get the info bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the info bytes as a vector
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Get the length of the info
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the info is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for HkdfInfo {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for HkdfInfo {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

/// Certificate chain for validation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateChain {
    /// Certificates in chain order (leaf first)
    pub certificates: Vec<Vec<u8>>,
}

impl CertificateChain {
    /// Create a new certificate chain
    pub fn new(certificates: Vec<Vec<u8>>) -> VefasResult<Self> {
        if certificates.is_empty() {
            return Err(VefasError::certificate_error(
                vefas_types::errors::CertificateErrorType::InvalidFormat,
                "certificate chain cannot be empty",
            ));
        }

        if certificates.len() > crate::constants::MAX_CERT_CHAIN_LEN {
            return Err(VefasError::certificate_error(
                vefas_types::errors::CertificateErrorType::ChainTooLong,
                "certificate chain too long",
            ));
        }

        // Validate each certificate size
        for cert in &certificates {
            if cert.len() > crate::constants::MAX_CERT_SIZE {
                return Err(VefasError::certificate_error(
                    vefas_types::errors::CertificateErrorType::InvalidFormat,
                    "certificate too large",
                ));
            }
        }

        Ok(Self { certificates })
    }

    /// Get the leaf certificate (first in chain)
    pub fn leaf_certificate(&self) -> &[u8] {
        &self.certificates[0]
    }

    /// Get the intermediate certificates
    pub fn intermediate_certificates(&self) -> &[Vec<u8>] {
        if self.certificates.len() > 1 {
            &self.certificates[1..]
        } else {
            &[]
        }
    }

    /// Get the number of certificates in the chain
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Calculate total memory footprint
    pub fn memory_footprint(&self) -> usize {
        self.certificates
            .iter()
            .map(|cert| cert.len())
            .sum::<usize>()
            + size_of::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_hash_output() {
        let hash = HashOutput::new(vec![0u8; 32]);
        assert_eq!(hash.len(), 32);
        assert!(!hash.is_empty());
        assert!(hash.validate_sha256().is_ok());

        let invalid_hash = HashOutput::new(vec![0u8; 16]);
        assert!(invalid_hash.validate_sha256().is_err());
    }

    #[test]
    fn test_ecdsa_signature() {
        // Valid DER signature (proper ECDSA signature structure)
        let sig_bytes = vec![
            0x30, 0x44, // SEQUENCE, length 68
            0x02, 0x20, // INTEGER, length 32 (r)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20, 0x02, 0x20, // INTEGER, length 32 (s)
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
            0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
            0x3d, 0x3e, 0x3f, 0x40,
        ];
        let sig = EcdsaSignature::new(sig_bytes).unwrap();
        assert!(sig.validate_der().is_ok());

        // Invalid signature
        let invalid_sig = EcdsaSignature::new(vec![]);
        assert!(invalid_sig.is_err());
    }

    #[test]
    fn test_public_key() {
        // Valid uncompressed P-256 key
        let mut key_bytes = vec![0x04];
        key_bytes.extend_from_slice(&[0u8; 64]);
        let pk = PublicKey::new_p256(key_bytes).unwrap();
        assert!(pk.is_uncompressed());
        assert!(pk.x_coordinate().is_ok());
        assert!(pk.y_coordinate().is_ok());

        // Invalid key
        let invalid_pk = PublicKey::new_p256(vec![0x02; 33]);
        assert!(invalid_pk.is_err());
    }

    #[test]
    fn test_private_key() {
        let mut pk = PrivateKey::new(vec![1u8; 32]).unwrap();
        assert_eq!(pk.len(), 32);
        pk.zeroize();
        assert_eq!(pk.as_slice(), &[0u8; 32]);

        let invalid_pk = PrivateKey::new(vec![1u8; 16]);
        assert!(invalid_pk.is_err());
    }

    #[test]
    fn test_aead_key() {
        let aes128_key = AeadKey::new_aes128(vec![0u8; 16]).unwrap();
        assert!(aes128_key.is_aes_key());
        assert!(!aes128_key.is_chacha20_key());

        let chacha20_key = AeadKey::new_chacha20(vec![0u8; 32]).unwrap();
        assert!(chacha20_key.is_chacha20_key());
        assert!(chacha20_key.is_aes_key()); // 32 bytes is valid for AES-256

        let invalid_key = AeadKey::new_aes128(vec![0u8; 32]);
        assert!(invalid_key.is_err());
    }

    #[test]
    fn test_aead_nonce() {
        let nonce = AeadNonce::new_aes_gcm(vec![0u8; 12]).unwrap();
        assert_eq!(nonce.len(), 12);

        let invalid_nonce = AeadNonce::new_aes_gcm(vec![0u8; 16]);
        assert!(invalid_nonce.is_err());
    }

    #[test]
    fn test_certificate_chain() {
        let chain = CertificateChain::new(vec![vec![0u8; 100], vec![0u8; 200]]).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.leaf_certificate().len(), 100);
        assert_eq!(chain.intermediate_certificates().len(), 1);

        let empty_chain = CertificateChain::new(vec![]);
        assert!(empty_chain.is_err());
    }

    #[test]
    fn test_hkdf_types() {
        let salt = HkdfSalt::new(vec![1, 2, 3]);
        assert!(!salt.is_empty());

        let empty_salt = HkdfSalt::empty();
        assert!(empty_salt.is_empty());

        let info = HkdfInfo::new(b"test info".to_vec());
        assert_eq!(info.len(), 9);
    }
}
