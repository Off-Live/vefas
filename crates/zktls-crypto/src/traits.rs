//! Platform-agnostic cryptographic traits for zkTLS
//!
//! This module defines the core cryptographic interfaces that enable
//! cross-platform support between SP1 and RISC0 zkVMs while maintaining
//! compatibility with standard Rust environments.
//!
//! # Design Principles
//!
//! 1. **Precompile Awareness**: Traits support detection of zkVM precompiles
//! 2. **Cross-Platform**: Identical API across SP1, RISC0, and standard environments
//! 3. **TLS 1.3 Focus**: Optimized for X25519 + AES-GCM + SHA-256 + ECDSA(P-256)
//! 4. **Production Quality**: Zero unsafe code, comprehensive error handling
//! 5. **RFC 8446 Compliance**: Full TLS 1.3 cryptographic requirements
//!
//! # Example Usage
//!
//! ```rust
//! use zktls_crypto::traits::{Hash, Aead};
//! use zktls_crypto::native::NativeCryptoProvider;
//!
//! let provider = NativeCryptoProvider::new();
//! let digest = provider.sha256(b"hello world");
//!
//! let key = &[0u8; 32];
//! let nonce = &[0u8; 12];
//! let ciphertext = provider.encrypt(key, nonce, b"aad", b"plaintext")?;
//! # Ok::<(), zktls_crypto::error::CryptoError>(())
//! ```

use crate::error::CryptoResult;

#[cfg(feature = "no_std")]
use alloc::vec::Vec;

/// Cryptographic hash functions with zkVM precompile support
///
/// Provides SHA-256 and SHA-384 hashing with automatic precompile detection
/// and fallback implementations for maximum performance and compatibility.
pub trait Hash {
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
    /// use zktls_crypto::traits::Hash;
    /// use zktls_crypto::native::NativeCryptoProvider;
    ///
    /// let provider = NativeCryptoProvider::new();
    /// let digest = provider.sha256(b"hello world");
    /// assert_eq!(digest.len(), 32);
    /// ```
    fn sha256(&self, input: &[u8]) -> [u8; 32];
    
    /// Compute SHA-384 hash of input data
    ///
    /// # Arguments
    /// * `input` - The data to hash
    ///
    /// # Returns
    /// 48-byte SHA-384 digest
    fn sha384(&self, input: &[u8]) -> [u8; 48];
    
    /// Check if zkVM precompile support is available
    ///
    /// Returns `true` if running in SP1 or RISC0 with hash precompiles enabled,
    /// `false` for standard Rust environments using software implementations.
    fn has_precompile_support(&self) -> bool;
}

/// Authenticated Encryption with Associated Data (AEAD)
///
/// Provides AES-GCM encryption/decryption with zkVM precompile optimization.
/// Supports both AES-128-GCM and AES-256-GCM variants used in TLS 1.3.
pub trait Aead {
    /// Encrypt plaintext with AES-GCM
    ///
    /// # Arguments
    /// * `key` - Encryption key (16 or 32 bytes for AES-128/256)
    /// * `nonce` - 12-byte nonce/IV (must be unique per key)
    /// * `aad` - Additional authenticated data (not encrypted)
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    /// Ciphertext with 16-byte authentication tag appended
    ///
    /// # Errors
    /// * `InvalidKeySize` - Key is not 16 or 32 bytes
    /// * `InvalidNonceSize` - Nonce is not exactly 12 bytes
    ///
    /// # Example
    /// ```rust
    /// use zktls_crypto::traits::Aead;
    /// use zktls_crypto::native::NativeCryptoProvider;
    ///
    /// let provider = NativeCryptoProvider::new();
    /// let key = &[0u8; 32]; // AES-256 key
    /// let nonce = &[0u8; 12];
    /// let ciphertext = provider.encrypt(key, nonce, b"aad", b"plaintext")?;
    /// # Ok::<(), zktls_crypto::error::CryptoError>(())
    /// ```
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CryptoResult<Vec<u8>>;
    
    /// Decrypt ciphertext with AES-GCM
    ///
    /// # Arguments
    /// * `key` - Decryption key (16 or 32 bytes)
    /// * `nonce` - 12-byte nonce/IV (same as used for encryption)
    /// * `aad` - Additional authenticated data (same as used for encryption)
    /// * `ciphertext` - Encrypted data with authentication tag
    ///
    /// # Returns
    /// Decrypted plaintext
    ///
    /// # Errors
    /// * `InvalidKeySize` - Key is not 16 or 32 bytes
    /// * `InvalidNonceSize` - Nonce is not exactly 12 bytes  
    /// * `DecryptionFailed` - Authentication tag verification failed
    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> CryptoResult<Vec<u8>>;
    
    /// Check if zkVM precompile support is available for AES-GCM
    fn has_precompile_support(&self) -> bool;
}

/// Elliptic Curve Diffie-Hellman key exchange
///
/// Supports X25519 and P-256 ECDH for TLS 1.3 key agreement.
/// Provides both key generation and Diffie-Hellman computation.
pub trait KeyExchange {
    /// Generate X25519 keypair
    ///
    /// # Returns
    /// Tuple of (private_key, public_key) where both are 32 bytes
    ///
    /// # Errors
    /// * `KeyGenerationFailed` - RNG failure or other key generation error
    fn x25519_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)>;
    
    /// Compute X25519 Diffie-Hellman shared secret
    ///
    /// # Arguments
    /// * `private_key` - Local private key (32 bytes)
    /// * `peer_public_key` - Peer's public key (32 bytes)
    ///
    /// # Returns
    /// 32-byte shared secret
    ///
    /// # Errors
    /// * `InvalidPrivateKey` - Private key format invalid
    /// * `InvalidPublicKey` - Public key format invalid or not on curve
    fn x25519_diffie_hellman(
        &self,
        private_key: &[u8],
        peer_public_key: &[u8],
    ) -> CryptoResult<Vec<u8>>;
    
    /// Generate P-256 keypair
    ///
    /// # Returns
    /// Tuple of (private_key, public_key) where private key is 32 bytes
    /// and public key is 64 bytes (uncompressed format)
    fn p256_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)>;
    
    /// Compute P-256 ECDH shared secret
    ///
    /// # Arguments
    /// * `private_key` - Local private key (32 bytes)
    /// * `peer_public_key` - Peer's public key (64 bytes uncompressed)
    ///
    /// # Returns
    /// 32-byte shared secret (x-coordinate of ECDH point)
    fn p256_diffie_hellman(
        &self,
        private_key: &[u8],
        peer_public_key: &[u8],
    ) -> CryptoResult<Vec<u8>>;
    
    /// Check if zkVM precompile support is available for elliptic curves
    fn has_precompile_support(&self) -> bool;
}

/// Digital signature algorithms
///
/// Supports ECDSA with P-256, Ed25519, and RSA signatures for TLS certificate
/// verification and authentication. Optimized for zkVM precompile usage.
pub trait Signature {
    /// Generate P-256 keypair for ECDSA
    ///
    /// # Returns
    /// Tuple of (private_key, public_key) where private key is 32 bytes
    /// and public key is 64 bytes (uncompressed format)
    fn p256_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)>;
    
    /// Sign message with ECDSA P-256
    ///
    /// # Arguments
    /// * `private_key` - Signing private key (32 bytes)
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// ASN.1 DER encoded signature
    fn p256_sign(&self, private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>>;
    
    /// Verify ECDSA P-256 signature
    ///
    /// # Arguments
    /// * `public_key` - Verification public key (64 bytes uncompressed)
    /// * `message` - Original message that was signed
    /// * `signature` - ASN.1 DER encoded signature
    ///
    /// # Returns
    /// `true` if signature is valid, `false` otherwise
    fn p256_verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool>;
    
    /// Verify ECDSA P-256 signature against pre-hashed data
    ///
    /// This function verifies signatures created over pre-computed hashes,
    /// which is the standard for X.509 certificate verification where
    /// signatures are created over the hash of TBS certificate data.
    ///
    /// # Arguments
    /// * `public_key` - Verification public key (65-byte uncompressed or 33-byte compressed)
    /// * `hash` - Pre-computed hash (typically SHA-256, 32 bytes)
    /// * `signature` - ASN.1 DER encoded signature or raw 64-byte (r || s)
    ///
    /// # Returns
    /// `true` if signature is valid, `false` otherwise
    ///
    /// # Security
    /// This function does NOT hash the input data. It expects the hash to be
    /// pre-computed. Use this for X.509 certificate verification where
    /// signatures are created over hashed TBS certificate data.
    fn p256_verify_prehashed(
        &self,
        public_key: &[u8],
        hash: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool>;
    
    /// Generate Ed25519 keypair
    ///
    /// # Returns
    /// Tuple of (private_key, public_key) where both are 32 bytes
    fn ed25519_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)>;
    
    /// Sign message with Ed25519
    ///
    /// # Arguments
    /// * `private_key` - Signing private key (32 bytes)
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// 64-byte signature
    fn ed25519_sign(&self, private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>>;
    
    /// Verify Ed25519 signature
    ///
    /// # Arguments
    /// * `public_key` - Verification public key (32 bytes)
    /// * `message` - Original message that was signed
    /// * `signature` - 64-byte signature
    ///
    /// # Returns
    /// `true` if signature is valid, `false` otherwise
    fn ed25519_verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool>;
    
    /// Verify RSA signature (for legacy certificate support)
    ///
    /// # Arguments
    /// * `public_key` - RSA public key in DER format
    /// * `message` - Original message that was signed
    /// * `signature` - RSA signature bytes
    /// * `hash_algorithm` - Hash algorithm used (e.g., "sha256")
    ///
    /// # Returns
    /// `true` if signature is valid, `false` otherwise
    ///
    /// # Note
    /// This is primarily for X.509 certificate chain validation.
    /// New applications should prefer ECDSA or Ed25519.
    fn rsa_verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        hash_algorithm: &str,
    ) -> CryptoResult<bool>;
    
    /// Check if zkVM precompile support is available for signatures
    fn has_precompile_support(&self) -> bool;
}

/// Trait for objects that can detect zkVM precompile availability
///
/// This trait provides a common interface for querying whether
/// cryptographic operations will use zkVM precompiles or fallback
/// to software implementations.
pub trait PrecompileDetection {
    /// Check if any precompiles are available in the current environment
    fn has_any_precompiles(&self) -> bool;
    
    /// Get the name of the zkVM platform if running in one
    ///
    /// Returns `Some("sp1")`, `Some("risc0")`, or `None` for standard environments
    fn platform_name(&self) -> Option<&'static str>;
}

/// Key Derivation Functions
///
/// Provides HKDF (HMAC-based Key Derivation Function) implementations
/// following RFC 5869 for TLS 1.3 key schedule operations.
/// Supports both SHA-256 and SHA-384 hash functions.
pub trait Kdf {
    /// HKDF-Extract using SHA-256
    ///
    /// Extracts a pseudorandom key (PRK) from input keying material (IKM).
    /// This is the first phase of HKDF as defined in RFC 5869 Section 2.2.
    ///
    /// # Arguments
    /// * `salt` - Optional salt value (use empty slice if no salt)
    /// * `ikm` - Input keying material
    ///
    /// # Returns
    /// 32-byte pseudorandom key (PRK)
    ///
    /// # Example
    /// ```rust
    /// use zktls_crypto::traits::Kdf;
    /// use zktls_crypto::native::NativeCryptoProvider;
    ///
    /// let provider = NativeCryptoProvider::new();
    /// let prk = provider.hkdf_extract_sha256(&[0u8; 16], &[0xabu8; 22])?;
    /// assert_eq!(prk.len(), 32);
    /// # Ok::<(), zktls_crypto::error::CryptoError>(())
    /// ```
    fn hkdf_extract_sha256(&self, salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>>;

    /// HKDF-Extract using SHA-384
    ///
    /// Extracts a pseudorandom key (PRK) from input keying material (IKM).
    /// This is the first phase of HKDF as defined in RFC 5869 Section 2.2.
    ///
    /// # Arguments
    /// * `salt` - Optional salt value (use empty slice if no salt)
    /// * `ikm` - Input keying material
    ///
    /// # Returns
    /// 48-byte pseudorandom key (PRK)
    fn hkdf_extract_sha384(&self, salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>>;

    /// HKDF-Expand using SHA-256
    ///
    /// Expands a pseudorandom key (PRK) into output keying material (OKM).
    /// This is the second phase of HKDF as defined in RFC 5869 Section 2.3.
    ///
    /// # Arguments
    /// * `prk` - Pseudorandom key from HKDF-Extract (must be 32 bytes for SHA-256)
    /// * `info` - Optional context and application specific information
    /// * `length` - Length of output keying material (max 255 * 32 = 8160 bytes)
    ///
    /// # Returns
    /// Output keying material of requested length
    ///
    /// # Errors
    /// * `InvalidHkdfOutputLength` - Requested length exceeds RFC 5869 limits
    /// * `InvalidHkdfPrk` - PRK is too short for the hash function
    ///
    /// # Example
    /// ```rust
    /// use zktls_crypto::traits::Kdf;
    /// use zktls_crypto::native::NativeCryptoProvider;
    ///
    /// let provider = NativeCryptoProvider::new();
    /// let prk = provider.hkdf_extract_sha256(&[0u8; 16], &[0xabu8; 22])?;
    /// let okm = provider.hkdf_expand_sha256(&prk, b"info", 42)?;
    /// assert_eq!(okm.len(), 42);
    /// # Ok::<(), zktls_crypto::error::CryptoError>(())
    /// ```
    fn hkdf_expand_sha256(&self, prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>>;

    /// HKDF-Expand using SHA-384
    ///
    /// Expands a pseudorandom key (PRK) into output keying material (OKM).
    /// This is the second phase of HKDF as defined in RFC 5869 Section 2.3.
    ///
    /// # Arguments
    /// * `prk` - Pseudorandom key from HKDF-Extract (must be 48 bytes for SHA-384)
    /// * `info` - Optional context and application specific information
    /// * `length` - Length of output keying material (max 255 * 48 = 12240 bytes)
    ///
    /// # Returns
    /// Output keying material of requested length
    ///
    /// # Errors
    /// * `InvalidHkdfOutputLength` - Requested length exceeds RFC 5869 limits
    /// * `InvalidHkdfPrk` - PRK is too short for the hash function
    fn hkdf_expand_sha384(&self, prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>>;

    /// Check if zkVM precompile support is available for HKDF operations
    ///
    /// Note: Most zkVMs don't have dedicated HKDF precompiles, but may optimize
    /// the underlying SHA-256/SHA-384 and HMAC operations used by HKDF.
    fn has_precompile_support(&self) -> bool;
}

/// Convenience trait for creating cryptographic providers
///
/// This trait allows for easy instantiation of crypto providers
/// with automatic platform detection and optimization.
pub trait CryptoProvider: Hash + Aead + KeyExchange + Signature + Kdf + PrecompileDetection + Clone {
    /// Create a new crypto provider instance
    ///
    /// Automatically detects the current environment and enables
    /// appropriate optimizations (precompiles vs. software fallback).
    fn new() -> Self;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traits_compile() {
        // This test ensures all trait definitions compile correctly
        // The actual implementations will be tested in the integration tests
        
        // Test that error types work correctly
        use crate::error::CryptoError;
        let _error = CryptoError::InvalidKeySize(15);
        let _result: CryptoResult<()> = Ok(());
    }
}