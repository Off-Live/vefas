//! Native cryptographic implementations using standard Rust crypto libraries
//!
//! This module provides production-grade implementations of all cryptographic
//! operations required for zkTLS using battle-tested Rust crypto libraries.
//! These implementations serve as the baseline for performance comparisons
//! and provide fallbacks when zkVM precompiles are not available.
//!
//! # Features
//!
//! - **Hash**: SHA-256/384 using `sha2` crate
//! - **AEAD**: AES-GCM encryption/decryption using `aes-gcm` crate  
//! - **Key Exchange**: X25519 and P-256 ECDH using `x25519-dalek` and `p256` crates
//! - **Signatures**: P-256 ECDSA, Ed25519, and RSA using respective crates
//! - **Cross-platform**: Works in `no_std` environments with `alloc`
//! - **Deterministic**: Consistent behavior across platforms for zkVM compatibility
//!
//! # Example
//!
//! ```rust
//! use zktls_crypto::native::NativeCryptoProvider;
//! use zktls_crypto::traits::{Hash, CryptoProvider};
//!
//! let provider = NativeCryptoProvider::new();
//! let digest = provider.sha256(b"hello world");
//! assert_eq!(digest.len(), 32);
//! ```

pub mod hash;
pub mod aead;
pub mod ecdh;
pub mod ecdsa;
pub mod kdf;

use crate::traits::{Hash, Aead, KeyExchange, Signature, Kdf, PrecompileDetection, CryptoProvider};
use crate::error::CryptoResult;

#[cfg(feature = "no_std")]
use alloc::{vec, vec::Vec};

/// Native cryptographic provider using standard Rust crypto libraries
///
/// This implementation provides all cryptographic operations needed for zkTLS
/// using production-grade Rust crypto libraries. It serves as both a reference
/// implementation and fallback when zkVM precompiles are unavailable.
#[derive(Debug, Clone, Default)]
pub struct NativeCryptoProvider {
    _private: (), // Prevent direct construction, use `new()`
}

impl NativeCryptoProvider {
    /// Create a new native crypto provider instance
    ///
    /// # Example
    /// ```rust
    /// use zktls_crypto::native::NativeCryptoProvider;
    /// let provider = NativeCryptoProvider::new();
    /// ```
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl PrecompileDetection for NativeCryptoProvider {
    fn has_any_precompiles(&self) -> bool {
        false // Native implementations never use precompiles
    }
    
    fn platform_name(&self) -> Option<&'static str> {
        None // Standard Rust environment
    }
}

impl CryptoProvider for NativeCryptoProvider {
    fn new() -> Self {
        NativeCryptoProvider::new()
    }
}

// Forward trait implementations to individual modules
impl Hash for NativeCryptoProvider {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        hash::sha256(input)
    }
    
    fn sha384(&self, input: &[u8]) -> [u8; 48] {
        hash::sha384(input)
    }
    
    fn has_precompile_support(&self) -> bool {
        false
    }
}

impl Aead for NativeCryptoProvider {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        aead::encrypt(key, nonce, aad, plaintext)
    }
    
    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        aead::decrypt(key, nonce, aad, ciphertext)
    }
    
    fn has_precompile_support(&self) -> bool {
        false
    }
}

impl KeyExchange for NativeCryptoProvider {
    fn x25519_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        ecdh::x25519_generate_keypair()
    }
    
    fn x25519_diffie_hellman(
        &self,
        private_key: &[u8],
        peer_public_key: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        ecdh::x25519_diffie_hellman(private_key, peer_public_key)
    }
    
    fn p256_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        ecdh::p256_generate_keypair()
    }
    
    fn p256_diffie_hellman(
        &self,
        private_key: &[u8],
        peer_public_key: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        ecdh::p256_diffie_hellman(private_key, peer_public_key)
    }
    
    fn has_precompile_support(&self) -> bool {
        false
    }
}

impl Signature for NativeCryptoProvider {
    fn p256_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        ecdsa::p256_generate_keypair()
    }
    
    fn p256_sign(&self, private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        ecdsa::p256_sign(private_key, message)
    }
    
    fn p256_verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool> {
        ecdsa::p256_verify(public_key, message, signature)
    }
    
    fn p256_verify_prehashed(
        &self,
        public_key: &[u8],
        hash: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool> {
        ecdsa::p256_verify_prehashed(public_key, hash, signature)
    }
    
    fn ed25519_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        ecdsa::ed25519_generate_keypair()
    }
    
    fn ed25519_sign(&self, private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        ecdsa::ed25519_sign(private_key, message)
    }
    
    fn ed25519_verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool> {
        ecdsa::ed25519_verify(public_key, message, signature)
    }
    
    fn rsa_verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        hash_algorithm: &str,
    ) -> CryptoResult<bool> {
        ecdsa::rsa_verify(public_key, message, signature, hash_algorithm)
    }
    
    fn has_precompile_support(&self) -> bool {
        false
    }
}

impl Kdf for NativeCryptoProvider {
    fn hkdf_extract_sha256(&self, salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
        kdf::hkdf_extract_sha256(salt, ikm)
    }

    fn hkdf_extract_sha384(&self, salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
        kdf::hkdf_extract_sha384(salt, ikm)
    }

    fn hkdf_expand_sha256(&self, prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        kdf::hkdf_expand_sha256(prk, info, length)
    }

    fn hkdf_expand_sha384(&self, prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        kdf::hkdf_expand_sha384(prk, info, length)
    }

    fn has_precompile_support(&self) -> bool {
        false // Native implementations don't use precompiles
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_provider_creation() {
        let provider = NativeCryptoProvider::new();
        assert!(!provider.has_any_precompiles());
        assert_eq!(provider.platform_name(), None);
    }
    
    #[test]
    fn test_provider_trait_implementation() {
        let provider = NativeCryptoProvider::new();
        
        // Test that all trait methods are available - use explicit trait disambiguation
        use crate::traits::Hash;
        assert!(!Hash::has_precompile_support(&provider));
        
        // These will fail until we implement the modules, but ensures trait compilation
        // let _ = provider.sha256(b"test");
        // let _ = provider.encrypt(&[], &[], &[], &[]);
        // let _ = provider.x25519_generate_keypair();
        // let _ = provider.p256_generate_keypair();
    }

    #[test]
    fn test_kdf_trait_implementation() {
        use crate::traits::Kdf;
        use hex_literal::hex;
        
        let provider = NativeCryptoProvider::new();
        
        // Test HKDF precompile support
        assert!(!Kdf::has_precompile_support(&provider));
        
        // Test HKDF-Extract and HKDF-Expand using RFC 5869 test vector
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let length = 42;
        
        // Expected outputs from RFC 5869 Test Case 1
        let expected_prk = hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let expected_okm = hex!("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
        
        // Test HKDF-Extract SHA-256
        let prk = provider.hkdf_extract_sha256(&salt, &ikm).unwrap();
        assert_eq!(prk, expected_prk, "HKDF-Extract SHA-256 should match RFC 5869 test vector");
        
        // Test HKDF-Expand SHA-256
        let okm = provider.hkdf_expand_sha256(&prk, &info, length).unwrap();
        assert_eq!(okm, expected_okm, "HKDF-Expand SHA-256 should match RFC 5869 test vector");
        
        // Test HKDF-Extract and HKDF-Expand SHA-384
        let prk_384 = provider.hkdf_extract_sha384(&salt, &ikm).unwrap();
        assert_eq!(prk_384.len(), 48, "HKDF-Extract SHA-384 should produce 48-byte PRK");
        
        let okm_384 = provider.hkdf_expand_sha384(&prk_384, &info, length).unwrap();
        assert_eq!(okm_384.len(), length, "HKDF-Expand SHA-384 should produce requested length");
        
        // Test error conditions
        let short_prk = vec![0u8; 16];
        let result = provider.hkdf_expand_sha256(&short_prk, &info, 32);
        assert!(result.is_err(), "HKDF-Expand should fail with short PRK");
        
        // Test maximum length validation
        let max_length_256 = 255 * 32; // Maximum for SHA-256
        let result = provider.hkdf_expand_sha256(&prk, &info, max_length_256);
        assert!(result.is_ok(), "HKDF-Expand should succeed at maximum length");
        
        let too_long = max_length_256 + 1;
        let result = provider.hkdf_expand_sha256(&prk, &info, too_long);
        assert!(result.is_err(), "HKDF-Expand should fail when exceeding maximum length");
    }

    #[test]
    fn test_kdf_consistency_with_direct_calls() {
        use crate::traits::Kdf;
        
        let provider = NativeCryptoProvider::new();
        let ikm = &[0xabu8; 22];
        let salt = &[0x01, 0x02, 0x03, 0x04];
        let info = b"test info";
        let length = 32;
        
        // Test that trait methods produce same results as direct function calls
        let trait_prk = provider.hkdf_extract_sha256(salt, ikm).unwrap();
        let direct_prk = crate::native::kdf::hkdf_extract_sha256(salt, ikm).unwrap();
        assert_eq!(trait_prk, direct_prk, "Trait and direct extract calls should match");
        
        let trait_okm = provider.hkdf_expand_sha256(&trait_prk, info, length).unwrap();
        let direct_okm = crate::native::kdf::hkdf_expand_sha256(&direct_prk, info, length).unwrap();
        assert_eq!(trait_okm, direct_okm, "Trait and direct expand calls should match");
        
        // Test SHA-384 consistency
        let trait_prk_384 = provider.hkdf_extract_sha384(salt, ikm).unwrap();
        let direct_prk_384 = crate::native::kdf::hkdf_extract_sha384(salt, ikm).unwrap();
        assert_eq!(trait_prk_384, direct_prk_384, "SHA-384 trait and direct extract calls should match");
        
        let trait_okm_384 = provider.hkdf_expand_sha384(&trait_prk_384, info, length).unwrap();
        let direct_okm_384 = crate::native::kdf::hkdf_expand_sha384(&direct_prk_384, info, length).unwrap();
        assert_eq!(trait_okm_384, direct_okm_384, "SHA-384 trait and direct expand calls should match");
    }
}