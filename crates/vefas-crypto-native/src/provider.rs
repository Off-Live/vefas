//! Native cryptographic provider implementation
//!
//! This module contains the main `NativeCryptoProvider` struct that implements
//! all VEFAS cryptographic traits using standard Rust crypto libraries.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use vefas_crypto::traits::{
    Aead, Hash, Kdf, KeyExchange, PrecompileDetection, PrecompileSummary, Signature, VefasCrypto,
};
use vefas_crypto::{MerkleHasher, MerkleVerifier, MerkleError};
use vefas_types::{VefasResult, VefasError};

/// Native cryptographic provider implementation
///
/// This provider implements all VEFAS cryptographic traits using production-grade
/// Rust cryptography libraries. It serves as both a reference implementation and
/// a fallback for zkVM environments where precompiles are unavailable.
///
/// # Features
///
/// - **Complete Implementation**: All VEFAS traits fully implemented
/// - **Production Quality**: RFC-compliant with proper error handling
/// - **Memory Safe**: Uses only safe Rust code
/// - **Dual Environment**: Works in both std and no_std environments
/// - **Deterministic**: Consistent behavior for proof generation
///
/// # Example
///
/// ```rust
/// use vefas_crypto_native::NativeCryptoProvider;
/// use vefas_crypto::traits::Hash;
///
/// let provider = NativeCryptoProvider::new();
/// let hash = provider.sha256(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
#[derive(Debug, Clone, Default)]
pub struct NativeCryptoProvider {
    // Private field to prevent direct construction
    _private: (),
}

impl NativeCryptoProvider {
    /// Create a new native crypto provider instance
    ///
    /// # Example
    ///
    /// ```rust
    /// use vefas_crypto_native::NativeCryptoProvider;
    ///
    /// let provider = NativeCryptoProvider::new();
    /// ```
    pub fn new() -> Self {
        Self { _private: () }
    }
}

// Forward implementations to individual modules for clean separation
impl Hash for NativeCryptoProvider {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        crate::hash::sha256(input)
    }

    fn sha384(&self, input: &[u8]) -> [u8; 48] {
        crate::hash::sha384(input)
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        crate::hash::hmac_sha256(key, data)
    }

    fn hmac_sha384(&self, key: &[u8], data: &[u8]) -> [u8; 48] {
        crate::hash::hmac_sha384(key, data)
    }

    fn has_precompile_support(&self) -> bool {
        false // Native implementation has no precompiles
    }
}

impl Aead for NativeCryptoProvider {
    fn aes_128_gcm_encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> VefasResult<Vec<u8>> {
        crate::aead::aes_128_gcm_encrypt(key, nonce, aad, plaintext)
    }

    fn aes_128_gcm_decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> VefasResult<Vec<u8>> {
        crate::aead::aes_128_gcm_decrypt(key, nonce, aad, ciphertext)
    }

    fn aes_256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> VefasResult<Vec<u8>> {
        crate::aead::aes_256_gcm_encrypt(key, nonce, aad, plaintext)
    }

    fn aes_256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> VefasResult<Vec<u8>> {
        crate::aead::aes_256_gcm_decrypt(key, nonce, aad, ciphertext)
    }

    fn chacha20_poly1305_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> VefasResult<Vec<u8>> {
        crate::aead::chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
    }

    fn chacha20_poly1305_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> VefasResult<Vec<u8>> {
        crate::aead::chacha20_poly1305_decrypt(key, nonce, aad, ciphertext)
    }

    fn has_precompile_support(&self) -> bool {
        false // Native implementation has no precompiles
    }
}

impl KeyExchange for NativeCryptoProvider {
    fn x25519_generate_keypair(&self) -> ([u8; 32], [u8; 32]) {
        crate::key_exchange::x25519_generate_keypair()
    }

    fn x25519_compute_shared_secret(
        &self,
        private_key: &[u8; 32],
        public_key: &[u8; 32],
    ) -> VefasResult<[u8; 32]> {
        crate::key_exchange::x25519_compute_shared_secret(private_key, public_key)
    }

    fn p256_generate_keypair(&self) -> VefasResult<([u8; 32], [u8; 65])> {
        crate::key_exchange::p256_generate_keypair()
    }

    fn p256_compute_shared_secret(
        &self,
        private_key: &[u8; 32],
        public_key: &[u8; 65],
    ) -> VefasResult<[u8; 32]> {
        crate::key_exchange::p256_compute_shared_secret(private_key, public_key)
    }

    fn has_precompile_support(&self) -> bool {
        false // Native implementation has no precompiles
    }
}

impl Signature for NativeCryptoProvider {
    fn p256_generate_keypair(&self) -> VefasResult<([u8; 32], [u8; 65])> {
        crate::signature::p256_generate_keypair()
    }

    fn p256_sign(&self, private_key: &[u8; 32], message: &[u8]) -> VefasResult<Vec<u8>> {
        crate::signature::p256_sign(private_key, message)
    }

    fn p256_verify(&self, public_key: &[u8; 65], message: &[u8], signature: &[u8]) -> bool {
        crate::signature::p256_verify(public_key, message, signature)
    }

    fn secp256k1_generate_keypair(&self) -> VefasResult<([u8; 32], [u8; 65])> {
        crate::signature::secp256k1_generate_keypair()
    }

    fn secp256k1_sign(&self, private_key: &[u8; 32], message: &[u8]) -> VefasResult<Vec<u8>> {
        crate::signature::secp256k1_sign(private_key, message)
    }

    fn secp256k1_verify(&self, public_key: &[u8; 65], message: &[u8], signature: &[u8]) -> bool {
        crate::signature::secp256k1_verify(public_key, message, signature)
    }

    fn ed25519_generate_keypair(&self) -> ([u8; 32], [u8; 32]) {
        crate::signature::ed25519_generate_keypair()
    }

    fn ed25519_sign(&self, private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
        crate::signature::ed25519_sign(private_key, message)
    }

    fn ed25519_verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        crate::signature::ed25519_verify(public_key, message, signature)
    }

    fn rsa_2048_generate_keypair(&self) -> VefasResult<(Vec<u8>, Vec<u8>)> {
        crate::signature::rsa_2048_generate_keypair()
    }

    fn rsa_pkcs1_sha256_sign(
        &self,
        private_key_der: &[u8],
        message: &[u8],
    ) -> VefasResult<Vec<u8>> {
        crate::signature::rsa_pkcs1_sha256_sign(private_key_der, message)
    }

    fn rsa_pkcs1_sha256_verify(
        &self,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        crate::signature::rsa_pkcs1_sha256_verify(public_key_der, message, signature)
    }

    fn rsa_pss_sha256_sign(&self, private_key_der: &[u8], message: &[u8]) -> VefasResult<Vec<u8>> {
        crate::signature::rsa_pss_sha256_sign(private_key_der, message)
    }

    fn rsa_pss_sha256_verify(
        &self,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        crate::signature::rsa_pss_sha256_verify(public_key_der, message, signature)
    }

    fn has_precompile_support(&self) -> bool {
        false // Native implementation has no precompiles
    }
}

impl Kdf for NativeCryptoProvider {
    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        crate::kdf::hkdf_extract(salt, ikm)
    }

    fn hkdf_expand(&self, prk: &[u8; 32], info: &[u8], length: usize) -> VefasResult<Vec<u8>> {
        crate::kdf::hkdf_expand(prk, info, length)
    }

    fn hkdf_extract_sha384(&self, salt: &[u8], ikm: &[u8]) -> [u8; 48] {
        crate::kdf::hkdf_extract_sha384(salt, ikm)
    }

    fn hkdf_expand_sha384(&self, prk: &[u8; 48], info: &[u8], length: usize) -> VefasResult<Vec<u8>> {
        crate::kdf::hkdf_expand_sha384(prk, info, length)
    }

    fn has_precompile_support(&self) -> bool {
        false // Native implementation has no precompiles
    }

    fn hkdf_expand_label(
        &self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> VefasResult<Vec<u8>> {
        // TLS 1.3 HKDF-Expand-Label format per RFC 8446
        let mut hkdf_label = Vec::new();
        hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
        hkdf_label.push(6 + label.len() as u8);
        hkdf_label.extend_from_slice(b"tls13 ");
        hkdf_label.extend_from_slice(label);
        hkdf_label.push(context.len() as u8);
        hkdf_label.extend_from_slice(context);

        // Convert secret to fixed-size array for HKDF
        let prk = if secret.len() == 32 {
            let mut prk_array = [0u8; 32];
            prk_array.copy_from_slice(secret);
            prk_array
        } else {
            self.hkdf_extract(&[], secret)
        };

        self.hkdf_expand(&prk, &hkdf_label, length)
    }

    fn derive_handshake_secrets(
        &self,
        shared_secret: &[u8],
        handshake_hash: &[u8; 32],
    ) -> VefasResult<([u8; 32], [u8; 32])> {
        let handshake_secret = self.hkdf_extract(&[0u8; 32], shared_secret);

        let client_secret =
            self.hkdf_expand_label(&handshake_secret, b"c hs traffic", handshake_hash, 32)?;

        let server_secret =
            self.hkdf_expand_label(&handshake_secret, b"s hs traffic", handshake_hash, 32)?;

        let mut client_array = [0u8; 32];
        let mut server_array = [0u8; 32];
        client_array.copy_from_slice(&client_secret);
        server_array.copy_from_slice(&server_secret);

        Ok((client_array, server_array))
    }

    fn derive_application_secrets(
        &self,
        handshake_secret: &[u8; 32],
        handshake_hash: &[u8; 32],
    ) -> VefasResult<([u8; 32], [u8; 32])> {
        let master_secret = self.hkdf_expand_label(
            handshake_secret,
            b"derived",
            &self.hkdf_extract(&[], &[]),
            32,
        )?;

        let master_array = if master_secret.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&master_secret);
            array
        } else {
            return Err(VefasError::crypto_error(
                vefas_types::errors::CryptoErrorType::InvalidKeyLength,
                "invalid master secret length",
            ));
        };

        let client_secret =
            self.hkdf_expand_label(&master_array, b"c ap traffic", handshake_hash, 32)?;

        let server_secret =
            self.hkdf_expand_label(&master_array, b"s ap traffic", handshake_hash, 32)?;

        let mut client_array = [0u8; 32];
        let mut server_array = [0u8; 32];
        client_array.copy_from_slice(&client_secret);
        server_array.copy_from_slice(&server_secret);

        Ok((client_array, server_array))
    }
}

impl PrecompileDetection for NativeCryptoProvider {
    fn precompile_summary(&self) -> PrecompileSummary {
        PrecompileSummary {
            provider_name: "native",
            total_operations: 12,
            accelerated_operations: 0, // Native implementation has no precompiles
        }
    }
}

impl VefasCrypto for NativeCryptoProvider {
    fn provider_name(&self) -> &'static str {
        "Native"
    }

    fn provider_version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn supports_hardware_acceleration(&self) -> bool {
        false // Native implementations don't use hardware acceleration
    }

    fn supports_zkvm_precompiles(&self) -> bool {
        false // Native implementations don't use precompiles
    }

    fn get_precompile_info(&self) -> PrecompileSummary {
        PrecompileSummary {
            provider_name: self.provider_name(),
            total_operations: 12,
            accelerated_operations: 0,
        }
    }
}

// Merkle tree trait implementations
impl MerkleHasher for NativeCryptoProvider {
    fn hash_data(&self, data: &[u8]) -> Result<[u8; 32], MerkleError> {
        Ok(self.sha256(data))
    }
    
    fn hasher_name(&self) -> &'static str {
        "NativeSHA256"
    }
}

impl MerkleVerifier for NativeCryptoProvider {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = NativeCryptoProvider::new();
        assert_eq!(provider.provider_name(), "Native");
        assert_eq!(provider.provider_version(), env!("CARGO_PKG_VERSION"));
        assert!(!provider.supports_hardware_acceleration());
        assert!(!provider.supports_zkvm_precompiles());
    }

    #[test]
    fn test_precompile_info() {
        let provider = NativeCryptoProvider::new();
        let info = provider.get_precompile_info();
        assert_eq!(info.provider_name, "Native");
        assert_eq!(info.total_operations, 12);
        assert_eq!(info.accelerated_operations, 0);
        assert_eq!(info.acceleration_percentage(), 0.0);
    }

    #[test]
    fn test_all_traits_implemented() {
        let provider = NativeCryptoProvider::new();

        // Test Hash trait
        let hash = provider.sha256(b"test");
        assert_eq!(hash.len(), 32);

        let hash384 = provider.sha384(b"test");
        assert_eq!(hash384.len(), 48);

        let hmac = provider.hmac_sha256(b"key", b"data");
        assert_eq!(hmac.len(), 32);

        // Test KeyExchange trait
        let (x25519_private, x25519_public) = provider.x25519_generate_keypair();
        assert_eq!(x25519_private.len(), 32);
        assert_eq!(x25519_public.len(), 32);

        // Test Signature trait
        let (ed25519_private, ed25519_public) = provider.ed25519_generate_keypair();
        assert_eq!(ed25519_private.len(), 32);
        assert_eq!(ed25519_public.len(), 32);

        let ed25519_signature = provider.ed25519_sign(&ed25519_private, b"message");
        assert_eq!(ed25519_signature.len(), 64);

        assert!(provider.ed25519_verify(&ed25519_public, b"message", &ed25519_signature));

        // Test Kdf trait
        let prk = provider.hkdf_extract(b"salt", b"ikm");
        assert_eq!(prk.len(), 32);

        let okm = provider.hkdf_expand(&prk, b"info", 42).unwrap();
        assert_eq!(okm.len(), 42);

        // Verify no precompile support
        assert!(!provider.supports_zkvm_precompiles());
    }
}
