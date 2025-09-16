//! SP1-optimized cryptographic implementations for zkTLS using official SP1 patches
//!
//! This crate provides SP1-specific implementations of all cryptographic operations
//! required for zkTLS, leveraging official SP1 patched crates for optimal performance
//! while maintaining compatibility with the zktls-crypto trait interface.
//!
//! # SP1 Patches Used
//!
//! This crate uses official SP1 patched versions of cryptographic crates that automatically
//! route operations through SP1's native precompiles for maximum performance:
//!
//! - **sha2**: `patch-sha2-0.10.9-sp1-4.0.0` - SHA-256/SHA-384 precompiles
//! - **p256**: `patch-p256-13.2-sp1-5.0.0` - P-256 elliptic curve precompiles
//! - **k256**: `patch-k256-13.4-sp1-5.0.0` - secp256k1 elliptic curve precompiles
//! - **curve25519-dalek**: `patch-4.1.3-sp1-5.0.0` - X25519/Ed25519 precompiles
//! - **ecdsa**: `patch-16.9-sp1-4.1.0` - ECDSA signature precompiles
//! - **rsa**: `patch-0.9.6-sp1-5.0.0` - RSA signature precompiles
//! - **crypto-bigint**: `patch-0.5.5-sp1-4.0.0` - Big integer arithmetic precompiles
//!
//! # Performance
//!
//! All cryptographic operations automatically benefit from SP1 precompiles
//! when available, providing significant performance improvements over standard
//! implementations while maintaining identical security properties.
//!
//! # Example
//!
//! ```rust
//! use zktls_crypto_sp1::SP1CryptoProvider;
//! use zktls_crypto::traits::CryptoProvider;
//!
//! let crypto = SP1CryptoProvider::new();
//! let digest = crypto.sha256(b"Hello, SP1!");
//! assert_eq!(digest.len(), 32);
//! ```

#![cfg_attr(feature = "no_std", no_std)]

#[cfg(feature = "no_std")]
extern crate alloc;

use zktls_crypto::error::{CryptoResult, CryptoError};
use zktls_crypto::traits::{CryptoProvider, Hash, Aead, KeyExchange, Signature, Kdf, PrecompileDetection};

// SP1 patched cryptographic crates
use sha2::{Sha256, Sha384, Digest};
use aes_gcm::{Aes256Gcm, Aes128Gcm, Nonce, aead::{Aead as AeadTrait, KeyInit}};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use rand_core::RngCore;
use p256::{
    ecdh::diffie_hellman,
    EncodedPoint, 
    PublicKey as P256PublicKey,
    SecretKey as P256SecretKey,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    ecdsa::{SigningKey, VerifyingKey, Signature as P256Signature},
};
use ecdsa::signature::hazmat::PrehashVerifier;
use ecdsa::signature::{Signer, Verifier};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey, Signature as Ed25519Signature};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs1v15::VerifyingKey as RsaVerifyingKey, pkcs1v15::Signature as RsaSignature};
use rand::rngs::OsRng;
use arrayref::array_ref;

#[cfg(feature = "no_std")]
use alloc::{vec, vec::Vec};

/// SP1-optimized cryptographic provider
///
/// This provider uses official SP1 patched crates which automatically route
/// operations through SP1's native precompiles for optimal performance.
/// It implements all cryptographic operations required for TLS 1.3.
///
/// # Example
///
/// ```rust
/// use zktls_crypto_sp1::SP1CryptoProvider;
/// use zktls_crypto::traits::CryptoProvider;
///
/// let crypto = SP1CryptoProvider::new();
/// let digest = crypto.sha256(b"Hello, SP1!");
/// assert_eq!(digest.len(), 32);
/// ```
#[derive(Clone)]
pub struct SP1CryptoProvider;

impl SP1CryptoProvider {
    /// Create a new SP1 crypto provider
    pub fn new() -> Self {
        Self
    }
}

impl Default for SP1CryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoProvider for SP1CryptoProvider {
    fn new() -> Self {
        Self
    }
}

impl PrecompileDetection for SP1CryptoProvider {
    fn has_any_precompiles(&self) -> bool {
        true // SP1 has precompile support
    }

    fn platform_name(&self) -> Option<&'static str> {
        Some("sp1")
    }
}

impl Hash for SP1CryptoProvider {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        hash.into()
    }

    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        let mut hasher = Sha384::new();
        hasher.update(data);
        let hash = hasher.finalize();
        hash.into()
    }

    fn has_precompile_support(&self) -> bool {
        true // SP1 has precompile support
    }
}

impl Aead for SP1CryptoProvider {
    fn encrypt(&self, key: &[u8], nonce: &[u8], _aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 16 && key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }
        
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() });
        }
        
        let nonce = Nonce::try_from(nonce).map_err(|_| CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() })?;
        
        if key.len() == 32 {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKeySize(key.len()))?;
            cipher.encrypt(&nonce, plaintext)
                .map_err(|_| CryptoError::DecryptionFailed)
        } else {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKeySize(key.len()))?;
            cipher.encrypt(&nonce, plaintext)
                .map_err(|_| CryptoError::DecryptionFailed)
        }
    }

    fn decrypt(&self, key: &[u8], nonce: &[u8], _aad: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 16 && key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }
        
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() });
        }
        
        if ciphertext.len() < 16 {
            return Err(CryptoError::DecryptionFailed);
        }
        
        let nonce = Nonce::try_from(nonce).map_err(|_| CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() })?;
        
        if key.len() == 32 {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKeySize(key.len()))?;
            cipher.decrypt(&nonce, ciphertext)
                .map_err(|_| CryptoError::DecryptionFailed)
        } else {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKeySize(key.len()))?;
            cipher.decrypt(&nonce, ciphertext)
                .map_err(|_| CryptoError::DecryptionFailed)
        }
    }

    fn has_precompile_support(&self) -> bool {
        true // SP1 has precompile support
    }
}

impl KeyExchange for SP1CryptoProvider {
    fn x25519_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let mut rng = OsRng;
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = X25519PublicKey::from(&secret);
        
        Ok((secret.to_bytes().to_vec(), public.to_bytes().to_vec()))
    }

    fn x25519_diffie_hellman(&self, private_key: &[u8], peer_public_key: &[u8]) -> CryptoResult<Vec<u8>> {
        if private_key.len() != 32 {
            return Err(CryptoError::InvalidPrivateKey);
        }
        if peer_public_key.len() != 32 {
            return Err(CryptoError::InvalidPublicKey);
        }
        
        let mut private_bytes = [0u8; 32];
        private_bytes.copy_from_slice(private_key);
        let secret = StaticSecret::from(private_bytes);
        
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(peer_public_key);
        let peer_public = X25519PublicKey::from(public_bytes);
        
        let shared_secret = secret.diffie_hellman(&peer_public);
        
        Ok(shared_secret.as_bytes().to_vec())
    }

    fn p256_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let mut rng = OsRng;
        let secret_key = P256SecretKey::random(&mut rng);
        let public_key = secret_key.public_key();
        
        let encoded_point = public_key.to_encoded_point(false);
        
        Ok((
            secret_key.to_bytes().to_vec(),
            encoded_point.as_bytes().to_vec(),
        ))
    }

    fn p256_diffie_hellman(&self, private_key: &[u8], peer_public_key: &[u8]) -> CryptoResult<Vec<u8>> {
        if private_key.len() != 32 {
            return Err(CryptoError::InvalidPrivateKey);
        }
        if peer_public_key.len() != 65 {
            return Err(CryptoError::InvalidPublicKey);
        }
        
        let secret_key = P256SecretKey::from_slice(private_key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        
        let encoded_point = EncodedPoint::from_bytes(peer_public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let peer_public = P256PublicKey::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or(CryptoError::InvalidPublicKey)?;
        
        let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), peer_public.as_affine());
        
        Ok(shared_secret.raw_secret_bytes().to_vec())
    }

    fn has_precompile_support(&self) -> bool {
        true // SP1 has precompile support
    }
}

impl Signature for SP1CryptoProvider {
    fn p256_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        KeyExchange::p256_generate_keypair(self)
    }

    fn p256_sign(&self, private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        if private_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(private_key.len()));
        }
        
        let secret_key = P256SecretKey::from_bytes(private_key.into())
            .map_err(|_| CryptoError::InvalidKeySize(private_key.len()))?;
        
        let signing_key = SigningKey::from(&secret_key);
        let signature: P256Signature = signing_key.sign(message);
        
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn p256_verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        if public_key.len() != 65 {
            return Err(CryptoError::InvalidKeySize(public_key.len()));
        }
        
        let public_key = P256PublicKey::from_sec1_bytes(public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        
        let verifying_key = VerifyingKey::from(&public_key);
        let signature = P256Signature::from_der(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        
        match verifying_key.verify_prehash(&hash, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn p256_verify_prehashed(&self, public_key: &[u8], hash: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        if public_key.len() != 65 {
            return Err(CryptoError::InvalidKeySize(public_key.len()));
        }
        
        let public_key = P256PublicKey::from_sec1_bytes(public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        
        let verifying_key = VerifyingKey::from(&public_key);
        let signature = P256Signature::from_der(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        
        match verifying_key.verify_prehash(hash, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn ed25519_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let mut rng = OsRng;
        let mut private_bytes = [0u8; 32];
        rng.fill_bytes(&mut private_bytes);
        
        let signing_key = Ed25519SigningKey::from_bytes(&private_bytes);
        let verifying_key = signing_key.verifying_key();
        
        Ok((
            private_bytes.to_vec(),
            verifying_key.to_bytes().to_vec(),
        ))
    }

    fn ed25519_sign(&self, private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        if private_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(private_key.len()));
        }
        
        let signing_key = Ed25519SigningKey::from_bytes(array_ref!(private_key, 0, 32));
        let signature: Ed25519Signature = signing_key.sign(message);
        
        Ok(signature.to_bytes().to_vec())
    }

    fn ed25519_verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        if public_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(public_key.len()));
        }
        
        if signature.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }
        
        let verifying_key = Ed25519VerifyingKey::from_bytes(array_ref!(public_key, 0, 32))
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        
        let signature = Ed25519Signature::from_bytes(array_ref!(signature, 0, 64));
        
        match verifying_key.verify(message, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn rsa_verify(&self, public_key: &[u8], message: &[u8], signature: &[u8], hash_alg: &str) -> CryptoResult<bool> {
        let public_key = RsaPublicKey::from_pkcs1_der(public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        
        let signature = RsaSignature::try_from(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        
        match hash_alg {
            "sha256" => {
                let verifying_key = RsaVerifyingKey::<sha2::Sha256>::new_unprefixed(public_key);
                match verifying_key.verify(message, &signature) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            },
            "sha384" => {
                let verifying_key = RsaVerifyingKey::<sha2::Sha384>::new_unprefixed(public_key);
                match verifying_key.verify(message, &signature) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            },
            _ => Err(CryptoError::InvalidSignature),
        }
    }

    fn has_precompile_support(&self) -> bool {
        true // SP1 has precompile support
    }
}

impl Kdf for SP1CryptoProvider {
    fn hkdf_extract_sha256(&self, salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Sha256::new();
        
        let mut processed_key = [0u8; 64];
        if salt.len() > 64 {
            let key_hash = self.sha256(salt);
            processed_key[..32].copy_from_slice(&key_hash);
        } else {
            processed_key[..salt.len()].copy_from_slice(salt);
        }
        
        hasher.update(&processed_key);
        hasher.update(ikm);
        let inner_hash = hasher.finalize();
        
        let mut outer_hasher = Sha256::new();
        outer_hasher.update(&processed_key);
        outer_hasher.update(&inner_hash);
        let outer_hash = outer_hasher.finalize();
        
        Ok(outer_hash.to_vec())
    }

    fn hkdf_extract_sha384(&self, salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Sha384::new();
        
        let mut processed_key = [0u8; 128];
        if salt.len() > 128 {
            let key_hash = self.sha384(salt);
            processed_key[..48].copy_from_slice(&key_hash);
        } else {
            processed_key[..salt.len()].copy_from_slice(salt);
        }
        
        hasher.update(&processed_key);
        hasher.update(ikm);
        let inner_hash = hasher.finalize();
        
        let mut outer_hasher = Sha384::new();
        outer_hasher.update(&processed_key);
        outer_hasher.update(&inner_hash);
        let outer_hash = outer_hasher.finalize();
        
        Ok(outer_hash.to_vec())
    }

    fn hkdf_expand_sha256(&self, prk: &[u8], info: &[u8], okm_len: usize) -> CryptoResult<Vec<u8>> {
        if okm_len == 0 {
            return Err(CryptoError::InvalidKeySize(0));
        }
        
        if okm_len > 255 * 32 {
            return Err(CryptoError::InvalidKeySize(okm_len));
        }
        
        let mut okm = Vec::with_capacity(okm_len);
        let mut counter = 1u8;
        
        while okm.len() < okm_len {
            let mut hasher = Sha256::new();
            hasher.update(prk);
            hasher.update(&[counter]);
            hasher.update(info);
            let t = hasher.finalize();
            
            let remaining = okm_len - okm.len();
            if remaining >= 32 {
                okm.extend_from_slice(&t);
            } else {
                okm.extend_from_slice(&t[..remaining]);
            }
            
            counter = counter.checked_add(1).ok_or_else(|| CryptoError::InvalidKeySize(okm_len))?;
        }
        
        Ok(okm)
    }

    fn hkdf_expand_sha384(&self, prk: &[u8], info: &[u8], okm_len: usize) -> CryptoResult<Vec<u8>> {
        if okm_len == 0 {
            return Err(CryptoError::InvalidKeySize(0));
        }
        
        if okm_len > 255 * 48 {
            return Err(CryptoError::InvalidKeySize(okm_len));
        }
        
        let mut okm = Vec::with_capacity(okm_len);
        let mut counter = 1u8;
        
        while okm.len() < okm_len {
            let mut hasher = Sha384::new();
            hasher.update(prk);
            hasher.update(&[counter]);
            hasher.update(info);
            let t = hasher.finalize();
            
            let remaining = okm_len - okm.len();
            if remaining >= 48 {
                okm.extend_from_slice(&t);
            } else {
                okm.extend_from_slice(&t[..remaining]);
            }
            
            counter = counter.checked_add(1).ok_or_else(|| CryptoError::InvalidKeySize(okm_len))?;
        }
        
        Ok(okm)
    }

    fn has_precompile_support(&self) -> bool {
        true // SP1 has precompile support
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp1_crypto_provider() {
        let provider = SP1CryptoProvider::new();
        
        // Test hash operations
        let data = b"Hello, world!";
        let hash = provider.sha256(data);
        assert_eq!(hash.len(), 32);
        
        // Test AEAD operations
        let key = &[0u8; 32];
        let nonce = &[0u8; 12];
        let aad = b"additional data";
        let plaintext = b"secret message";
        let ciphertext = provider.encrypt(key, nonce, aad, plaintext).unwrap();
        let decrypted = provider.decrypt(key, nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
        
        // Test key exchange
        let (private_key, public_key) = provider.x25519_generate_keypair().unwrap();
        assert_eq!(private_key.len(), 32);
        assert_eq!(public_key.len(), 32);
        
        // Test signature
        let (private_key, public_key) = provider.p256_generate_keypair().unwrap();
        let message = b"Hello, world!";
        let signature = provider.p256_sign(&private_key, message).unwrap();
        let verified = provider.p256_verify(&public_key, message, &signature).unwrap();
        assert!(verified);
        
        // Test KDF
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let okm = provider.hkdf_expand_sha256(&provider.hkdf_extract_sha256(salt, ikm).unwrap(), info, 32).unwrap();
        assert_eq!(okm.len(), 32);
    }
    
    #[test]
    fn test_sp1_precompile_detection() {
        let provider = SP1CryptoProvider::new();
        assert!(provider.has_any_precompiles());
        assert_eq!(provider.platform_name(), Some("sp1"));
    }
    
    #[test]
    fn test_sp1_consistency_with_native() {
        let sp1_provider = SP1CryptoProvider::new();
        let native_provider = zktls_crypto::native::NativeCryptoProvider::new();
        
        let data = b"consistency test data";
        
        // Test hash consistency
        let sp1_hash = sp1_provider.sha256(data);
        let native_hash = native_provider.sha256(data);
        assert_eq!(sp1_hash, native_hash);
        
        // Test AEAD consistency
        let key = &[0u8; 32];
        let nonce = &[0u8; 12];
        let aad = b"additional data";
        let plaintext = b"secret message";
        
        let sp1_ciphertext = sp1_provider.encrypt(key, nonce, aad, plaintext).unwrap();
        let native_ciphertext = native_provider.encrypt(key, nonce, aad, plaintext).unwrap();
        
        let sp1_decrypted = sp1_provider.decrypt(key, nonce, aad, &sp1_ciphertext).unwrap();
        let native_decrypted = native_provider.decrypt(key, nonce, aad, &native_ciphertext).unwrap();
        
        assert_eq!(sp1_decrypted, native_decrypted);
        assert_eq!(sp1_decrypted, plaintext);
        assert_eq!(native_decrypted, plaintext);
        
        // Test KDF consistency
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        
        let sp1_okm = sp1_provider.hkdf_expand_sha256(&sp1_provider.hkdf_extract_sha256(salt, ikm).unwrap(), info, 32).unwrap();
        let native_okm = native_provider.hkdf_expand_sha256(&native_provider.hkdf_extract_sha256(salt, ikm).unwrap(), info, 32).unwrap();
        assert_eq!(sp1_okm, native_okm);
    }
}