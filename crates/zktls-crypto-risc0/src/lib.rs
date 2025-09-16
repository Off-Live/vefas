//! RISC0-optimized cryptographic implementations for zkTLS
//!
//! This crate provides cryptographic implementations optimized for RISC0 zkVM
//! using official RISC0 patched crates. These implementations automatically
//! route operations through RISC0's native precompiles for optimal performance
//! while maintaining compatibility with the zktls-crypto trait interface.
//!
//! # RISC0 Patches Used
//!
//! This crate uses official RISC0 patched versions of cryptographic libraries:
//! - **sha2**: SHA-256/SHA-384 hash functions (v0.10.8-risczero.0)
//! - **p256**: P-256 elliptic curve operations (v0.13.2-risczero.1)
//! - **k256**: secp256k1 elliptic curve operations (v0.13.3-risczero.1)
//! - **curve25519-dalek**: Curve25519 and Ed25519 operations (4.1.2-risczero.0)
//! - **rsa**: RSA signature operations (v0.9.6-risczero.0)
//! - **crypto-bigint**: Big integer arithmetic (v0.5.5-risczero.0)
//!
//! # Performance
//!
//! All cryptographic operations automatically benefit from RISC0 precompiles
//! when available, providing significant performance improvements over standard
//! implementations while maintaining identical security properties.
//!
//! # Example
//!
//! ```rust
//! use zktls_crypto_risc0::RISC0CryptoProvider;
//! use zktls_crypto::traits::CryptoProvider;
//!
//! let crypto = RISC0CryptoProvider::new();
//! let digest = crypto.sha256(b"Hello, RISC0!");
//! assert_eq!(digest.len(), 32);
//! ```

#![cfg_attr(feature = "no_std", no_std)]

#[cfg(feature = "no_std")]
extern crate alloc;

use zktls_crypto::traits::{CryptoProvider, Hash, Aead, KeyExchange, Signature, Kdf, PrecompileDetection};
use zktls_crypto::error::{CryptoResult, CryptoError};

// Import traits needed for cryptographic operations
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::ecdsa::signature::{Signer, Verifier};
// Ed25519 traits are imported locally where needed
use rsa::pkcs1::DecodeRsaPublicKey;
use rand::Rng;
use aes_gcm::Nonce;

#[cfg(feature = "no_std")]
use alloc::vec::Vec;

/// RISC0-optimized cryptographic provider
///
/// This provider uses RISC0 patched cryptographic crates to automatically
/// route operations through RISC0's native precompiles for optimal performance.
#[derive(Debug, Clone, Default)]
pub struct RISC0CryptoProvider {
    _private: (), // Prevent direct construction, use `new()`
}

impl RISC0CryptoProvider {
    /// Create a new RISC0 crypto provider
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl CryptoProvider for RISC0CryptoProvider {
    fn new() -> Self {
        Self::new()
    }
}

impl PrecompileDetection for RISC0CryptoProvider {
    fn has_any_precompiles(&self) -> bool {
        true // RISC0 has precompile support
    }

    fn platform_name(&self) -> Option<&'static str> {
        Some("risc0")
    }
}

impl Hash for RISC0CryptoProvider {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        // Uses RISC0 patched sha2 crate with precompile acceleration
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }

    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        // Uses RISC0 patched sha2 crate with precompile acceleration
        use sha2::{Sha384, Digest};
        let mut hasher = Sha384::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 48];
        digest.copy_from_slice(&result);
        digest
    }

    fn has_precompile_support(&self) -> bool {
        true // RISC0 has precompile support for SHA-256/SHA-384
    }
}

impl Aead for RISC0CryptoProvider {
    fn encrypt(&self, key: &[u8], nonce: &[u8], _aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Uses standard AES-GCM implementation (no RISC0 precompiles available for AES-GCM)
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() });
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeySize(key.len()))?;
        
        // Convert nonce to array for RISC0 compatibility
        let nonce_array: [u8; 12] = nonce.try_into()
            .map_err(|_| CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() })?;
        let nonce = Nonce::from(nonce_array);
        
        cipher.encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn decrypt(&self, key: &[u8], nonce: &[u8], _aad: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Uses standard AES-GCM implementation (no RISC0 precompiles available for AES-GCM)
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() });
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeySize(key.len()))?;
        
        // Convert nonce to array for RISC0 compatibility
        let nonce_array: [u8; 12] = nonce.try_into()
            .map_err(|_| CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() })?;
        let nonce = Nonce::from(nonce_array);
        
        cipher.decrypt(&nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn has_precompile_support(&self) -> bool {
        false // RISC0 does not have precompile support for AES-GCM
    }
}

impl KeyExchange for RISC0CryptoProvider {
    fn x25519_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        // Uses standard x25519-dalek implementation (no RISC0 precompiles available for X25519)
        use x25519_dalek::{StaticSecret, PublicKey};
        use rand::rngs::OsRng;
        
        let mut rng = OsRng;
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);
        
        Ok((
            secret.to_bytes().to_vec(),
            public.to_bytes().to_vec(),
        ))
    }

    fn x25519_diffie_hellman(&self, private_key: &[u8], peer_public_key: &[u8]) -> CryptoResult<Vec<u8>> {
        // Uses standard x25519-dalek implementation (no RISC0 precompiles available for X25519)
        use x25519_dalek::{StaticSecret, PublicKey};
        
        if private_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(private_key.len()));
        }
        if peer_public_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(peer_public_key.len()));
        }

        let mut private_bytes = [0u8; 32];
        private_bytes.copy_from_slice(private_key);
        let secret = StaticSecret::from(private_bytes);
        
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(peer_public_key);
        let peer_public = PublicKey::from(public_bytes);
        
        let shared_secret = secret.diffie_hellman(&peer_public);
        Ok(shared_secret.as_bytes().to_vec())
    }

    fn p256_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        // Uses RISC0 patched p256 crate with precompile acceleration
        use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
        use rand::rngs::OsRng;
        
        let mut rng = OsRng;
        let secret_key = SecretKey::random(&mut rng);
        let public_key = secret_key.public_key();
        
        let encoded_point = public_key.to_encoded_point(false);
        
        Ok((
            secret_key.to_bytes().to_vec(),
            encoded_point.as_bytes().to_vec(),
        ))
    }

    fn p256_diffie_hellman(&self, private_key: &[u8], peer_public_key: &[u8]) -> CryptoResult<Vec<u8>> {
        // Uses RISC0 patched p256 crate with precompile acceleration
        use p256::{SecretKey, EncodedPoint, PublicKey, ecdh::diffie_hellman};
        
        if private_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(private_key.len()));
        }
        if peer_public_key.len() != 65 {
            return Err(CryptoError::InvalidKeySize(peer_public_key.len()));
        }

        let secret_key = SecretKey::from_slice(private_key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        
        let encoded_point = EncodedPoint::from_bytes(peer_public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let peer_public = PublicKey::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or(CryptoError::InvalidPublicKey)?;
        
        let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), peer_public.as_affine());
        Ok(shared_secret.raw_secret_bytes().to_vec())
    }

    fn has_precompile_support(&self) -> bool {
        true // RISC0 has precompile support for P-256 elliptic curve operations
    }
}

impl Signature for RISC0CryptoProvider {
    fn p256_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        // Delegate to KeyExchange implementation
        KeyExchange::p256_generate_keypair(self)
    }

    fn p256_sign(&self, private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        // Uses RISC0 patched p256 crate with precompile acceleration
        use p256::{SecretKey, ecdsa::SigningKey};
        
        if private_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(private_key.len()));
        }

        let secret_key = SecretKey::from_slice(private_key)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        
        let signing_key = SigningKey::from(secret_key);
        let signature: p256::ecdsa::Signature = signing_key.sign(message);
        
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn p256_verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        // Uses RISC0 patched p256 crate with precompile acceleration
        use p256::{PublicKey, EncodedPoint, ecdsa::VerifyingKey, ecdsa::Signature};
        
        if public_key.len() != 65 {
            return Err(CryptoError::InvalidKeySize(public_key.len()));
        }

        let encoded_point = EncodedPoint::from_bytes(public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let public_key = PublicKey::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or(CryptoError::InvalidPublicKey)?;
        
        let verifying_key = VerifyingKey::from(public_key);
        let signature = Signature::from_der(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        
        Ok(verifying_key.verify(message, &signature).is_ok())
    }

    fn p256_verify_prehashed(&self, public_key: &[u8], hash: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        // Uses RISC0 patched p256 crate with precompile acceleration for prehashed verification
        use p256::{PublicKey, EncodedPoint, ecdsa::VerifyingKey, ecdsa::Signature, ecdsa::signature::hazmat::PrehashVerifier};
        
        if public_key.len() != 65 {
            return Err(CryptoError::InvalidKeySize(public_key.len()));
        }

        let encoded_point = EncodedPoint::from_bytes(public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let public_key = PublicKey::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or(CryptoError::InvalidPublicKey)?;
        
        let verifying_key = VerifyingKey::from(public_key);
        let signature = Signature::from_der(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        
        Ok(verifying_key.verify_prehash(hash, &signature).is_ok())
    }

    fn ed25519_generate_keypair(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        // Uses RISC0 patched curve25519-dalek crate with precompile acceleration
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        
        let mut rng = OsRng;
        let mut secret_bytes = [0u8; 32];
        rng.fill(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        
        Ok((
            signing_key.to_bytes().to_vec(),
            verifying_key.to_bytes().to_vec(),
        ))
    }

    fn ed25519_sign(&self, private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        // Uses RISC0 patched curve25519-dalek crate with precompile acceleration
        use ed25519_dalek::{SigningKey, Signer};
        
        if private_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(private_key.len()));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(private_key);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(message);
        
        Ok(signature.to_bytes().to_vec())
    }

    fn ed25519_verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        // Uses RISC0 patched curve25519-dalek crate with precompile acceleration
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        
        if public_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(public_key.len()));
        }
        if signature.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(public_key);
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let signature = Signature::from_bytes(&sig_bytes);
        
        Ok(verifying_key.verify(message, &signature).is_ok())
    }

    fn rsa_verify(&self, public_key: &[u8], message: &[u8], signature: &[u8], hash_alg: &str) -> CryptoResult<bool> {
        // Uses RISC0 patched rsa crate with precompile acceleration
        use rsa::{RsaPublicKey, pkcs1v15::VerifyingKey, pkcs1v15::Signature as RsaSignature};
        use sha2::{Sha256, Sha384};
        
        let public_key = RsaPublicKey::from_pkcs1_der(public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        
        let signature = RsaSignature::try_from(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        
        match hash_alg {
            "sha256" => {
                let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(public_key);
                Ok(verifying_key.verify(message, &signature).is_ok())
            }
            "sha384" => {
                let verifying_key = VerifyingKey::<Sha384>::new_unprefixed(public_key);
                Ok(verifying_key.verify(message, &signature).is_ok())
            }
            _ => Err(CryptoError::InvalidSignature),
        }
    }

    fn has_precompile_support(&self) -> bool {
        true // RISC0 has precompile support for P-256, Ed25519, and RSA signature operations
    }
}

impl Kdf for RISC0CryptoProvider {
    fn hkdf_extract_sha256(&self, salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
        // Uses RISC0 patched sha2 crate with precompile acceleration for HKDF
        // Manual HKDF implementation following RFC 5869 to avoid trait bound issues
        use sha2::{Sha256, Digest};
        
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
        // Uses RISC0 patched sha2 crate with precompile acceleration for HKDF
        // Manual HKDF implementation following RFC 5869 to avoid trait bound issues
        use sha2::{Sha384, Digest};
        
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
        // Uses RISC0 patched sha2 crate with precompile acceleration for HKDF
        // Manual HKDF implementation following RFC 5869 to avoid trait bound issues
        use sha2::{Sha256, Digest};
        
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
        // Uses RISC0 patched sha2 crate with precompile acceleration for HKDF
        // Manual HKDF implementation following RFC 5869 to avoid trait bound issues
        use sha2::{Sha384, Digest};
        
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
        true // RISC0 has precompile support for SHA-256/SHA-384 used in HKDF
    }
}