//! Production-grade cryptographic trait definitions for VEFAS
//!
//! This module defines separated cryptographic traits that must be implemented
//! by different platforms (host, SP1, RISC0) to provide cryptographic operations
//! for VEFAS zkTLS verification. The architecture follows the zktls-crypto pattern
//! for production-ready implementations.
//!
//! ## Trait Separation
//!
//! - `Hash`: SHA-256, SHA-384 hash functions
//! - `Aead`: AES-GCM, ChaCha20Poly1305 authenticated encryption
//! - `KeyExchange`: X25519, P-256 ECDH key exchange
//! - `Signature`: ECDSA, RSA, Ed25519 signature verification and generation
//! - `Kdf`: HKDF key derivation functions
//! - `PrecompileDetection`: zkVM precompile capability detection
//! - `VefasCrypto`: Combined trait for convenience

use alloc::vec::Vec;

use vefas_types::{VefasError, VefasResult};

// Note: The new trait structure uses standard arrays instead of wrapper types
// for better performance and cleaner API design following zktls-crypto patterns

/// Hash function operations (SHA-256, SHA-384)
///
/// Basic cryptographic hash operations return arrays directly for performance.
/// Only complex operations that can fail return Result<>.
pub trait Hash {
    /// Compute SHA-256 hash of input data
    ///
    /// # Arguments
    /// * `input` - Input data to hash
    ///
    /// # Returns
    /// 32-byte SHA-256 hash output (direct array, no Result wrapper)
    fn sha256(&self, input: &[u8]) -> [u8; 32];

    /// Compute SHA-384 hash of input data
    ///
    /// # Arguments
    /// * `input` - Input data to hash
    ///
    /// # Returns
    /// 48-byte SHA-384 hash output (direct array, no Result wrapper)
    fn sha384(&self, input: &[u8]) -> [u8; 48];

    /// Check if this provider has hardware/precompile support for hashing
    fn has_precompile_support(&self) -> bool {
        false
    }

    /// Compute HMAC-SHA256
    ///
    /// # Arguments
    /// * `key` - HMAC key
    /// * `data` - Data to authenticate
    ///
    /// # Returns
    /// 32-byte HMAC output (direct array)
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32];

    /// Compute HMAC-SHA384
    ///
    /// # Arguments
    /// * `key` - HMAC key
    /// * `data` - Data to authenticate
    ///
    /// # Returns
    /// 48-byte HMAC output (direct array)
    fn hmac_sha384(&self, key: &[u8], data: &[u8]) -> [u8; 48];

    /// Compute SHA-256 of multiple concatenated inputs (optimization)
    ///
    /// # Arguments
    /// * `inputs` - Slice of input data to hash in order
    ///
    /// # Returns
    /// 32-byte SHA-256 hash output
    fn sha256_multi(&self, inputs: &[&[u8]]) -> [u8; 32] {
        let mut combined = Vec::new();
        for input in inputs {
            combined.extend_from_slice(input);
        }
        self.sha256(&combined)
    }
}

/// Authenticated Encryption with Associated Data (AEAD) operations
///
/// Encryption/decryption operations that can fail return Result<>.
/// Basic parameter validation may cause errors.
pub trait Aead {
    /// Encrypt plaintext using AES-128-GCM
    ///
    /// # Arguments
    /// * `key` - 16-byte AES-128 key
    /// * `nonce` - 12-byte nonce
    /// * `aad` - Additional authenticated data
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    /// Ciphertext with 16-byte authentication tag appended
    fn aes_128_gcm_encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> VefasResult<Vec<u8>>;

    /// Decrypt ciphertext using AES-128-GCM
    ///
    /// # Arguments
    /// * `key` - 16-byte AES-128 key
    /// * `nonce` - 12-byte nonce
    /// * `aad` - Additional authenticated data
    /// * `ciphertext` - Ciphertext with authentication tag
    ///
    /// # Returns
    /// Decrypted plaintext if authentication succeeds
    fn aes_128_gcm_decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> VefasResult<Vec<u8>>;

    /// Encrypt plaintext using AES-256-GCM
    ///
    /// # Arguments
    /// * `key` - 32-byte AES-256 key
    /// * `nonce` - 12-byte nonce
    /// * `aad` - Additional authenticated data
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    /// Ciphertext with 16-byte authentication tag appended
    fn aes_256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> VefasResult<Vec<u8>>;

    /// Decrypt ciphertext using AES-256-GCM
    ///
    /// # Arguments
    /// * `key` - 32-byte AES-256 key
    /// * `nonce` - 12-byte nonce
    /// * `aad` - Additional authenticated data
    /// * `ciphertext` - Ciphertext with authentication tag
    ///
    /// # Returns
    /// Decrypted plaintext if authentication succeeds
    fn aes_256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> VefasResult<Vec<u8>>;

    /// Encrypt plaintext using ChaCha20Poly1305
    ///
    /// # Arguments
    /// * `key` - 32-byte ChaCha20 key
    /// * `nonce` - 12-byte nonce
    /// * `aad` - Additional authenticated data
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    /// Ciphertext with 16-byte authentication tag appended
    fn chacha20_poly1305_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> VefasResult<Vec<u8>>;

    /// Decrypt ciphertext using ChaCha20Poly1305
    ///
    /// # Arguments
    /// * `key` - 32-byte ChaCha20 key
    /// * `nonce` - 12-byte nonce
    /// * `aad` - Additional authenticated data
    /// * `ciphertext` - Ciphertext with authentication tag
    ///
    /// # Returns
    /// Decrypted plaintext if authentication succeeds
    fn chacha20_poly1305_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> VefasResult<Vec<u8>>;

    /// Check if this provider has hardware/precompile support for AEAD
    fn has_precompile_support(&self) -> bool {
        false
    }
}

/// Key exchange operations (X25519, P-256 ECDH)
///
/// Key generation and shared secret computation for TLS 1.3.
pub trait KeyExchange {
    /// Generate X25519 key pair
    ///
    /// # Returns
    /// (private_key, public_key) tuple where:
    /// - private_key: 32-byte scalar
    /// - public_key: 32-byte compressed point
    fn x25519_generate_keypair(&self) -> ([u8; 32], [u8; 32]);

    /// Compute X25519 shared secret
    ///
    /// # Arguments
    /// * `private_key` - 32-byte private scalar
    /// * `public_key` - 32-byte peer public key
    ///
    /// # Returns
    /// 32-byte shared secret or error if invalid
    fn x25519_compute_shared_secret(
        &self,
        private_key: &[u8; 32],
        public_key: &[u8; 32],
    ) -> VefasResult<[u8; 32]>;

    /// Generate P-256 ECDH key pair
    ///
    /// # Returns
    /// (private_key, public_key) tuple where:
    /// - private_key: 32-byte scalar
    /// - public_key: 65-byte uncompressed point (0x04 || x || y)
    fn p256_generate_keypair(&self) -> VefasResult<([u8; 32], [u8; 65])>;

    /// Compute P-256 ECDH shared secret
    ///
    /// # Arguments
    /// * `private_key` - 32-byte private scalar
    /// * `public_key` - 65-byte peer public key (uncompressed)
    ///
    /// # Returns
    /// 32-byte shared secret or error if invalid
    fn p256_compute_shared_secret(
        &self,
        private_key: &[u8; 32],
        public_key: &[u8; 65],
    ) -> VefasResult<[u8; 32]>;

    /// Check if this provider has hardware/precompile support for key exchange
    fn has_precompile_support(&self) -> bool {
        false
    }
}

/// Digital signature operations (ECDSA, RSA, Ed25519)
///
/// Signature verification and generation for multiple algorithms.
/// Returns direct boolean for verification, Result<> for generation.
pub trait Signature {
    /// Generate P-256 ECDSA key pair
    ///
    /// # Returns
    /// (private_key, public_key) tuple where:
    /// - private_key: 32-byte scalar
    /// - public_key: 65-byte uncompressed point (0x04 || x || y)
    fn p256_generate_keypair(&self) -> VefasResult<([u8; 32], [u8; 65])>;

    /// Sign message with P-256 ECDSA
    ///
    /// # Arguments
    /// * `private_key` - 32-byte private scalar
    /// * `message` - Message to sign (typically a hash)
    ///
    /// # Returns
    /// DER-encoded ECDSA signature
    fn p256_sign(&self, private_key: &[u8; 32], message: &[u8]) -> VefasResult<Vec<u8>>;

    /// Verify P-256 ECDSA signature
    ///
    /// # Arguments
    /// * `public_key` - 65-byte uncompressed public key (0x04 || x || y)
    /// * `message` - Message that was signed
    /// * `signature` - DER-encoded signature
    ///
    /// # Returns
    /// `true` if signature is valid (direct boolean, no Result wrapper)
    fn p256_verify(&self, public_key: &[u8; 65], message: &[u8], signature: &[u8]) -> bool;

    /// Generate secp256k1 ECDSA key pair
    ///
    /// # Returns
    /// (private_key, public_key) tuple
    fn secp256k1_generate_keypair(&self) -> VefasResult<([u8; 32], [u8; 65])>;

    /// Sign message with secp256k1 ECDSA
    ///
    /// # Arguments
    /// * `private_key` - 32-byte private scalar
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// DER-encoded ECDSA signature
    fn secp256k1_sign(&self, private_key: &[u8; 32], message: &[u8]) -> VefasResult<Vec<u8>>;

    /// Verify secp256k1 ECDSA signature
    ///
    /// # Arguments
    /// * `public_key` - 65-byte uncompressed public key
    /// * `message` - Message that was signed
    /// * `signature` - DER-encoded signature
    ///
    /// # Returns
    /// `true` if signature is valid
    fn secp256k1_verify(&self, public_key: &[u8; 65], message: &[u8], signature: &[u8]) -> bool;

    /// Generate Ed25519 key pair
    ///
    /// # Returns
    /// (private_key, public_key) tuple where:
    /// - private_key: 32-byte seed
    /// - public_key: 32-byte compressed point
    fn ed25519_generate_keypair(&self) -> ([u8; 32], [u8; 32]);

    /// Sign message with Ed25519
    ///
    /// # Arguments
    /// * `private_key` - 32-byte private key seed
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// 64-byte signature
    fn ed25519_sign(&self, private_key: &[u8; 32], message: &[u8]) -> [u8; 64];

    /// Verify Ed25519 signature
    ///
    /// # Arguments
    /// * `public_key` - 32-byte public key
    /// * `message` - Message that was signed
    /// * `signature` - 64-byte signature
    ///
    /// # Returns
    /// `true` if signature is valid
    fn ed25519_verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool;

    /// Generate RSA key pair (2048-bit)
    ///
    /// # Returns
    /// (private_key_der, public_key_der) tuple with DER-encoded keys
    fn rsa_2048_generate_keypair(&self) -> VefasResult<(Vec<u8>, Vec<u8>)>;

    /// Sign message with RSA PKCS#1 v1.5 SHA-256
    ///
    /// # Arguments
    /// * `private_key_der` - DER-encoded RSA private key
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// RSA signature
    fn rsa_pkcs1_sha256_sign(&self, private_key_der: &[u8], message: &[u8])
        -> VefasResult<Vec<u8>>;

    /// Verify RSA PKCS#1 v1.5 SHA-256 signature
    ///
    /// # Arguments
    /// * `public_key_der` - DER-encoded RSA public key
    /// * `message` - Message that was signed
    /// * `signature` - RSA signature
    ///
    /// # Returns
    /// `true` if signature is valid
    fn rsa_pkcs1_sha256_verify(
        &self,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool;

    /// Sign message with RSA PSS SHA-256
    ///
    /// # Arguments
    /// * `private_key_der` - DER-encoded RSA private key
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// RSA signature
    fn rsa_pss_sha256_sign(&self, private_key_der: &[u8], message: &[u8]) -> VefasResult<Vec<u8>>;

    /// Verify RSA PSS SHA-256 signature
    ///
    /// # Arguments
    /// * `public_key_der` - DER-encoded RSA public key
    /// * `message` - Message that was signed
    /// * `signature` - RSA signature
    ///
    /// # Returns
    /// `true` if signature is valid
    fn rsa_pss_sha256_verify(
        &self,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool;

    /// Check if this provider has hardware/precompile support for signatures
    fn has_precompile_support(&self) -> bool {
        false
    }
}

/// Key Derivation Function (KDF) operations
///
/// HKDF and TLS 1.3 key derivation functions following RFC 5869 and RFC 8446.
/// Only operations that can fail return Result<>.
pub trait Kdf {
    /// HKDF-Extract: extract a pseudorandom key from input keying material
    ///
    /// # Arguments
    /// * `salt` - Optional salt value (empty slice for no salt)
    /// * `ikm` - Input keying material
    ///
    /// # Returns
    /// 32-byte pseudorandom key (PRK)
    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> [u8; 32];

    /// HKDF-Expand: expand a pseudorandom key to desired length (SHA-256)
    ///
    /// # Arguments
    /// * `prk` - 32-byte pseudorandom key from HKDF-Extract
    /// * `info` - Context and application specific information
    /// * `length` - Desired output length in bytes (max 8160 for SHA-256)
    ///
    /// # Returns
    /// Output keying material of requested length or error if length too large
    fn hkdf_expand(&self, prk: &[u8; 32], info: &[u8], length: usize) -> VefasResult<Vec<u8>>;

    /// HKDF-Extract for SHA-384: extract a fixed-length pseudorandom key from input keying material
    ///
    /// # Arguments
    /// * `salt` - Optional salt value (can be empty)
    /// * `ikm` - Input keying material
    ///
    /// # Returns
    /// 48-byte pseudorandom key
    fn hkdf_extract_sha384(&self, salt: &[u8], ikm: &[u8]) -> [u8; 48];

    /// HKDF-Expand for SHA-384: expand a pseudorandom key to desired length
    ///
    /// # Arguments
    /// * `prk` - 48-byte pseudorandom key from HKDF-Extract-SHA384
    /// * `info` - Context and application specific information
    /// * `length` - Desired output length in bytes (max 12240 for SHA-384)
    ///
    /// # Returns
    /// Output keying material of requested length or error if length too large
    fn hkdf_expand_sha384(&self, prk: &[u8; 48], info: &[u8], length: usize) -> VefasResult<Vec<u8>>;

    /// HKDF: combined extract-then-expand operation
    ///
    /// # Arguments
    /// * `salt` - Optional salt value
    /// * `ikm` - Input keying material
    /// * `info` - Context and application specific information
    /// * `length` - Desired output length in bytes
    ///
    /// # Returns
    /// Output keying material of requested length
    fn hkdf(&self, salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> VefasResult<Vec<u8>> {
        let prk = self.hkdf_extract(salt, ikm);
        self.hkdf_expand(&prk, info, length)
    }

    /// TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1)
    ///
    /// # Arguments
    /// * `secret` - Input secret
    /// * `label` - TLS 1.3 label (without "tls13 " prefix)
    /// * `context` - Hash of handshake messages
    /// * `length` - Desired output length (max 255 bytes)
    ///
    /// # Returns
    /// Derived traffic secret
    fn hkdf_expand_label(
        &self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: u8,
    ) -> VefasResult<Vec<u8>> {
        // TLS 1.3 HKDF-Expand-Label format per RFC 8446
        let mut hkdf_label = Vec::new();
        hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
        hkdf_label.push(6 + label.len() as u8); // "tls13 " + label length
        hkdf_label.extend_from_slice(b"tls13 ");
        hkdf_label.extend_from_slice(label);
        hkdf_label.push(context.len() as u8);
        hkdf_label.extend_from_slice(context);

        // Extract PRK if needed (for consistency with HKDF)
        let prk = if secret.len() == 32 {
            let mut prk_array = [0u8; 32];
            prk_array.copy_from_slice(secret);
            prk_array
        } else {
            self.hkdf_extract(&[], secret)
        };

        self.hkdf_expand(&prk, &hkdf_label, length as usize)
    }

    /// Derive TLS 1.3 handshake traffic secrets
    ///
    /// # Arguments
    /// * `shared_secret` - ECDH shared secret
    /// * `handshake_hash` - Hash of Client Hello ... Server Hello
    ///
    /// # Returns
    /// (client_handshake_traffic_secret, server_handshake_traffic_secret)
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

    /// Derive TLS 1.3 application traffic secrets
    ///
    /// # Arguments
    /// * `handshake_secret` - Handshake secret from derive_handshake_secrets
    /// * `handshake_hash` - Hash of Client Hello ... Server Finished
    ///
    /// # Returns
    /// (client_application_traffic_secret, server_application_traffic_secret)
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

    /// Check if this provider has hardware/precompile support for KDF
    fn has_precompile_support(&self) -> bool {
        false
    }
}

/// zkVM precompile detection and capability reporting
///
/// Provides information about which cryptographic operations have
/// hardware or precompile acceleration support.
pub trait PrecompileDetection {
    /// Check if SHA-256 has precompile support
    fn has_sha256_precompile(&self) -> bool {
        false
    }

    /// Check if SHA-384 has precompile support
    fn has_sha384_precompile(&self) -> bool {
        false
    }

    /// Check if AES-128-GCM has precompile support
    fn has_aes_128_gcm_precompile(&self) -> bool {
        false
    }

    /// Check if AES-256-GCM has precompile support
    fn has_aes_256_gcm_precompile(&self) -> bool {
        false
    }

    /// Check if ChaCha20Poly1305 has precompile support
    fn has_chacha20_poly1305_precompile(&self) -> bool {
        false
    }

    /// Check if X25519 has precompile support
    fn has_x25519_precompile(&self) -> bool {
        false
    }

    /// Check if P-256 ECDH has precompile support
    fn has_p256_ecdh_precompile(&self) -> bool {
        false
    }

    /// Check if P-256 ECDSA has precompile support
    fn has_p256_ecdsa_precompile(&self) -> bool {
        false
    }

    /// Check if secp256k1 ECDSA has precompile support
    fn has_secp256k1_ecdsa_precompile(&self) -> bool {
        false
    }

    /// Check if Ed25519 has precompile support
    fn has_ed25519_precompile(&self) -> bool {
        false
    }

    /// Check if RSA has precompile support
    fn has_rsa_precompile(&self) -> bool {
        false
    }

    /// Check if HKDF has precompile support
    fn has_hkdf_precompile(&self) -> bool {
        false
    }

    /// Get overall precompile support summary
    fn precompile_summary(&self) -> PrecompileSummary {
        let accelerated_count = [
            self.has_sha256_precompile(),
            self.has_sha384_precompile(),
            self.has_aes_128_gcm_precompile(),
            self.has_aes_256_gcm_precompile(),
            self.has_chacha20_poly1305_precompile(),
            self.has_x25519_precompile(),
            self.has_p256_ecdh_precompile(),
            self.has_p256_ecdsa_precompile(),
            self.has_secp256k1_ecdsa_precompile(),
            self.has_ed25519_precompile(),
            self.has_rsa_precompile(),
            self.has_hkdf_precompile(),
        ]
        .iter()
        .map(|&x| x as u32)
        .sum();

        PrecompileSummary {
            provider_name: "unknown",
            total_operations: 12,
            accelerated_operations: accelerated_count,
        }
    }
}

/// Summary of precompile acceleration support
#[derive(Debug, Clone, Copy)]
pub struct PrecompileSummary {
    /// Name of the cryptographic provider
    pub provider_name: &'static str,
    /// Total number of supported operations
    pub total_operations: u32,
    /// Number of operations with acceleration
    pub accelerated_operations: u32,
}

impl PrecompileSummary {
    /// Calculate acceleration percentage
    pub fn acceleration_percentage(&self) -> f32 {
        if self.total_operations == 0 {
            0.0
        } else {
            (self.accelerated_operations as f32 / self.total_operations as f32) * 100.0
        }
    }
}

/// Combined cryptographic provider trait
///
/// This trait combines all individual cryptographic traits for convenience.
/// Implementations should provide comprehensive cryptographic functionality
/// for TLS 1.3 and related protocols.
pub trait VefasCrypto: Hash + Aead + KeyExchange + Signature + Kdf + PrecompileDetection {
    /// Get the name of this cryptographic provider
    fn provider_name(&self) -> &'static str {
        "unknown"
    }

    /// Get the version of this cryptographic provider
    fn provider_version(&self) -> &'static str {
        "unknown"
    }

    /// Check if this provider supports hardware acceleration
    fn supports_hardware_acceleration(&self) -> bool {
        false
    }

    /// Check if this provider supports zkVM precompiles
    fn supports_zkvm_precompiles(&self) -> bool {
        self.precompile_summary().accelerated_operations > 0
    }

    /// Get detailed precompile information
    fn get_precompile_info(&self) -> PrecompileSummary {
        PrecompileSummary {
            provider_name: self.provider_name(),
            ..self.precompile_summary()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // Mock implementation for testing new trait structure
    struct MockCrypto;

    impl Hash for MockCrypto {
        fn sha256(&self, _input: &[u8]) -> [u8; 32] {
            [0u8; 32]
        }

        fn sha384(&self, _input: &[u8]) -> [u8; 48] {
            [0u8; 48]
        }

        fn hmac_sha256(&self, _key: &[u8], _data: &[u8]) -> [u8; 32] {
            [0u8; 32]
        }

        fn hmac_sha384(&self, _key: &[u8], _data: &[u8]) -> [u8; 48] {
            [0u8; 48]
        }
    }

    impl Aead for MockCrypto {
        fn aes_128_gcm_encrypt(
            &self,
            _key: &[u8; 16],
            _nonce: &[u8; 12],
            _aad: &[u8],
            plaintext: &[u8],
        ) -> VefasResult<Vec<u8>> {
            Ok(vec![0u8; plaintext.len() + 16])
        }

        fn aes_128_gcm_decrypt(
            &self,
            _key: &[u8; 16],
            _nonce: &[u8; 12],
            _aad: &[u8],
            ciphertext: &[u8],
        ) -> VefasResult<Vec<u8>> {
            if ciphertext.len() < 16 {
                return Err(VefasError::crypto_error(
                    vefas_types::errors::CryptoErrorType::CipherFailed,
                    "ciphertext too short",
                ));
            }
            Ok(vec![0u8; ciphertext.len() - 16])
        }

        fn aes_256_gcm_encrypt(
            &self,
            _key: &[u8; 32],
            _nonce: &[u8; 12],
            _aad: &[u8],
            plaintext: &[u8],
        ) -> VefasResult<Vec<u8>> {
            Ok(vec![0u8; plaintext.len() + 16])
        }

        fn aes_256_gcm_decrypt(
            &self,
            _key: &[u8; 32],
            _nonce: &[u8; 12],
            _aad: &[u8],
            ciphertext: &[u8],
        ) -> VefasResult<Vec<u8>> {
            if ciphertext.len() < 16 {
                return Err(VefasError::crypto_error(
                    vefas_types::errors::CryptoErrorType::CipherFailed,
                    "ciphertext too short",
                ));
            }
            Ok(vec![0u8; ciphertext.len() - 16])
        }

        fn chacha20_poly1305_encrypt(
            &self,
            _key: &[u8; 32],
            _nonce: &[u8; 12],
            _aad: &[u8],
            plaintext: &[u8],
        ) -> VefasResult<Vec<u8>> {
            Ok(vec![0u8; plaintext.len() + 16])
        }

        fn chacha20_poly1305_decrypt(
            &self,
            _key: &[u8; 32],
            _nonce: &[u8; 12],
            _aad: &[u8],
            ciphertext: &[u8],
        ) -> VefasResult<Vec<u8>> {
            if ciphertext.len() < 16 {
                return Err(VefasError::crypto_error(
                    vefas_types::errors::CryptoErrorType::CipherFailed,
                    "ciphertext too short",
                ));
            }
            Ok(vec![0u8; ciphertext.len() - 16])
        }
    }

    impl KeyExchange for MockCrypto {
        fn x25519_generate_keypair(&self) -> ([u8; 32], [u8; 32]) {
            ([1u8; 32], [2u8; 32])
        }

        fn x25519_compute_shared_secret(
            &self,
            _private_key: &[u8; 32],
            _public_key: &[u8; 32],
        ) -> VefasResult<[u8; 32]> {
            Ok([3u8; 32])
        }

        fn p256_generate_keypair(&self) -> VefasResult<([u8; 32], [u8; 65])> {
            let mut public_key = [0u8; 65];
            public_key[0] = 0x04; // Uncompressed point marker
            Ok(([1u8; 32], public_key))
        }

        fn p256_compute_shared_secret(
            &self,
            _private_key: &[u8; 32],
            _public_key: &[u8; 65],
        ) -> VefasResult<[u8; 32]> {
            Ok([3u8; 32])
        }
    }

    impl Signature for MockCrypto {
        fn p256_generate_keypair(&self) -> VefasResult<([u8; 32], [u8; 65])> {
            let mut public_key = [0u8; 65];
            public_key[0] = 0x04;
            Ok(([1u8; 32], public_key))
        }

        fn p256_sign(&self, _private_key: &[u8; 32], _message: &[u8]) -> VefasResult<Vec<u8>> {
            Ok(vec![0u8; 64])
        }

        fn p256_verify(&self, _public_key: &[u8; 65], _message: &[u8], _signature: &[u8]) -> bool {
            true
        }

        fn secp256k1_generate_keypair(&self) -> VefasResult<([u8; 32], [u8; 65])> {
            let mut public_key = [0u8; 65];
            public_key[0] = 0x04;
            Ok(([1u8; 32], public_key))
        }

        fn secp256k1_sign(&self, _private_key: &[u8; 32], _message: &[u8]) -> VefasResult<Vec<u8>> {
            Ok(vec![0u8; 64])
        }

        fn secp256k1_verify(
            &self,
            _public_key: &[u8; 65],
            _message: &[u8],
            _signature: &[u8],
        ) -> bool {
            true
        }

        fn ed25519_generate_keypair(&self) -> ([u8; 32], [u8; 32]) {
            ([1u8; 32], [2u8; 32])
        }

        fn ed25519_sign(&self, _private_key: &[u8; 32], _message: &[u8]) -> [u8; 64] {
            [0u8; 64]
        }

        fn ed25519_verify(
            &self,
            _public_key: &[u8; 32],
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> bool {
            true
        }

        fn rsa_2048_generate_keypair(&self) -> VefasResult<(Vec<u8>, Vec<u8>)> {
            Ok((vec![0u8; 256], vec![0u8; 256]))
        }

        fn rsa_pkcs1_sha256_sign(
            &self,
            _private_key_der: &[u8],
            _message: &[u8],
        ) -> VefasResult<Vec<u8>> {
            Ok(vec![0u8; 256])
        }

        fn rsa_pkcs1_sha256_verify(
            &self,
            _public_key_der: &[u8],
            _message: &[u8],
            _signature: &[u8],
        ) -> bool {
            true
        }

        fn rsa_pss_sha256_sign(
            &self,
            _private_key_der: &[u8],
            _message: &[u8],
        ) -> VefasResult<Vec<u8>> {
            Ok(vec![0u8; 256])
        }

        fn rsa_pss_sha256_verify(
            &self,
            _public_key_der: &[u8],
            _message: &[u8],
            _signature: &[u8],
        ) -> bool {
            true
        }
    }

    impl Kdf for MockCrypto {
        fn hkdf_extract(&self, _salt: &[u8], _ikm: &[u8]) -> [u8; 32] {
            [0u8; 32]
        }

        fn hkdf_expand(
            &self,
            _prk: &[u8; 32],
            _info: &[u8],
            length: usize,
        ) -> VefasResult<Vec<u8>> {
            Ok(vec![0u8; length])
        }

        fn hkdf_extract_sha384(&self, _salt: &[u8], _ikm: &[u8]) -> [u8; 48] {
            [0u8; 48]
        }

        fn hkdf_expand_sha384(
            &self,
            _prk: &[u8; 48],
            _info: &[u8],
            length: usize,
        ) -> VefasResult<Vec<u8>> {
            Ok(vec![0u8; length])
        }
    }

    impl PrecompileDetection for MockCrypto {
        // All defaults (false) - no precompile support in mock
    }

    impl VefasCrypto for MockCrypto {
        fn provider_name(&self) -> &'static str {
            "mock"
        }

        fn provider_version(&self) -> &'static str {
            "test"
        }
    }

    #[test]
    fn test_hash_operations() {
        let crypto = MockCrypto;
        let data = b"hello world";

        let sha256_result = crypto.sha256(data);
        assert_eq!(sha256_result.len(), 32);

        let sha384_result = crypto.sha384(data);
        assert_eq!(sha384_result.len(), 48);

        let hmac_result = crypto.hmac_sha256(b"key", data);
        assert_eq!(hmac_result.len(), 32);

        let multi_result = crypto.sha256_multi(&[b"hello", b"world"]);
        assert_eq!(multi_result.len(), 32);
    }

    #[test]
    fn test_aead_operations() {
        let crypto = MockCrypto;
        let plaintext = b"hello world";
        let key_128 = [0u8; 16];
        let key_256 = [0u8; 32];
        let nonce = [0u8; 12];

        // AES-128-GCM
        let ciphertext_128 = crypto
            .aes_128_gcm_encrypt(&key_128, &nonce, b"", plaintext)
            .unwrap();
        assert!(ciphertext_128.len() >= plaintext.len() + 16);

        let decrypted_128 = crypto
            .aes_128_gcm_decrypt(&key_128, &nonce, b"", &ciphertext_128)
            .unwrap();
        assert_eq!(decrypted_128.len(), plaintext.len());

        // AES-256-GCM
        let ciphertext_256 = crypto
            .aes_256_gcm_encrypt(&key_256, &nonce, b"", plaintext)
            .unwrap();
        assert!(ciphertext_256.len() >= plaintext.len() + 16);

        let decrypted_256 = crypto
            .aes_256_gcm_decrypt(&key_256, &nonce, b"", &ciphertext_256)
            .unwrap();
        assert_eq!(decrypted_256.len(), plaintext.len());

        // ChaCha20Poly1305
        let ciphertext_chacha = crypto
            .chacha20_poly1305_encrypt(&key_256, &nonce, b"", plaintext)
            .unwrap();
        assert!(ciphertext_chacha.len() >= plaintext.len() + 16);

        let decrypted_chacha = crypto
            .chacha20_poly1305_decrypt(&key_256, &nonce, b"", &ciphertext_chacha)
            .unwrap();
        assert_eq!(decrypted_chacha.len(), plaintext.len());
    }

    #[test]
    fn test_key_exchange() {
        let crypto = MockCrypto;

        // X25519
        let (x25519_private, x25519_public) = crypto.x25519_generate_keypair();
        assert_eq!(x25519_private.len(), 32);
        assert_eq!(x25519_public.len(), 32);

        let x25519_shared = crypto
            .x25519_compute_shared_secret(&x25519_private, &x25519_public)
            .unwrap();
        assert_eq!(x25519_shared.len(), 32);

        // P-256
        let (p256_private, p256_public) = KeyExchange::p256_generate_keypair(&crypto).unwrap();
        assert_eq!(p256_private.len(), 32);
        assert_eq!(p256_public.len(), 65);
        assert_eq!(p256_public[0], 0x04); // Uncompressed point marker

        let p256_shared = crypto
            .p256_compute_shared_secret(&p256_private, &p256_public)
            .unwrap();
        assert_eq!(p256_shared.len(), 32);
    }

    #[test]
    fn test_signatures() {
        let crypto = MockCrypto;
        let message = b"test message";

        // P-256 ECDSA
        let (p256_private, p256_public) = Signature::p256_generate_keypair(&crypto).unwrap();
        let p256_signature = crypto.p256_sign(&p256_private, message).unwrap();
        assert!(crypto.p256_verify(&p256_public, message, &p256_signature));

        // secp256k1 ECDSA
        let (secp256k1_private, secp256k1_public) = crypto.secp256k1_generate_keypair().unwrap();
        let secp256k1_signature = crypto.secp256k1_sign(&secp256k1_private, message).unwrap();
        assert!(crypto.secp256k1_verify(&secp256k1_public, message, &secp256k1_signature));

        // Ed25519
        let (ed25519_private, ed25519_public) = crypto.ed25519_generate_keypair();
        let ed25519_signature = crypto.ed25519_sign(&ed25519_private, message);
        assert!(crypto.ed25519_verify(&ed25519_public, message, &ed25519_signature));

        // RSA
        let (rsa_private, rsa_public) = crypto.rsa_2048_generate_keypair().unwrap();
        let rsa_pkcs1_signature = crypto.rsa_pkcs1_sha256_sign(&rsa_private, message).unwrap();
        assert!(crypto.rsa_pkcs1_sha256_verify(&rsa_public, message, &rsa_pkcs1_signature));

        let rsa_pss_signature = crypto.rsa_pss_sha256_sign(&rsa_private, message).unwrap();
        assert!(crypto.rsa_pss_sha256_verify(&rsa_public, message, &rsa_pss_signature));
    }

    #[test]
    fn test_kdf_operations() {
        let crypto = MockCrypto;
        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"context info";

        let prk = crypto.hkdf_extract(salt, ikm);
        assert_eq!(prk.len(), 32);

        let okm = crypto.hkdf_expand(&prk, info, 42).unwrap();
        assert_eq!(okm.len(), 42);

        let combined = crypto.hkdf(salt, ikm, info, 64).unwrap();
        assert_eq!(combined.len(), 64);

        let tls13_secret = crypto
            .hkdf_expand_label(&prk, b"c hs traffic", &[0u8; 32], 32)
            .unwrap();
        assert_eq!(tls13_secret.len(), 32);

        let (client_hs, server_hs) = crypto
            .derive_handshake_secrets(&[0u8; 32], &[0u8; 32])
            .unwrap();
        assert_eq!(client_hs.len(), 32);
        assert_eq!(server_hs.len(), 32);

        let (client_app, server_app) = crypto.derive_application_secrets(&prk, &[0u8; 32]).unwrap();
        assert_eq!(client_app.len(), 32);
        assert_eq!(server_app.len(), 32);
    }

    #[test]
    fn test_precompile_detection() {
        let crypto = MockCrypto;

        // Mock has no precompile support
        assert!(!crypto.has_sha256_precompile());
        assert!(!crypto.has_aes_128_gcm_precompile());
        assert!(!crypto.has_p256_ecdsa_precompile());

        let summary = crypto.precompile_summary();
        assert_eq!(summary.total_operations, 12);
        assert_eq!(summary.accelerated_operations, 0);
        assert_eq!(summary.acceleration_percentage(), 0.0);
    }

    #[test]
    fn test_vefas_crypto_trait() {
        let crypto = MockCrypto;

        assert_eq!(crypto.provider_name(), "mock");
        assert_eq!(crypto.provider_version(), "test");
        assert!(!crypto.supports_hardware_acceleration());
        assert!(!crypto.supports_zkvm_precompiles());

        let info = crypto.get_precompile_info();
        assert_eq!(info.provider_name, "mock");
        assert_eq!(info.accelerated_operations, 0);
    }
}
