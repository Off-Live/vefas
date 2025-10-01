//! Authenticated Encryption with Associated Data (AEAD) implementations
//!
//! This module provides production-grade implementations of AEAD ciphers
//! including AES-128-GCM, AES-256-GCM, and ChaCha20Poly1305.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce as ChaNonce};
use vefas_types::{errors::CryptoErrorType, VefasError, VefasResult};

/// Encrypt data using AES-128-GCM
///
/// # Arguments
/// * `key` - 16-byte AES-128 key
/// * `nonce` - 12-byte nonce
/// * `aad` - Additional authenticated data
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Ciphertext with 16-byte authentication tag appended
///
/// # Errors
/// Returns error if encryption fails or parameters are invalid
pub fn aes_128_gcm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> VefasResult<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| {
        VefasError::crypto_error(CryptoErrorType::InvalidKeyLength, "invalid AES-128 key")
    })?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| {
            VefasError::crypto_error(
                CryptoErrorType::CipherFailed,
                "AES-128-GCM encryption failed",
            )
        })
}

/// Decrypt data using AES-128-GCM
///
/// # Arguments
/// * `key` - 16-byte AES-128 key
/// * `nonce` - 12-byte nonce
/// * `aad` - Additional authenticated data
/// * `ciphertext` - Ciphertext with authentication tag
///
/// # Returns
/// Decrypted plaintext if authentication succeeds
///
/// # Errors
/// Returns error if decryption or authentication fails
pub fn aes_128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> VefasResult<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| {
        VefasError::crypto_error(CryptoErrorType::InvalidKeyLength, "invalid AES-128 key")
    })?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            VefasError::crypto_error(
                CryptoErrorType::CipherFailed,
                "AES-128-GCM decryption failed",
            )
        })
}

/// Encrypt data using AES-256-GCM
///
/// # Arguments
/// * `key` - 32-byte AES-256 key
/// * `nonce` - 12-byte nonce
/// * `aad` - Additional authenticated data
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Ciphertext with 16-byte authentication tag appended
///
/// # Errors
/// Returns error if encryption fails or parameters are invalid
pub fn aes_256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> VefasResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
        VefasError::crypto_error(CryptoErrorType::InvalidKeyLength, "invalid AES-256 key")
    })?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| {
            VefasError::crypto_error(
                CryptoErrorType::CipherFailed,
                "AES-256-GCM encryption failed",
            )
        })
}

/// Decrypt data using AES-256-GCM
///
/// # Arguments
/// * `key` - 32-byte AES-256 key
/// * `nonce` - 12-byte nonce
/// * `aad` - Additional authenticated data
/// * `ciphertext` - Ciphertext with authentication tag
///
/// # Returns
/// Decrypted plaintext if authentication succeeds
///
/// # Errors
/// Returns error if decryption or authentication fails
pub fn aes_256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> VefasResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
        VefasError::crypto_error(CryptoErrorType::InvalidKeyLength, "invalid AES-256 key")
    })?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            VefasError::crypto_error(
                CryptoErrorType::CipherFailed,
                "AES-256-GCM decryption failed",
            )
        })
}

/// Encrypt data using ChaCha20Poly1305
///
/// # Arguments
/// * `key` - 32-byte ChaCha20 key
/// * `nonce` - 12-byte nonce
/// * `aad` - Additional authenticated data
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Ciphertext with 16-byte authentication tag appended
///
/// # Errors
/// Returns error if encryption fails or parameters are invalid
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> VefasResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaNonce::from_slice(nonce);

    cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| {
            VefasError::crypto_error(
                CryptoErrorType::CipherFailed,
                "ChaCha20Poly1305 encryption failed",
            )
        })
}

/// Decrypt data using ChaCha20Poly1305
///
/// # Arguments
/// * `key` - 32-byte ChaCha20 key
/// * `nonce` - 12-byte nonce
/// * `aad` - Additional authenticated data
/// * `ciphertext` - Ciphertext with authentication tag
///
/// # Returns
/// Decrypted plaintext if authentication succeeds
///
/// # Errors
/// Returns error if decryption or authentication fails
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> VefasResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaNonce::from_slice(nonce);

    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            VefasError::crypto_error(
                CryptoErrorType::CipherFailed,
                "ChaCha20Poly1305 decryption failed",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_gcm_encrypt_decrypt() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"hello world";
        let aad = b"associated data";

        let ciphertext = aes_128_gcm_encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for auth tag

        let decrypted = aes_128_gcm_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_256_gcm_encrypt_decrypt() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"hello world from AES-256-GCM";
        let aad = b"";

        let ciphertext = aes_256_gcm_encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for auth tag

        let decrypted = aes_256_gcm_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_encrypt_decrypt() {
        let key = [3u8; 32];
        let nonce = [4u8; 12];
        let plaintext = b"hello world from ChaCha20Poly1305";
        let aad = b"additional authenticated data";

        let ciphertext = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for auth tag

        let decrypted = chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_authentication_failure() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"hello world";
        let aad = b"aad";

        let mut ciphertext = aes_128_gcm_encrypt(&key, &nonce, aad, plaintext).unwrap();

        // Corrupt the authentication tag
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0x01;

        let result = aes_128_gcm_decrypt(&key, &nonce, aad, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20_poly1305_authentication_failure() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"hello world";
        let aad = b"aad";

        let mut ciphertext = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext).unwrap();

        // Corrupt the authentication tag
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0x01;

        let result = chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_affects_authentication() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"hello world";
        let aad1 = b"aad1";
        let aad2 = b"aad2";

        let ciphertext = aes_128_gcm_encrypt(&key, &nonce, aad1, plaintext).unwrap();

        // Decryption with different AAD should fail
        let result = aes_128_gcm_decrypt(&key, &nonce, aad2, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"";
        let aad = b"empty plaintext test";

        let ciphertext = aes_256_gcm_encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), 16); // Only auth tag

        let decrypted = aes_256_gcm_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = [5u8; 32];
        let nonce = [6u8; 12];
        let plaintext = vec![7u8; 1024 * 1024]; // 1MB
        let aad = b"large data test";

        let ciphertext = chacha20_poly1305_encrypt(&key, &nonce, aad, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
