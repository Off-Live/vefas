//! Native AEAD implementations using aes-gcm crate
//!
//! This module provides AES-GCM AEAD encryption and decryption using the well-tested
//! `aes-gcm` crate. It supports both AES-128-GCM and AES-256-GCM as used in TLS 1.3.
//!
//! # Security
//!
//! All implementations use constant-time algorithms and are resistant to timing attacks.
//! The `aes-gcm` crate has been extensively audited and is used throughout the Rust
//! cryptographic ecosystem.
//!
//! # Performance
//!
//! These implementations automatically benefit from hardware acceleration (e.g., AES-NI
//! and CLMUL instructions) when available on the target platform.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use crate::error::{CryptoResult, CryptoError, IntoCryptoError};

#[cfg(feature = "no_std")]
use alloc::vec::Vec;

/// Encrypt plaintext with AES-GCM
///
/// Automatically selects AES-128-GCM or AES-256-GCM based on key size.
/// Returns ciphertext with authentication tag appended.
///
/// # Arguments
/// * `key` - Encryption key (16 bytes for AES-128, 32 bytes for AES-256)
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
/// use zktls_crypto::native::aead::encrypt;
///
/// let key = &[0u8; 32]; // AES-256 key
/// let nonce = &[0u8; 12];
/// let ciphertext = encrypt(key, nonce, b"aad", b"plaintext")?;
/// # Ok::<(), zktls_crypto::error::CryptoError>(())
/// ```
pub fn encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    // Validate nonce size (must be exactly 12 bytes for GCM)
    if nonce.len() != 12 {
        return Err(CryptoError::invalid_nonce_size(12, nonce.len()));
    }
    
    let nonce = Nonce::try_from(nonce).map_err(|_| CryptoError::invalid_nonce_size(12, nonce.len()))?;
    
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    
    match key.len() {
        16 => {
            // AES-128-GCM
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKeySize(key.len()))?;
            
            cipher.encrypt(&nonce, payload)
                .into_crypto_error()
        }
        32 => {
            // AES-256-GCM
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKeySize(key.len()))?;
            
            cipher.encrypt(&nonce, payload)
                .into_crypto_error()
        }
        _ => Err(CryptoError::InvalidKeySize(key.len()))
    }
}

/// Decrypt ciphertext with AES-GCM
///
/// Automatically selects AES-128-GCM or AES-256-GCM based on key size.
/// Verifies authentication tag and returns decrypted plaintext.
///
/// # Arguments
/// * `key` - Decryption key (16 bytes for AES-128, 32 bytes for AES-256)
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
///
/// # Example
/// ```rust
/// use zktls_crypto::native::aead::{encrypt, decrypt};
///
/// let key = &[0u8; 32];
/// let nonce = &[0u8; 12];
/// let ciphertext = encrypt(key, nonce, b"aad", b"plaintext")?;
/// let plaintext = decrypt(key, nonce, b"aad", &ciphertext)?;
/// # Ok::<(), zktls_crypto::error::CryptoError>(())
/// ```
pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    // Validate nonce size (must be exactly 12 bytes for GCM)
    if nonce.len() != 12 {
        return Err(CryptoError::invalid_nonce_size(12, nonce.len()));
    }
    
    let nonce = Nonce::try_from(nonce).map_err(|_| CryptoError::invalid_nonce_size(12, nonce.len()))?;
    
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    
    match key.len() {
        16 => {
            // AES-128-GCM
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKeySize(key.len()))?;
            
            cipher.decrypt(&nonce, payload)
                .into_crypto_error()
        }
        32 => {
            // AES-256-GCM
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKeySize(key.len()))?;
            
            cipher.decrypt(&nonce, payload)
                .into_crypto_error()
        }
        _ => Err(CryptoError::InvalidKeySize(key.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_basic_aes128_gcm() {
        let key = hex!("00000000000000000000000000000000");
        let nonce = hex!("000000000000000000000000");
        let plaintext = hex!("00000000000000000000000000000000");
        let aad = hex!("");
        
        let ciphertext = encrypt(&key, &nonce, &aad, &plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &aad, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // 16-byte tag
    }
    
    #[test]
    fn test_basic_aes256_gcm() {
        let key = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("000000000000000000000000");
        let plaintext = hex!("00000000000000000000000000000000");
        let aad = hex!("");
        
        let ciphertext = encrypt(&key, &nonce, &aad, &plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &aad, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // 16-byte tag
    }
    
    #[test]
    fn test_invalid_key_size() {
        let key = hex!("000000000000000000000000000000"); // 15 bytes
        let nonce = hex!("000000000000000000000000");
        let plaintext = hex!("00");
        let aad = hex!("");
        
        let result = encrypt(&key, &nonce, &aad, &plaintext);
        assert!(matches!(result, Err(CryptoError::InvalidKeySize(15))));
    }
    
    #[test]
    fn test_invalid_nonce_size() {
        let key = hex!("00000000000000000000000000000000"); // Valid 16-byte key
        let nonce = hex!("0000000000000000000000"); // 11 bytes instead of 12
        let plaintext = hex!("00");
        let aad = hex!("");
        
        let result = encrypt(&key, &nonce, &aad, &plaintext);
        assert!(matches!(result, Err(CryptoError::InvalidNonceSize { expected: 12, actual: 11 })));
    }
    
    #[test]
    fn test_empty_plaintext() {
        let key = hex!("00000000000000000000000000000000");
        let nonce = hex!("000000000000000000000000");
        let plaintext = hex!("");
        let aad = hex!("");
        
        let ciphertext = encrypt(&key, &nonce, &aad, &plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &aad, &ciphertext).unwrap();
        
        assert!(decrypted.is_empty());
        assert_eq!(ciphertext.len(), 16); // Just the authentication tag
    }
    
    #[test]
    fn test_aad_integrity() {
        let key = hex!("00000000000000000000000000000000");
        let nonce = hex!("000000000000000000000000");
        let plaintext = hex!("deadbeef");
        let aad = hex!("feedface");
        
        let ciphertext = encrypt(&key, &nonce, &aad, &plaintext).unwrap();
        
        // Should decrypt successfully with correct AAD
        let decrypted = decrypt(&key, &nonce, &aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
        
        // Should fail with wrong AAD
        let wrong_aad = hex!("feedfacf");
        let result = decrypt(&key, &nonce, &wrong_aad, &ciphertext);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }
}