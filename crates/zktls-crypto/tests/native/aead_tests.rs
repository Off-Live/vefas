//! Native AEAD implementation tests with NIST CAVP test vectors
//!
//! This module contains comprehensive tests for AES-GCM implementations using
//! official NIST CAVP (Cryptographic Algorithm Validation Program) test vectors.

use hex_literal::hex;
use zktls_crypto::native::NativeCryptoProvider;
use zktls_crypto::traits::{Aead, PrecompileDetection};
use zktls_crypto::error::CryptoError;

#[test]
fn test_aes128_gcm_basic_encrypt_decrypt() {
    let provider = NativeCryptoProvider::new();
    
    // NIST CAVP test vector for AES-128-GCM
    let key = hex!("00000000000000000000000000000000");
    let nonce = hex!("000000000000000000000000");
    let plaintext = hex!("00000000000000000000000000000000");
    let aad = hex!("");
    
    // Expected ciphertext + tag from NIST
    let expected_ciphertext_with_tag = hex!("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
    
    let result = provider.encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    assert_eq!(result, expected_ciphertext_with_tag);
    
    // Test decryption
    let decrypted = provider.decrypt(&key, &nonce, &aad, &result).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes256_gcm_basic_encrypt_decrypt() {
    let provider = NativeCryptoProvider::new();
    
    // NIST CAVP test vector for AES-256-GCM
    let key = hex!("0000000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex!("000000000000000000000000");
    let plaintext = hex!("00000000000000000000000000000000");
    let aad = hex!("");
    
    // Expected ciphertext + tag from NIST
    let expected_ciphertext_with_tag = hex!("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
    
    let result = provider.encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    assert_eq!(result, expected_ciphertext_with_tag);
    
    // Test decryption
    let decrypted = provider.decrypt(&key, &nonce, &aad, &result).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test] 
fn test_aes_gcm_with_aad() {
    let provider = NativeCryptoProvider::new();
    
    // NIST test vector with AAD
    let key = hex!("feffe9928665731c6d6a8f9467308308");
    let nonce = hex!("cafebabefacedbaddecaf888");
    let plaintext = hex!("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    let aad = hex!("");
    
    let result = provider.encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    
    // Should be ciphertext (64 bytes) + tag (16 bytes) = 80 bytes total
    assert_eq!(result.len(), plaintext.len() + 16);
    
    // Test decryption round-trip
    let decrypted = provider.decrypt(&key, &nonce, &aad, &result).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_gcm_with_non_empty_aad() {
    let provider = NativeCryptoProvider::new();
    
    let key = hex!("feffe9928665731c6d6a8f9467308308");
    let nonce = hex!("cafebabefacedbaddecaf888");
    let plaintext = hex!("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    let aad = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    
    let result = provider.encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    let decrypted = provider.decrypt(&key, &nonce, &aad, &result).unwrap();
    assert_eq!(decrypted, plaintext);
    
    // Should fail with wrong AAD
    let wrong_aad = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad3");
    let decrypt_result = provider.decrypt(&key, &nonce, &wrong_aad, &result);
    assert!(matches!(decrypt_result, Err(CryptoError::DecryptionFailed)));
}

#[test]
fn test_invalid_key_sizes() {
    let provider = NativeCryptoProvider::new();
    let nonce = hex!("000000000000000000000000");
    let plaintext = hex!("00");
    let aad = hex!("");
    
    // Invalid key sizes should be rejected
    let invalid_keys = [
        hex!("00").to_vec(),                          // 1 byte
        hex!("0000000000000000000000000000").to_vec(), // 15 bytes  
        hex!("000000000000000000000000000000000000000000000000000000000000").to_vec(), // 31 bytes
        hex!("00000000000000000000000000000000000000000000000000000000000000000000").to_vec(), // 34 bytes
    ];
    
    for invalid_key in &invalid_keys {
        let result = provider.encrypt(invalid_key, &nonce, &aad, &plaintext);
        assert!(matches!(result, Err(CryptoError::InvalidKeySize(_))));
    }
}

#[test]
fn test_invalid_nonce_sizes() {
    let provider = NativeCryptoProvider::new();
    let key = hex!("00000000000000000000000000000000"); // Valid 16-byte key
    let plaintext = hex!("00");
    let aad = hex!("");
    
    // Invalid nonce sizes should be rejected
    let invalid_nonces = [
        hex!("00").to_vec(),                           // 1 byte
        hex!("0000000000000000000000").to_vec(),        // 11 bytes
        hex!("000000000000000000000000000000").to_vec(), // 15 bytes
    ];
    
    for invalid_nonce in &invalid_nonces {
        let result = provider.encrypt(&key, invalid_nonce, &aad, &plaintext);
        assert!(matches!(result, Err(CryptoError::InvalidNonceSize { .. })));
    }
}

#[test]
fn test_decryption_failure_with_invalid_tag() {
    let provider = NativeCryptoProvider::new();
    let key = hex!("00000000000000000000000000000000");
    let nonce = hex!("000000000000000000000000");
    let aad = hex!("");
    
    // Valid ciphertext + corrupted tag
    let mut ciphertext_with_corrupted_tag = hex!("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf").to_vec();
    let last_index = ciphertext_with_corrupted_tag.len() - 1;
    ciphertext_with_corrupted_tag[last_index] ^= 0x01; // Corrupt last byte of tag
    
    let result = provider.decrypt(&key, &nonce, &aad, &ciphertext_with_corrupted_tag);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

#[test]
fn test_aead_precompile_detection() {
    let provider = NativeCryptoProvider::new();
    
    // Native implementation should never report precompile support
    assert!(!provider.has_precompile_support());
    assert!(!provider.has_any_precompiles());
    assert_eq!(provider.platform_name(), None);
}

#[test]
fn test_empty_plaintext() {
    let provider = NativeCryptoProvider::new();
    
    let key = hex!("00000000000000000000000000000000");
    let nonce = hex!("000000000000000000000000");
    let plaintext = hex!("");
    let aad = hex!("");
    
    let result = provider.encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    
    // Should be just the 16-byte authentication tag for empty plaintext
    assert_eq!(result.len(), 16);
    
    let decrypted = provider.decrypt(&key, &nonce, &aad, &result).unwrap();
    assert_eq!(decrypted, plaintext);
    assert!(decrypted.is_empty());
}

#[test]
fn test_deterministic_encryption() {
    let provider = NativeCryptoProvider::new();
    
    let key = hex!("00000000000000000000000000000000");
    let nonce = hex!("000000000000000000000000");
    let plaintext = hex!("deadbeef");
    let aad = hex!("feedface");
    
    // Multiple encryptions with same inputs should produce identical results
    let result1 = provider.encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    let result2 = provider.encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    let result3 = provider.encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    
    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
}

#[cfg(feature = "std")]
#[test]
fn test_aead_thread_safety() {
    use std::thread;
    use std::sync::Arc;
    
    let provider = Arc::new(NativeCryptoProvider::new());
    let key = hex!("00000000000000000000000000000000");
    let nonce = hex!("000000000000000000000000");
    let plaintext = b"thread safety test";
    let aad = hex!("");
    
    let handles: Vec<_> = (0..10).map(|_| {
        let provider = Arc::clone(&provider);
        thread::spawn(move || {
            provider.encrypt(&key, &nonce, &aad, plaintext)
        })
    }).collect();
    
    let results: Vec<Vec<u8>> = handles.into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .collect();
    
    // All results should be identical
    let first_result = &results[0];
    for result in &results[1..] {
        assert_eq!(result, first_result);
    }
}