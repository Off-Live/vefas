//! Core crypto implementation tests for TLS 1.3 cipher suites
//!
//! Tests cover cryptographic operations for all three core cipher suites:
//! - TLS_AES_128_GCM_SHA256
//! - TLS_AES_256_GCM_SHA384  
//! - TLS_CHACHA20_POLY1305_SHA256

use vefas_crypto_risc0::RISC0CryptoProvider;
use vefas_crypto::traits::{Aead, Hash, KeyExchange};
use vefas_types::tls::{CipherSuite, HashAlgorithm, AeadAlgorithm};
use rand::RngCore;

/// Helper function to generate random bytes
fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

#[test]
fn test_cipher_suite_aead_encryption_decryption() {
    let crypto = RISC0CryptoProvider::new();
    
    // Test data
    let plaintext = b"Hello, TLS 1.3!";
    let aad = b"additional authenticated data";
    
    // Test AES-128-GCM
    let key_128: [u8; 16] = generate_random_bytes(16).try_into().unwrap();
    let iv: [u8; 12] = generate_random_bytes(12).try_into().unwrap();
    
    let ciphertext = crypto.aes_128_gcm_encrypt(&key_128, &iv, aad, plaintext).unwrap();
    let decrypted = crypto.aes_128_gcm_decrypt(&key_128, &iv, aad, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
    
    // Test AES-256-GCM
    let key_256: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
    
    let ciphertext = crypto.aes_256_gcm_encrypt(&key_256, &iv, aad, plaintext).unwrap();
    let decrypted = crypto.aes_256_gcm_decrypt(&key_256, &iv, aad, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
    
    // Test ChaCha20-Poly1305
    let ciphertext = crypto.chacha20_poly1305_encrypt(&key_256, &iv, aad, plaintext).unwrap();
    let decrypted = crypto.chacha20_poly1305_decrypt(&key_256, &iv, aad, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_cipher_suite_hash_algorithms() {
    let crypto = RISC0CryptoProvider::new();
    
    let test_data = b"Test data for hash algorithms";
    
    // Test SHA-256 (used by AES-128-GCM and ChaCha20-Poly1305)
    let sha256_hash = crypto.sha256(test_data);
    assert_eq!(sha256_hash.len(), 32);
    
    // Test SHA-384 (used by AES-256-GCM)
    let sha384_hash = crypto.sha384(test_data);
    assert_eq!(sha384_hash.len(), 48);
    
    // Verify hash algorithms match cipher suite expectations
    assert_eq!(CipherSuite::Aes128GcmSha256.hash_algorithm(), HashAlgorithm::Sha256);
    assert_eq!(CipherSuite::Aes256GcmSha384.hash_algorithm(), HashAlgorithm::Sha384);
    assert_eq!(CipherSuite::ChaCha20Poly1305Sha256.hash_algorithm(), HashAlgorithm::Sha256);
}

#[test]
fn test_cipher_suite_key_exchange() {
    let crypto = RISC0CryptoProvider::new();
    
    // Test X25519 key exchange (commonly used with TLS 1.3)
    let (alice_private, alice_public) = crypto.x25519_generate_keypair();
    let (bob_private, bob_public) = crypto.x25519_generate_keypair();
    
    let alice_shared = crypto.x25519_compute_shared_secret(&alice_private, &bob_public);
    let bob_shared = crypto.x25519_compute_shared_secret(&bob_private, &alice_public);
    
    assert!(alice_shared.is_ok());
    assert!(bob_shared.is_ok());
    
    let alice_shared = alice_shared.unwrap();
    let bob_shared = bob_shared.unwrap();
    
    assert_eq!(alice_shared, bob_shared, "X25519 shared secrets should match");
    assert_eq!(alice_shared.len(), 32, "X25519 shared secret should be 32 bytes");
}

#[test]
fn test_cipher_suite_authentication_failure() {
    let crypto = RISC0CryptoProvider::new();
    
    let plaintext = b"Secret message";
    let aad = b"authenticated data";
    let wrong_aad = b"wrong authenticated data";
    
    let key: [u8; 16] = generate_random_bytes(16).try_into().unwrap();
    let iv: [u8; 12] = generate_random_bytes(12).try_into().unwrap();
    
    // Encrypt with correct AAD
    let ciphertext = crypto.aes_128_gcm_encrypt(&key, &iv, aad, plaintext).unwrap();
    
    // Try to decrypt with wrong AAD - should fail
    let result = crypto.aes_128_gcm_decrypt(&key, &iv, wrong_aad, &ciphertext);
    assert!(result.is_err(), "Authentication should fail with wrong AAD");
}

#[test]
fn test_cipher_suite_properties() {
    // Test comprehensive properties for each cipher suite
    let test_cases = vec![
        (
            CipherSuite::Aes128GcmSha256,
            "TLS_AES_128_GCM_SHA256",
            0x1301,
            HashAlgorithm::Sha256,
            AeadAlgorithm::Aes128Gcm,
            16,
            12,
        ),
        (
            CipherSuite::Aes256GcmSha384,
            "TLS_AES_256_GCM_SHA384",
            0x1302,
            HashAlgorithm::Sha384,
            AeadAlgorithm::Aes256Gcm,
            32,
            12,
        ),
        (
            CipherSuite::ChaCha20Poly1305Sha256,
            "TLS_CHACHA20_POLY1305_SHA256",
            0x1303,
            HashAlgorithm::Sha256,
            AeadAlgorithm::ChaCha20Poly1305,
            32,
            12,
        ),
    ];
    
    for (suite, expected_str, expected_wire, expected_hash, expected_aead, expected_key_len, expected_iv_len) in test_cases {
        assert_eq!(suite.as_str(), expected_str);
        assert_eq!(suite.wire_format(), expected_wire);
        assert_eq!(suite.hash_algorithm(), expected_hash);
        assert_eq!(suite.aead_algorithm(), expected_aead);
        assert_eq!(suite.key_length(), expected_key_len);
        assert_eq!(suite.iv_length(), expected_iv_len);
        assert!(!suite.is_deprecated());
    }
}

#[test]
fn test_cipher_suite_roundtrip_serialization() {
    use serde_json;
    
    let suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
    ];
    
    for suite in suites {
        // Test JSON serialization/deserialization
        let json = serde_json::to_string(&suite).unwrap();
        let deserialized: CipherSuite = serde_json::from_str(&json).unwrap();
        assert_eq!(suite, deserialized);
        
        // Test wire format roundtrip
        let wire_format = suite.wire_format();
        let from_wire = CipherSuite::from_wire_format(wire_format).unwrap();
        assert_eq!(suite, from_wire);
    }
}