//! Comprehensive tests for TLS 1.3 cipher suites
//!
//! Tests cover all three core cipher suites:
//! - TLS_AES_128_GCM_SHA256
//! - TLS_AES_256_GCM_SHA384  
//! - TLS_CHACHA20_POLY1305_SHA256

use vefas_types::tls::{CipherSuite, HashAlgorithm, AeadAlgorithm};

#[test]
fn test_cipher_suite_wire_formats() {
    // Test wire format encoding
    assert_eq!(CipherSuite::Aes128GcmSha256.wire_format(), 0x1301);
    assert_eq!(CipherSuite::Aes256GcmSha384.wire_format(), 0x1302);
    assert_eq!(CipherSuite::ChaCha20Poly1305Sha256.wire_format(), 0x1303);
}

#[test]
fn test_cipher_suite_from_wire_format() {
    // Test wire format decoding
    assert_eq!(CipherSuite::from_wire_format(0x1301).unwrap(), CipherSuite::Aes128GcmSha256);
    assert_eq!(CipherSuite::from_wire_format(0x1302).unwrap(), CipherSuite::Aes256GcmSha384);
    assert_eq!(CipherSuite::from_wire_format(0x1303).unwrap(), CipherSuite::ChaCha20Poly1305Sha256);
    
    // Test invalid wire format
    assert!(CipherSuite::from_wire_format(0x1304).is_err());
    assert!(CipherSuite::from_wire_format(0x0000).is_err());
}

#[test]
fn test_cipher_suite_string_representations() {
    assert_eq!(CipherSuite::Aes128GcmSha256.as_str(), "TLS_AES_128_GCM_SHA256");
    assert_eq!(CipherSuite::Aes256GcmSha384.as_str(), "TLS_AES_256_GCM_SHA384");
    assert_eq!(CipherSuite::ChaCha20Poly1305Sha256.as_str(), "TLS_CHACHA20_POLY1305_SHA256");
}

#[test]
fn test_cipher_suite_hash_algorithms() {
    assert_eq!(CipherSuite::Aes128GcmSha256.hash_algorithm(), HashAlgorithm::Sha256);
    assert_eq!(CipherSuite::Aes256GcmSha384.hash_algorithm(), HashAlgorithm::Sha384);
    assert_eq!(CipherSuite::ChaCha20Poly1305Sha256.hash_algorithm(), HashAlgorithm::Sha256);
}

#[test]
fn test_cipher_suite_aead_algorithms() {
    assert_eq!(CipherSuite::Aes128GcmSha256.aead_algorithm(), AeadAlgorithm::Aes128Gcm);
    assert_eq!(CipherSuite::Aes256GcmSha384.aead_algorithm(), AeadAlgorithm::Aes256Gcm);
    assert_eq!(CipherSuite::ChaCha20Poly1305Sha256.aead_algorithm(), AeadAlgorithm::ChaCha20Poly1305);
}

#[test]
fn test_cipher_suite_key_lengths() {
    assert_eq!(CipherSuite::Aes128GcmSha256.key_length(), 16);
    assert_eq!(CipherSuite::Aes256GcmSha384.key_length(), 32);
    assert_eq!(CipherSuite::ChaCha20Poly1305Sha256.key_length(), 32);
}

#[test]
fn test_cipher_suite_iv_lengths() {
    assert_eq!(CipherSuite::Aes128GcmSha256.iv_length(), 12);
    assert_eq!(CipherSuite::Aes256GcmSha384.iv_length(), 12);
    assert_eq!(CipherSuite::ChaCha20Poly1305Sha256.iv_length(), 12);
}

#[test]
fn test_cipher_suite_deprecation_status() {
    // None of our core cipher suites should be deprecated
    assert!(!CipherSuite::Aes128GcmSha256.is_deprecated());
    assert!(!CipherSuite::Aes256GcmSha384.is_deprecated());
    assert!(!CipherSuite::ChaCha20Poly1305Sha256.is_deprecated());
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

#[test]
fn test_all_supported_cipher_suites() {
    let supported = CipherSuite::all_supported();
    assert_eq!(supported.len(), 3);
    
    assert!(supported.contains(&CipherSuite::Aes128GcmSha256));
    assert!(supported.contains(&CipherSuite::Aes256GcmSha384));
    assert!(supported.contains(&CipherSuite::ChaCha20Poly1305Sha256));
}

#[test]
fn test_all_cipher_suites() {
    let all = CipherSuite::all();
    assert_eq!(all.len(), 3);
    
    // Should be the same as supported since we only have core suites
    assert_eq!(all, CipherSuite::all_supported());
}

#[test]
fn test_cipher_suite_equality_and_hashing() {
    use std::collections::HashSet;
    
    let suite1 = CipherSuite::Aes128GcmSha256;
    let suite2 = CipherSuite::Aes128GcmSha256;
    let suite3 = CipherSuite::Aes256GcmSha384;
    
    // Test equality
    assert_eq!(suite1, suite2);
    assert_ne!(suite1, suite3);
    
    // Test hashing (should work in HashSet)
    let mut set = HashSet::new();
    set.insert(suite1);
    set.insert(suite2);
    set.insert(suite3);
    
    assert_eq!(set.len(), 2); // suite1 and suite2 are the same
    assert!(set.contains(&CipherSuite::Aes128GcmSha256));
    assert!(set.contains(&CipherSuite::Aes256GcmSha384));
}

#[test]
fn test_cipher_suite_debug_formatting() {
    // Test that debug formatting works
    let suite = CipherSuite::Aes128GcmSha256;
    let debug_str = format!("{:?}", suite);
    assert!(debug_str.contains("Aes128GcmSha256"));
}

#[test]
fn test_hash_algorithm_properties() {
    // Test SHA-256
    assert_eq!(HashAlgorithm::Sha256.output_length(), 32);
    assert_eq!(HashAlgorithm::Sha256.as_str(), "SHA256");
    
    // Test SHA-384
    assert_eq!(HashAlgorithm::Sha384.output_length(), 48);
    assert_eq!(HashAlgorithm::Sha384.as_str(), "SHA384");
}

#[test]
fn test_aead_algorithm_properties() {
    // Test that all AEAD algorithms are properly defined
    let aead_algs = vec![
        AeadAlgorithm::Aes128Gcm,
        AeadAlgorithm::Aes256Gcm,
        AeadAlgorithm::ChaCha20Poly1305,
    ];
    
    for alg in aead_algs {
        // Test debug formatting
        let debug_str = format!("{:?}", alg);
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn test_cipher_suite_comprehensive_properties() {
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
fn test_cipher_suite_ordering() {
    // Test that cipher suites can be ordered consistently
    let mut suites = vec![
        CipherSuite::ChaCha20Poly1305Sha256,
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
    ];
    
    suites.sort_by_key(|s| s.wire_format());
    
    assert_eq!(suites[0], CipherSuite::Aes128GcmSha256);
    assert_eq!(suites[1], CipherSuite::Aes256GcmSha384);
    assert_eq!(suites[2], CipherSuite::ChaCha20Poly1305Sha256);
}

#[test]
fn test_cipher_suite_cloning() {
    let original = CipherSuite::Aes128GcmSha256;
    let cloned = original.clone();
    
    assert_eq!(original, cloned);
    assert_eq!(original.wire_format(), cloned.wire_format());
    assert_eq!(original.as_str(), cloned.as_str());
}

#[test]
fn test_cipher_suite_copying() {
    let suite1 = CipherSuite::Aes128GcmSha256;
    let suite2 = suite1; // This should work because CipherSuite implements Copy
    
    assert_eq!(suite1, suite2);
    assert_eq!(suite1.wire_format(), suite2.wire_format());
}

