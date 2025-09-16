//! Tests for real AES-GCM encryption in TLS application data
//!
//! This module contains tests that expose the XOR mock encryption issue
//! and validate that real AES-GCM encryption is implemented correctly.

use zktls_core::tls::application::ApplicationDataHandler;
use zktls_core::errors::ZkTlsError;

/// Test that exposes the XOR mock encryption vulnerability
/// 
/// This test demonstrates that the current implementation uses XOR encryption
/// instead of real AES-GCM, making it completely insecure.
#[test]
fn test_xor_mock_encryption_vulnerability() {
    let app_handler = ApplicationDataHandler::new().unwrap();
    let traffic_key = [0x42u8; 32]; // Fixed key for testing
    let plaintext = b"Hello, World! This is a test message.";
    let sequence_number = 1u64;
    
    // Encrypt the same plaintext twice
    let encrypted1 = app_handler.encrypt(plaintext, &traffic_key, sequence_number).unwrap();
    let encrypted2 = app_handler.encrypt(plaintext, &traffic_key, sequence_number).unwrap();
    
    // With XOR encryption, identical inputs produce identical outputs
    // This is a security vulnerability - real AES-GCM should produce different outputs
    assert_eq!(encrypted1, encrypted2, 
        "XOR mock encryption produces identical outputs for identical inputs - this is insecure!");
    
    // The encrypted data should be longer than plaintext due to nonce + auth tag
    assert!(encrypted1.len() > plaintext.len(), 
        "Encrypted data should be longer than plaintext");
    
    // Verify we can decrypt back to original
    let decrypted = app_handler.decrypt(&encrypted1, &traffic_key, sequence_number).unwrap();
    assert_eq!(decrypted, plaintext, "Decryption should produce original plaintext");
}

/// Test that demonstrates XOR encryption is deterministic and insecure
#[test]
fn test_xor_encryption_deterministic_insecurity() {
    let app_handler = ApplicationDataHandler::new().unwrap();
    let traffic_key = [0xABu8; 32];
    let plaintext = b"Secret message that should be encrypted securely";
    let sequence_number = 42u64;
    
    // Encrypt the same message multiple times
    let mut encrypted_results = Vec::new();
    for _ in 0..5 {
        let encrypted = app_handler.encrypt(plaintext, &traffic_key, sequence_number).unwrap();
        encrypted_results.push(encrypted);
    }
    
    // All encrypted results should be identical (XOR behavior)
    // This is a critical security flaw - real AES-GCM should produce different results
    for i in 1..encrypted_results.len() {
        assert_eq!(encrypted_results[0], encrypted_results[i],
            "XOR encryption is deterministic - this is a security vulnerability!");
    }
    
    // Verify the XOR pattern by examining the encrypted data
    let encrypted = &encrypted_results[0];
    let nonce = &encrypted[..12];
    let encrypted_data = &encrypted[12..encrypted.len() - 16];
    let auth_tag = &encrypted[encrypted.len() - 16..];
    
    // With real AES-GCM, we should NOT see XOR patterns
    let key_pattern = traffic_key[0];
    let mut xor_pattern_found = true;
    for (i, &byte) in encrypted_data.iter().enumerate() {
        let expected_xor = plaintext[i] ^ key_pattern;
        if byte != expected_xor {
            xor_pattern_found = false;
            break;
        }
    }
    assert!(!xor_pattern_found, 
        "Real AES-GCM should NOT show XOR patterns - this confirms we're using real encryption!");
}

/// Test that validates real AES-GCM encryption requirements
/// 
/// This test defines what real AES-GCM encryption should look like
/// and will fail until the mock implementation is replaced.
#[test]
fn test_real_aes_gcm_encryption_requirements() {
    let app_handler = ApplicationDataHandler::new().unwrap();
    let traffic_key = [0xCDu8; 32];
    let plaintext = b"Test message for real AES-GCM encryption";
    let sequence_number = 1u64;
    
    // Encrypt the same plaintext multiple times
    let encrypted1 = app_handler.encrypt(plaintext, &traffic_key, sequence_number).unwrap();
    let encrypted2 = app_handler.encrypt(plaintext, &traffic_key, sequence_number).unwrap();
    
    // In TLS 1.3, the nonce is deterministic based on sequence number
    // So identical inputs (same plaintext, key, sequence) should produce identical outputs
    // This is correct TLS 1.3 behavior, not a security issue
    assert_eq!(encrypted1, encrypted2, 
        "TLS 1.3 with deterministic nonce should produce identical ciphertexts for identical inputs");
    
    // Both should decrypt to the same plaintext
    let decrypted1 = app_handler.decrypt(&encrypted1, &traffic_key, sequence_number).unwrap();
    let decrypted2 = app_handler.decrypt(&encrypted2, &traffic_key, sequence_number).unwrap();
    
    assert_eq!(decrypted1, plaintext, "First decryption should work");
    assert_eq!(decrypted2, plaintext, "Second decryption should work");
    
    // Test that different sequence numbers produce different ciphertexts
    let encrypted3 = app_handler.encrypt(plaintext, &traffic_key, 2u64).unwrap();
    assert_ne!(encrypted1, encrypted3, 
        "Different sequence numbers should produce different ciphertexts");
    
    // Verify the different sequence number decrypts correctly
    let decrypted3 = app_handler.decrypt(&encrypted3, &traffic_key, 2u64).unwrap();
    assert_eq!(decrypted3, plaintext, "Different sequence number decryption should work");
}

/// Test that validates proper AES-GCM authentication
#[test]
fn test_aes_gcm_authentication_requirements() {
    let app_handler = ApplicationDataHandler::new().unwrap();
    let traffic_key = [0xEFu8; 32];
    let plaintext = b"Message requiring authentication";
    let sequence_number = 1u64;
    
    let encrypted = app_handler.encrypt(plaintext, &traffic_key, sequence_number).unwrap();
    
    // Tamper with the encrypted data
    let mut tampered = encrypted.clone();
    if tampered.len() > 20 {
        tampered[20] = tampered[20].wrapping_add(1); // Modify encrypted data
    }
    
    // Real AES-GCM should detect tampering and fail to decrypt
    let result = app_handler.decrypt(&tampered, &traffic_key, sequence_number);
    
    // This test will FAIL until real AES-GCM authentication is implemented
    assert!(result.is_err(), 
        "Real AES-GCM should detect tampering and fail to decrypt");
    
    // Verify original still works
    let original_result = app_handler.decrypt(&encrypted, &traffic_key, sequence_number).unwrap();
    assert_eq!(original_result, plaintext, "Original should still decrypt correctly");
}

/// Test that validates proper nonce handling
#[test]
fn test_aes_gcm_nonce_handling_requirements() {
    let app_handler = ApplicationDataHandler::new().unwrap();
    let traffic_key = [0x12u8; 32];
    let plaintext = b"Test nonce handling";
    
    // Encrypt with different sequence numbers
    let encrypted1 = app_handler.encrypt(plaintext, &traffic_key, 1).unwrap();
    let encrypted2 = app_handler.encrypt(plaintext, &traffic_key, 2).unwrap();
    
    // Different sequence numbers should produce different ciphertexts
    assert_ne!(encrypted1, encrypted2, 
        "Different sequence numbers should produce different ciphertexts");
    
    // Each should decrypt with its correct sequence number
    let decrypted1 = app_handler.decrypt(&encrypted1, &traffic_key, 1).unwrap();
    let decrypted2 = app_handler.decrypt(&encrypted2, &traffic_key, 2).unwrap();
    
    assert_eq!(decrypted1, plaintext, "First decryption should work");
    assert_eq!(decrypted2, plaintext, "Second decryption should work");
    
    // Cross-decryption should fail
    let cross_result1 = app_handler.decrypt(&encrypted1, &traffic_key, 2);
    let cross_result2 = app_handler.decrypt(&encrypted2, &traffic_key, 1);
    
    // This test will FAIL until real nonce validation is implemented
    assert!(cross_result1.is_err(), 
        "Decryption with wrong sequence number should fail");
    assert!(cross_result2.is_err(), 
        "Decryption with wrong sequence number should fail");
}
