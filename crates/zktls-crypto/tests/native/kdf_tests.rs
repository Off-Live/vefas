//! Native KDF implementation tests with RFC 5869 test vectors
//!
//! This module contains comprehensive tests for HKDF-Extract and HKDF-Expand
//! implementations using official RFC 5869 test vectors.

use hex_literal::hex;
use zktls_crypto::native::kdf::*;
use zktls_crypto::error::{CryptoError, CryptoResult};

// RFC 5869 Test Case 1: Basic test case with SHA-256
#[test]
fn test_hkdf_sha256_basic() {
    // Test inputs from RFC 5869 Appendix A.1
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex!("000102030405060708090a0b0c");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");
    let length = 42;
    
    // Expected outputs from RFC 5869
    let expected_prk = hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let expected_okm = hex!("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    
    // Test HKDF-Extract
    let prk = hkdf_extract_sha256(&salt, &ikm).unwrap();
    assert_eq!(prk, expected_prk, "HKDF-Extract output mismatch");
    
    // Test HKDF-Expand
    let okm = hkdf_expand_sha256(&prk, &info, length).unwrap();
    assert_eq!(okm, expected_okm, "HKDF-Expand output mismatch");
    
    // Test full HKDF
    let full_okm = hkdf_sha256(&ikm, &salt, &info, length).unwrap();
    assert_eq!(full_okm, expected_okm, "Full HKDF output mismatch");
}

// RFC 5869 Test Case 2: Test with longer inputs/outputs
#[test]
fn test_hkdf_sha256_long() {
    let ikm = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
    let salt = hex!("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    let info = hex!("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let length = 82;
    
    let expected_prk = hex!("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
    let expected_okm = hex!("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
    
    let prk = hkdf_extract_sha256(&salt, &ikm).unwrap();
    assert_eq!(prk, expected_prk);
    
    let okm = hkdf_expand_sha256(&prk, &info, length).unwrap();
    assert_eq!(okm, expected_okm);
    
    let full_okm = hkdf_sha256(&ikm, &salt, &info, length).unwrap();
    assert_eq!(full_okm, expected_okm);
}

// RFC 5869 Test Case 3: Test with zero-length salt/info
#[test]
fn test_hkdf_sha256_zero_salt_info() {
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = &[];
    let info = &[];
    let length = 42;
    
    let expected_prk = hex!("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    let expected_okm = hex!("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    
    let prk = hkdf_extract_sha256(salt, &ikm).unwrap();
    assert_eq!(prk, expected_prk);
    
    let okm = hkdf_expand_sha256(&prk, info, length).unwrap();
    assert_eq!(okm, expected_okm);
    
    let full_okm = hkdf_sha256(&ikm, salt, info, length).unwrap();
    assert_eq!(full_okm, expected_okm);
}

// TLS 1.3 specific HKDF tests
#[test]
fn test_tls13_hkdf_label() {
    // Test TLS 1.3 HKDF-Expand-Label function as defined in RFC 8446 Section 7.1
    let secret = hex!("b067ca1a32cc218caabfaf5006e4c49b38b6e390be0a4b9e3b38070e2c7b8ab9");
    let label = b"tls13 key";
    let context = &[];
    let length = 16;
    
    // This test verifies our TLS 1.3 specific HKDF-Expand-Label implementation
    let result = hkdf_expand_label_sha256(&secret, label, context, length);
    assert!(result.is_ok(), "TLS 1.3 HKDF-Expand-Label should succeed");
    
    let output = result.unwrap();
    assert_eq!(output.len(), length, "Output length should match requested length");
    
    // Verify deterministic output (same inputs should produce same output)
    let result2 = hkdf_expand_label_sha256(&secret, label, context, length).unwrap();
    assert_eq!(output, result2, "HKDF should be deterministic");
}

#[test]
fn test_hkdf_error_conditions() {
    let ikm = hex!("0b0b0b0b0b0b0b0b");
    let salt = hex!("000102030405060708");
    let info = hex!("f0f1f2f3f4");
    
    // First extract a PRK for use in expand tests
    let prk = hkdf_extract_sha256(&salt, &ikm).unwrap();
    
    // Test maximum length validation (RFC 5869 specifies max 255 * HashLen)
    let max_length = 255 * 32; // 255 * SHA256 output size
    let result = hkdf_expand_sha256(&prk, &info, max_length);
    assert!(result.is_ok(), "Should succeed at maximum length");
    
    // Test exceeding maximum length
    let too_long = max_length + 1;
    let result = hkdf_expand_sha256(&prk, &info, too_long);
    assert!(result.is_err(), "Should fail when exceeding maximum length");
    match result.unwrap_err() {
        CryptoError::InvalidHkdfOutputLength { requested, max_allowed } => {
            assert_eq!(requested, too_long);
            assert_eq!(max_allowed, max_length);
        },
        _ => panic!("Should return InvalidHkdfOutputLength error"),
    }
    
    // Test zero length
    let result = hkdf_expand_sha256(&prk, &info, 0);
    assert!(result.is_ok(), "Should succeed with zero length");
    assert_eq!(result.unwrap().len(), 0, "Zero length should return empty vector");
    
    // Test invalid PRK (too short)
    let short_prk = vec![0u8; 16]; // Only 16 bytes, need 32 for SHA-256
    let result = hkdf_expand_sha256(&short_prk, &info, 32);
    assert!(result.is_err(), "Should fail with short PRK");
    match result.unwrap_err() {
        CryptoError::InvalidHkdfPrk { min_length, actual_length } => {
            assert_eq!(min_length, 32);
            assert_eq!(actual_length, 16);
        },
        _ => panic!("Should return InvalidHkdfPrk error"),
    }
}

// HKDF with SHA-384 test (for TLS 1.3 compatibility)
#[test]
fn test_hkdf_sha384_basic() {
    // Basic test with SHA-384 to ensure multi-hash support
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex!("000102030405060708090a0b0c");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");
    let length = 42;
    
    let result = hkdf_sha384(&ikm, &salt, &info, length);
    assert!(result.is_ok(), "HKDF-SHA384 should succeed");
    
    let output = result.unwrap();
    assert_eq!(output.len(), length, "Output length should match requested length");
}

#[test]
fn test_hkdf_parameter_validation() {
    let ikm = hex!("0b0b0b0b0b0b0b0b");
    let empty_salt = &[];
    let info = hex!("f0f1f2f3f4");
    
    // Empty IKM should be acceptable according to RFC 5869
    let empty_ikm = &[];
    let result = hkdf_sha256(empty_ikm, empty_salt, &info, 32);
    assert!(result.is_ok(), "Empty IKM should be acceptable");
    
    // Large but valid length
    let result = hkdf_sha256(&ikm, empty_salt, &info, 1024);
    assert!(result.is_ok(), "Large but valid length should work");
    
    let output = result.unwrap();
    assert_eq!(output.len(), 1024, "Output should have requested length");
}

// Generic HKDF interface tests
#[test]
fn test_generic_hkdf_interface() {
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex!("000102030405060708090a0b0c");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");
    let length = 42;
    
    // Test SHA-256 generic interface
    let result_256 = HkdfSha256::derive(&ikm, &salt, &info, length);
    assert!(result_256.is_ok(), "Generic HKDF-SHA256 should succeed");
    
    let output_256 = result_256.unwrap();
    assert_eq!(output_256.len(), length, "Output length should match requested");
    
    // Compare with direct function call
    let direct_result = hkdf_sha256(&ikm, &salt, &info, length).unwrap();
    assert_eq!(output_256, direct_result, "Generic and direct results should match");
    
    // Test SHA-384 generic interface
    let result_384 = HkdfSha384::derive(&ikm, &salt, &info, length);
    assert!(result_384.is_ok(), "Generic HKDF-SHA384 should succeed");
    
    let output_384 = result_384.unwrap();
    assert_eq!(output_384.len(), length, "Output length should match requested");
    
    // Compare with direct function call
    let direct_result_384 = hkdf_sha384(&ikm, &salt, &info, length).unwrap();
    assert_eq!(output_384, direct_result_384, "Generic and direct results should match");
}

#[test]
fn test_generic_hkdf_extract_expand() {
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex!("000102030405060708090a0b0c");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");
    let length = 42;
    
    // Test separate extract and expand operations
    let prk = HkdfSha256::extract(&salt, &ikm).unwrap();
    assert_eq!(prk.len(), HkdfSha256::OUTPUT_SIZE, "PRK should be hash output size");
    
    let okm = HkdfSha256::expand(&prk, &info, length).unwrap();
    assert_eq!(okm.len(), length, "Output length should match requested");
    
    // Should match combined derive operation
    let combined = HkdfSha256::derive(&ikm, &salt, &info, length).unwrap();
    assert_eq!(okm, combined, "Separate and combined operations should match");
}

// Edge cases and stress tests
#[test]
fn test_hkdf_edge_cases() {
    // Test with various salt lengths
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");
    
    // Very short salt
    let short_salt = hex!("01");
    let result = hkdf_sha256(&ikm, &short_salt, &info, 32);
    assert!(result.is_ok(), "Should work with very short salt");
    
    // Very long salt  
    let long_salt = vec![0x42u8; 200];
    let result = hkdf_sha256(&ikm, &long_salt, &info, 32);
    assert!(result.is_ok(), "Should work with very long salt");
    
    // Test with various info lengths
    let salt = hex!("000102030405060708090a0b0c");
    
    // Very long info
    let long_info = vec![0x55u8; 300];
    let result = hkdf_sha256(&ikm, &salt, &long_info, 32);
    assert!(result.is_ok(), "Should work with very long info");
    
    // Test maximum valid output length for SHA-256
    let max_length = 255 * 32; // Maximum per RFC 5869
    let result = hkdf_sha256(&ikm, &salt, &info, max_length);
    assert!(result.is_ok(), "Should work at maximum length");
    assert_eq!(result.unwrap().len(), max_length, "Should return exact requested length");
    
    // Test various output lengths
    for &len in &[1, 15, 16, 31, 32, 33, 64, 127, 128, 129, 255, 256, 1000] {
        let result = hkdf_sha256(&ikm, &salt, &info, len);
        assert!(result.is_ok(), "Should work with output length {}", len);
        assert_eq!(result.unwrap().len(), len, "Should return exact requested length {}", len);
    }
}

#[test]
fn test_hkdf_consistency_across_calls() {
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex!("000102030405060708090a0b0c");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");
    let length = 42;
    
    // Multiple calls should produce identical results
    let result1 = hkdf_sha256(&ikm, &salt, &info, length).unwrap();
    let result2 = hkdf_sha256(&ikm, &salt, &info, length).unwrap();
    let result3 = hkdf_sha256(&ikm, &salt, &info, length).unwrap();
    
    assert_eq!(result1, result2, "Multiple calls should be identical");
    assert_eq!(result2, result3, "Multiple calls should be identical");
    
    // Test with SHA-384 as well
    let result1_384 = hkdf_sha384(&ikm, &salt, &info, length).unwrap();
    let result2_384 = hkdf_sha384(&ikm, &salt, &info, length).unwrap();
    
    assert_eq!(result1_384, result2_384, "SHA-384 calls should be identical");
    
    // SHA-256 and SHA-384 should produce different results
    assert_ne!(result1, result1_384, "Different hash functions should produce different results");
}

#[test]
fn test_hkdf_input_sensitivity() {
    let base_ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let base_salt = hex!("000102030405060708090a0b0c");
    let base_info = hex!("f0f1f2f3f4f5f6f7f8f9");
    let length = 32;
    
    let base_result = hkdf_sha256(&base_ikm, &base_salt, &base_info, length).unwrap();
    
    // Single bit flip in IKM should change output completely
    let mut modified_ikm = base_ikm.clone();
    modified_ikm[0] ^= 0x01; // Flip one bit
    let modified_result = hkdf_sha256(&modified_ikm, &base_salt, &base_info, length).unwrap();
    assert_ne!(base_result, modified_result, "Single bit change should produce different output");
    
    // Single bit flip in salt should change output
    let mut modified_salt = base_salt.clone();
    modified_salt[0] ^= 0x01;
    let modified_result = hkdf_sha256(&base_ikm, &modified_salt, &base_info, length).unwrap();
    assert_ne!(base_result, modified_result, "Salt change should produce different output");
    
    // Single bit flip in info should change output
    let mut modified_info = base_info.clone();
    modified_info[0] ^= 0x01;
    let modified_result = hkdf_sha256(&base_ikm, &base_salt, &modified_info, length).unwrap();
    assert_ne!(base_result, modified_result, "Info change should produce different output");
}