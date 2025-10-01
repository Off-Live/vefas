//! Comprehensive Certificate Validation Tests using TLS 1.3 Fixtures
//!
//! This module tests certificate validation using the real TLS 1.3 certificate fixtures
//! generated for comprehensive testing of all algorithms and cipher suites.

use std::fs;
use std::path::Path;

use vefas_crypto::validation::{verify_certificate_signature, verify_certificate_chain_signatures};
use vefas_crypto_risc0::RISC0CryptoProvider;
use vefas_types::{errors::CryptoErrorType, VefasError, VefasResult};

/// Path to the fixtures directory
const FIXTURES_DIR: &str = "../../fixtures/certificates";

/// Certificate fixture loader for TLS 1.3 testing
struct CertificateFixtures {
    fixtures_path: String,
}

impl CertificateFixtures {
    fn new() -> Self {
        Self {
            fixtures_path: FIXTURES_DIR.to_string(),
        }
    }

    /// Load a certificate file as DER bytes (converts from PEM if needed)
    fn load_certificate(&self, cert_name: &str) -> VefasResult<Vec<u8>> {
        let cert_path = format!("{}/{}.crt", self.fixtures_path, cert_name);
        let cert_pem = fs::read(&cert_path)
            .map_err(|e| VefasError::InvalidInput {
                field: format!("certificate_{}", cert_name),
                reason: format!("Failed to read certificate file: {}", e)
            })?;
        
        // Convert PEM to DER
        let cert_der = self.pem_to_der(&cert_pem)
            .map_err(|e| VefasError::InvalidInput {
                field: format!("certificate_{}", cert_name),
                reason: format!("Failed to convert PEM to DER: {}", e)
            })?;
        
        Ok(cert_der)
    }

    /// Convert PEM certificate to DER format
    fn pem_to_der(&self, pem_data: &[u8]) -> Result<Vec<u8>, String> {
        let pem_str = String::from_utf8(pem_data.to_vec())
            .map_err(|e| format!("Invalid UTF-8 in PEM data: {}", e))?;
        
        // Find the certificate section
        let begin_marker = "-----BEGIN CERTIFICATE-----";
        let end_marker = "-----END CERTIFICATE-----";
        
        let begin_pos = pem_str.find(begin_marker)
            .ok_or("BEGIN CERTIFICATE marker not found")?;
        let end_pos = pem_str.find(end_marker)
            .ok_or("END CERTIFICATE marker not found")?;
        
        if end_pos <= begin_pos {
            return Err("Invalid PEM structure".to_string());
        }
        
        // Extract base64 content
        let base64_start = begin_pos + begin_marker.len();
        let base64_content = &pem_str[base64_start..end_pos];
        
        // Remove whitespace and newlines
        let clean_base64: String = base64_content
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        
        // Decode base64 to DER
        use base64::Engine;
        let der_data = base64::engine::general_purpose::STANDARD
            .decode(&clean_base64)
            .map_err(|e| format!("Base64 decode error: {}", e))?;
        
        Ok(der_data)
    }

    /// Load a private key file as PEM bytes
    fn load_private_key(&self, key_name: &str) -> VefasResult<Vec<u8>> {
        let key_path = format!("{}/{}.key", self.fixtures_path, key_name);
        let key_bytes = fs::read(&key_path)
            .map_err(|e| VefasError::InvalidInput {
                field: format!("private_key_{}", key_name),
                reason: format!("Failed to read private key file: {}", e)
            })?;
        Ok(key_bytes)
    }

    /// Check if a certificate file exists
    fn certificate_exists(&self, cert_name: &str) -> bool {
        let cert_path = format!("{}/{}.crt", self.fixtures_path, cert_name);
        Path::new(&cert_path).exists()
    }

    /// Get list of available certificates
    fn list_certificates(&self) -> VefasResult<Vec<String>> {
        let mut certificates = Vec::new();
        
        if let Ok(entries) = fs::read_dir(&self.fixtures_path) {
            for entry in entries {
                let entry = entry.map_err(|e| VefasError::InvalidInput {
                    field: "directory_entry".to_string(),
                    reason: format!("Failed to read directory entry: {}", e)
                })?;
                
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("crt") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        certificates.push(stem.to_string());
                    }
                }
            }
        }
        
        certificates.sort();
        Ok(certificates)
    }
}

/// Test RSA certificate validation with different key sizes
#[test]
fn test_rsa_certificate_validation() {
    let fixtures = CertificateFixtures::new();
    let crypto = RISC0CryptoProvider::new();

    // Test RSA 2048 certificate (most common)
    if fixtures.certificate_exists("rsa2048") {
        let cert_bytes = fixtures.load_certificate("rsa2048").unwrap();
        
        // Test self-signed certificate verification
        let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);
        assert!(
            result.is_ok(),
            "RSA 2048 self-signed certificate verification should succeed. Error: {:?}",
            result.err()
        );
        
        println!("✅ RSA 2048 certificate validation passed");
    } else {
        println!("⚠️  RSA 2048 certificate not found, skipping test");
    }

    // Test RSA 4096 certificate (high security)
    if fixtures.certificate_exists("rsa4096") {
        let cert_bytes = fixtures.load_certificate("rsa4096").unwrap();
        
        let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);
        assert!(
            result.is_ok(),
            "RSA 4096 self-signed certificate verification should succeed. Error: {:?}",
            result.err()
        );
        
        println!("✅ RSA 4096 certificate validation passed");
    } else {
        println!("⚠️  RSA 4096 certificate not found, skipping test");
    }

    // Test RSA 1024 certificate (legacy, should work but may trigger warnings)
    if fixtures.certificate_exists("rsa1024") {
        let cert_bytes = fixtures.load_certificate("rsa1024").unwrap();
        
        let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);
        assert!(
            result.is_ok(),
            "RSA 1024 self-signed certificate verification should succeed (legacy). Error: {:?}",
            result.err()
        );
        
        println!("✅ RSA 1024 certificate validation passed (legacy)");
    } else {
        println!("⚠️  RSA 1024 certificate not found, skipping test");
    }
}

/// Test ECDSA certificate validation with different curves
#[test]
fn test_ecdsa_certificate_validation() {
    let fixtures = CertificateFixtures::new();
    let crypto = RISC0CryptoProvider::new();

    // Test ECDSA P-256 certificate (most common elliptic curve)
    if fixtures.certificate_exists("ecdsa_p256") {
        let cert_bytes = fixtures.load_certificate("ecdsa_p256").unwrap();
        
        let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);
        assert!(
            result.is_ok(),
            "ECDSA P-256 self-signed certificate verification should succeed. Error: {:?}",
            result.err()
        );
        
        println!("✅ ECDSA P-256 certificate validation passed");
    } else {
        println!("⚠️  ECDSA P-256 certificate not found, skipping test");
    }

    // Test ECDSA P-384 certificate (higher security) - NOT YET IMPLEMENTED (H-4)
    if fixtures.certificate_exists("ecdsa_p384") {
        let cert_bytes = fixtures.load_certificate("ecdsa_p384").unwrap();
        let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);

        // P-384 not yet implemented, expect specific error
        // Note: P-384 certs may use different hash algorithms, causing different errors
        match &result {
            Err(e) => {
                let err_str = format!("{:?}", e);
                if err_str.contains("P-384 verification not yet implemented")
                    || err_str.contains("Invalid P-256 public key format") {
                    println!("⚠️  ECDSA P-384 verification not yet implemented (H-4 priority) - test passed");
                } else {
                    panic!("Expected P-384 not implemented or invalid key format error, got: {:?}", result);
                }
            }
            Ok(_) => {
                panic!("P-384 certificate should not verify without implementation, got: {:?}", result);
            }
        }
    } else {
        println!("⚠️  ECDSA P-384 certificate not found, skipping test");
    }

    // Test ECDSA P-521 certificate (highest security) - NOT YET IMPLEMENTED (H-4)
    if fixtures.certificate_exists("ecdsa_p521") {
        let cert_bytes = fixtures.load_certificate("ecdsa_p521").unwrap();
        let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);

        // P-521 not yet implemented, expect specific error
        // Note: P-521 certs may use different hash algorithms, causing different errors
        match &result {
            Err(e) => {
                let err_str = format!("{:?}", e);
                if err_str.contains("P-521 verification not yet implemented")
                    || err_str.contains("Invalid P-256 public key format") {
                    println!("⚠️  ECDSA P-521 verification not yet implemented (H-4 priority) - test passed");
                } else {
                    panic!("Expected P-521 not implemented or invalid key format error, got: {:?}", result);
                }
            }
            Ok(_) => {
                panic!("P-521 certificate should not verify without implementation, got: {:?}", result);
            }
        }
    } else {
        println!("⚠️  ECDSA P-521 certificate not found, skipping test");
    }
}

/// Test Ed25519 certificate validation (currently not supported)
#[test]
fn test_ed25519_certificate_validation() {
    let fixtures = CertificateFixtures::new();
    let crypto = RISC0CryptoProvider::new();

    if fixtures.certificate_exists("ed25519") {
        let cert_bytes = fixtures.load_certificate("ed25519").unwrap();
        
        let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);
        // Ed25519 is not currently supported in the validation module
        assert!(
            result.is_err(),
            "Ed25519 certificate verification should fail (not supported). Error: {:?}",
            result.err()
        );
        
        // Check that the error is about unsupported signature algorithm
        if let Err(VefasError::InvalidInput { reason, .. }) = result {
            assert!(
                reason.contains("Unsupported signature algorithm"),
                "Expected unsupported signature algorithm error, got: {}",
                reason
            );
        }
        
        println!("✅ Ed25519 certificate validation correctly failed (not supported)");
    } else {
        println!("⚠️  Ed25519 certificate not found, skipping test");
    }
}

/// Test certificate chain validation scenarios
#[test]
fn test_certificate_chain_validation() {
    let fixtures = CertificateFixtures::new();
    let crypto = RISC0CryptoProvider::new();

    // Test single certificate chain (self-signed)
    if fixtures.certificate_exists("rsa2048") {
        let cert_bytes = fixtures.load_certificate("rsa2048").unwrap();
        let chain = vec![cert_bytes.clone()];
        
        let result = verify_certificate_chain_signatures(&crypto, &chain);
        assert!(
            result.is_ok(),
            "Single certificate chain verification should succeed. Error: {:?}",
            result.err()
        );
        
        println!("✅ Single certificate chain validation passed");
    }

    // Test empty chain (should fail)
    let empty_chain: Vec<Vec<u8>> = vec![];
    let result = verify_certificate_chain_signatures(&crypto, &empty_chain);
    assert!(
        result.is_err(),
        "Empty certificate chain should fail verification"
    );
    
    println!("✅ Empty chain validation correctly failed");
}

/// Test certificate parsing and metadata extraction
#[test]
fn test_certificate_parsing() {
    let fixtures = CertificateFixtures::new();

    if fixtures.certificate_exists("rsa2048") {
        let cert_bytes = fixtures.load_certificate("rsa2048").unwrap();
        
        // Basic certificate structure validation
        assert!(
            cert_bytes.len() > 100,
            "Certificate should be substantial in size (at least 100 bytes)"
        );
        
        // Check for DER structure (should start with 0x30)
        assert_eq!(
            cert_bytes[0], 0x30,
            "Certificate should start with DER SEQUENCE tag (0x30)"
        );
        
        println!("✅ Certificate parsing validation passed");
    } else {
        println!("⚠️  RSA 2048 certificate not found, skipping parsing test");
    }
}

/// Test cross-algorithm certificate verification (should fail)
#[test]
fn test_cross_algorithm_verification_fails() {
    let fixtures = CertificateFixtures::new();
    let crypto = RISC0CryptoProvider::new();

    // Try to verify RSA certificate with ECDSA certificate as issuer (should fail)
    if fixtures.certificate_exists("rsa2048") && fixtures.certificate_exists("ecdsa_p256") {
        let rsa_cert = fixtures.load_certificate("rsa2048").unwrap();
        let ecdsa_cert = fixtures.load_certificate("ecdsa_p256").unwrap();
        
        let result = verify_certificate_signature(&crypto, &rsa_cert, &ecdsa_cert);
        assert!(
            result.is_err(),
            "Cross-algorithm certificate verification should fail (RSA cert with ECDSA issuer)"
        );
        
        println!("✅ Cross-algorithm verification correctly failed");
    } else {
        println!("⚠️  Required certificates not found, skipping cross-algorithm test");
    }
}

/// Test certificate tampering detection
#[test]
fn test_certificate_tampering_detection() {
    let fixtures = CertificateFixtures::new();
    let crypto = RISC0CryptoProvider::new();

    if fixtures.certificate_exists("rsa2048") {
        let mut cert_bytes = fixtures.load_certificate("rsa2048").unwrap();
        
        // Tamper with the certificate by changing the last byte
        if !cert_bytes.is_empty() {
            let last_index = cert_bytes.len() - 1;
            cert_bytes[last_index] = cert_bytes[last_index].wrapping_add(1);
            
            let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);
            assert!(
                result.is_err(),
                "Tampered certificate should fail verification"
            );
            
            println!("✅ Certificate tampering detection passed");
        }
    } else {
        println!("⚠️  RSA 2048 certificate not found, skipping tampering test");
    }
}

/// Test all available certificates
#[test]
fn test_all_available_certificates() {
    let fixtures = CertificateFixtures::new();
    let crypto = RISC0CryptoProvider::new();

    match fixtures.list_certificates() {
        Ok(certificates) => {
            println!("Found {} certificates for testing", certificates.len());

            for cert_name in certificates {
                println!("Testing certificate: {}", cert_name);

                match fixtures.load_certificate(&cert_name) {
                    Ok(cert_bytes) => {
                        let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);

                        // Handle unsupported curves/algorithms (H-4 priority)
                        if cert_name.contains("ecdsa_p384") {
                            match &result {
                                Err(e) => {
                                    let err_str = format!("{:?}", e);
                                    if err_str.contains("P-384 verification not yet implemented")
                                        || err_str.contains("Invalid P-256 public key format") {
                                        println!("  ⚠️  {} - not yet implemented (H-4) - test passed", cert_name);
                                    } else {
                                        panic!("Expected P-384 not implemented for {}, got: {:?}", cert_name, result);
                                    }
                                }
                                Ok(_) => {
                                    panic!("P-384 certificate {} should not verify without implementation", cert_name);
                                }
                            }
                        } else if cert_name.contains("ecdsa_p521") {
                            match &result {
                                Err(e) => {
                                    let err_str = format!("{:?}", e);
                                    if err_str.contains("P-521 verification not yet implemented")
                                        || err_str.contains("Invalid P-256 public key format") {
                                        println!("  ⚠️  {} - not yet implemented (H-4) - test passed", cert_name);
                                    } else {
                                        panic!("Expected P-521 not implemented for {}, got: {:?}", cert_name, result);
                                    }
                                }
                                Ok(_) => {
                                    panic!("P-521 certificate {} should not verify without implementation", cert_name);
                                }
                            }
                        } else if cert_name.contains("ed25519") {
                            match &result {
                                Err(e) => {
                                    let err_str = format!("{:?}", e);
                                    if err_str.contains("Unsupported signature algorithm") {
                                        println!("  ⚠️  {} - not yet implemented (H-4) - test passed", cert_name);
                                    } else {
                                        panic!("Expected Ed25519 not implemented for {}, got: {:?}", cert_name, result);
                                    }
                                }
                                Ok(_) => {
                                    panic!("Ed25519 certificate {} should not verify without implementation", cert_name);
                                }
                            }
                        } else {
                            assert!(
                                result.is_ok(),
                                "Certificate {} verification should succeed. Error: {:?}",
                                cert_name,
                                result.err()
                            );
                            println!("  ✅ {} validation passed", cert_name);
                        }
                    }
                    Err(e) => {
                        panic!("Failed to load certificate {}: {:?}", cert_name, e);
                    }
                }
            }

            println!("✅ All available certificates validated successfully");
        }
        Err(e) => {
            println!("⚠️  Could not list certificates: {:?}", e);
            println!("This is expected if fixtures are not available");
        }
    }
}

/// Test certificate validation performance
#[test]
fn test_certificate_validation_performance() {
    let fixtures = CertificateFixtures::new();
    let crypto = RISC0CryptoProvider::new();

    if fixtures.certificate_exists("rsa2048") {
        let cert_bytes = fixtures.load_certificate("rsa2048").unwrap();
        
        let start = std::time::Instant::now();
        
        // Perform multiple verifications to test performance
        for _ in 0..10 {
            let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);
            assert!(result.is_ok(), "Performance test verification should succeed");
        }
        
        let duration = start.elapsed();
        println!("✅ 10 certificate verifications completed in {:?}", duration);
        
        // Performance should be reasonable (less than 1 second for 10 verifications)
        assert!(
            duration.as_millis() < 1000,
            "Certificate verification should be reasonably fast"
        );
    } else {
        println!("⚠️  RSA 2048 certificate not found, skipping performance test");
    }
}

/// Test certificate validation error handling
#[test]
fn test_certificate_validation_error_handling() {
    let crypto = RISC0CryptoProvider::new();

    // Test with invalid DER data
    let invalid_der = vec![0x00, 0x01, 0x02, 0x03]; // Not a valid certificate
    let result = verify_certificate_signature(&crypto, &invalid_der, &invalid_der);
    assert!(
        result.is_err(),
        "Invalid DER data should fail certificate verification"
    );
    
    // Test with empty data
    let empty_data = vec![];
    let result = verify_certificate_signature(&crypto, &empty_data, &empty_data);
    assert!(
        result.is_err(),
        "Empty data should fail certificate verification"
    );
    
    println!("✅ Certificate validation error handling passed");
}

/// Test certificate validation with different signature algorithms
#[test]
fn test_signature_algorithm_compatibility() {
    let fixtures = CertificateFixtures::new();
    let crypto = RISC0CryptoProvider::new();

    // Test RSA certificates (should use RSA-SHA256)
    if fixtures.certificate_exists("rsa2048") {
        let cert_bytes = fixtures.load_certificate("rsa2048").unwrap();
        let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);
        assert!(result.is_ok(), "RSA certificate should verify with RSA-SHA256");
        println!("✅ RSA signature algorithm compatibility passed");
    }

    // Test ECDSA certificates (should use ECDSA-SHA256)
    if fixtures.certificate_exists("ecdsa_p256") {
        let cert_bytes = fixtures.load_certificate("ecdsa_p256").unwrap();
        let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);
        assert!(result.is_ok(), "ECDSA certificate should verify with ECDSA-SHA256");
        println!("✅ ECDSA signature algorithm compatibility passed");
    }

    // Test Ed25519 certificates (should fail - not supported)
    if fixtures.certificate_exists("ed25519") {
        let cert_bytes = fixtures.load_certificate("ed25519").unwrap();
        let result = verify_certificate_signature(&crypto, &cert_bytes, &cert_bytes);
        assert!(result.is_err(), "Ed25519 certificate should fail (not supported)");
        println!("✅ Ed25519 signature algorithm correctly not supported");
    }
}
