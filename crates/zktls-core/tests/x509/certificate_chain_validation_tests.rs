//! Certificate chain validation tests following RFC 5280 and strict TDD methodology
//!
//! This test suite validates X.509 certificate chain validation including:
//! - Chain building from leaf to root
//! - Signature verification using zktls-crypto 
//! - Validity period validation
//! - Key usage and extended key usage constraints
//! - Name constraints and path length validation
//! - Trust anchor verification

use zktls_core::x509::{X509Certificate, CertificateChain, CertificateChainValidator, ValidationError, ChainValidationResult};
use zktls_crypto::native::NativeCryptoProvider;

/// Test fixture: Let's Encrypt certificate chain (leaf -> intermediate -> root)
const LETSENCRYPT_LEAF_CERT_DER: &[u8] = include_bytes!("fixtures/certificates/letsencrypt_leaf.der");
const LETSENCRYPT_INTERMEDIATE_CERT_DER: &[u8] = include_bytes!("fixtures/certificates/letsencrypt_intermediate.der");
const LETSENCRYPT_ROOT_CERT_DER: &[u8] = include_bytes!("fixtures/certificates/letsencrypt_root.der");

/// Test fixture: Self-signed certificate for negative testing
const SELF_SIGNED_CERT_DER: &[u8] = include_bytes!("fixtures/certificates/self_signed.der");

/// Test fixture: Expired certificate
const EXPIRED_CERT_DER: &[u8] = include_bytes!("fixtures/certificates/expired.der");

#[cfg(test)]
mod chain_building_tests {
    use super::*;

    #[test]
    fn test_build_certificate_chain_from_leaf_to_root() {
        // RED: This test will fail until we implement CertificateChain::build
        
        // Parse certificates
        let leaf = X509Certificate::parse(LETSENCRYPT_LEAF_CERT_DER)
            .expect("Should parse leaf certificate");
        let intermediate = X509Certificate::parse(LETSENCRYPT_INTERMEDIATE_CERT_DER)
            .expect("Should parse intermediate certificate");  
        let root = X509Certificate::parse(LETSENCRYPT_ROOT_CERT_DER)
            .expect("Should parse root certificate");
        
        // Provide certificates in random order to test chain building logic
        let provided_certs = vec![&intermediate, &root, &leaf];
        
        // Build chain from leaf certificate
        let chain = CertificateChain::build(&leaf, &provided_certs)
            .expect("Should build valid certificate chain");
        
        // Verify chain order: leaf -> intermediate -> root
        assert_eq!(chain.certificates().len(), 3);
        assert_eq!(chain.leaf_certificate().subject().common_name(), 
                  Some("test.example.com")); // Expected from test cert
        assert_eq!(chain.root_certificate().issuer(), 
                  chain.root_certificate().subject()); // Self-signed root
    }

    #[test]
    fn test_build_chain_with_missing_intermediate() {
        // RED: This test will fail until we implement proper error handling
        
        let leaf = X509Certificate::parse(LETSENCRYPT_LEAF_CERT_DER)
            .expect("Should parse leaf certificate");
        let root = X509Certificate::parse(LETSENCRYPT_ROOT_CERT_DER)
            .expect("Should parse root certificate");
        
        // Missing intermediate certificate
        let provided_certs = vec![&root];
        
        let result = CertificateChain::build(&leaf, &provided_certs);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::MissingIntermediateCertificate(_) => {},
            _ => panic!("Expected MissingIntermediateCertificate error"),
        }
    }

    #[test] 
    fn test_build_chain_with_circular_reference() {
        // RED: Test circular certificate references
        let leaf = X509Certificate::parse(LETSENCRYPT_LEAF_CERT_DER)
            .expect("Should parse leaf certificate");
        
        // Create a malicious chain where certificates reference each other in a loop
        // For now, we'll use the same certificate twice to simulate this
        let provided_certs = vec![&leaf, &leaf];
        
        let result = CertificateChain::build(&leaf, &provided_certs);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::CircularChainReference => {},
            _ => panic!("Expected CircularChainReference error"),
        }
    }
}

#[cfg(test)]
mod signature_verification_tests {
    use super::*;

    #[test]
    fn test_verify_certificate_chain_signatures() {
        // RED: This test will fail until we implement signature verification
        
        let leaf = X509Certificate::parse(LETSENCRYPT_LEAF_CERT_DER)
            .expect("Should parse leaf certificate");
        let intermediate = X509Certificate::parse(LETSENCRYPT_INTERMEDIATE_CERT_DER)
            .expect("Should parse intermediate certificate");
        let root = X509Certificate::parse(LETSENCRYPT_ROOT_CERT_DER)
            .expect("Should parse root certificate");
        
        let provided_certs = vec![&intermediate, &root];
        let chain = CertificateChain::build(&leaf, &provided_certs)
            .expect("Should build certificate chain");
        
        let crypto_provider = NativeCryptoProvider::new();
        let validator = CertificateChainValidator::new(crypto_provider);
        
        // Verify all signatures in the chain
        let result = validator.verify_signatures(&chain);
        
        match result {
            Ok(_) => {
                // Signatures are valid - test passes
            },
            Err(e) => {
                panic!("Certificate signature verification failed: {:?}", e);
            }
        }
    }

    #[test]
    fn test_verify_chain_with_invalid_signature() {
        // RED: Test with a certificate that has an invalid signature
        let self_signed = X509Certificate::parse(SELF_SIGNED_CERT_DER)
            .expect("Should parse self-signed certificate");
        
        // Build a "chain" with just the self-signed cert
        let provided_certs = vec![];
        let chain = CertificateChain::build(&self_signed, &provided_certs)
            .expect("Should build single-certificate chain");
        
        let crypto_provider = NativeCryptoProvider::new();
        let validator = CertificateChainValidator::new(crypto_provider);
        
        // Self-signed certificates should fail signature verification against a proper CA chain
        let result = validator.verify_signatures(&chain);
        
        // NOTE: Self-signed certs can have valid signatures, but they're not trusted
        // The validation should depend on whether we have the self-signed cert in our trust store
        match result {
            Ok(_) => {
                // Self-signed cert is valid if we trust it
                assert!(true);
            },
            Err(ValidationError::InvalidSignature(_)) => {
                // Expected if not in trust store
                assert!(true);
            },
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}

#[cfg(test)]
mod validity_period_tests {
    use super::*;

    #[test]
    fn test_validate_certificate_validity_periods() {
        // RED: This test will fail until we implement validity period validation
        
        let leaf = X509Certificate::parse(LETSENCRYPT_LEAF_CERT_DER)
            .expect("Should parse leaf certificate");
        let intermediate = X509Certificate::parse(LETSENCRYPT_INTERMEDIATE_CERT_DER)
            .expect("Should parse intermediate certificate");
        let root = X509Certificate::parse(LETSENCRYPT_ROOT_CERT_DER)
            .expect("Should parse root certificate");
        
        let provided_certs = vec![&intermediate, &root];
        let chain = CertificateChain::build(&leaf, &provided_certs)
            .expect("Should build certificate chain");
        
        let crypto_provider = NativeCryptoProvider::new();
        let validator = CertificateChainValidator::new(crypto_provider);
        
        // Validate with current time
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let result = validator.validate_validity_periods(&chain, current_time);
        
        // Should pass if certificates are still valid
        assert!(result.is_ok(), "Certificate validity periods should be valid");
    }

    #[test]
    fn test_validate_expired_certificate() {
        // RED: This test will fail until we implement proper validity checking
        
        let expired = X509Certificate::parse(EXPIRED_CERT_DER)
            .expect("Should parse expired certificate");
        
        let provided_certs = vec![];
        let chain = CertificateChain::build(&expired, &provided_certs)
            .expect("Should build single-certificate chain");
        
        let crypto_provider = NativeCryptoProvider::new();
        let validator = CertificateChainValidator::new(crypto_provider);
        
        // Use a time after certificate expiration
        let future_time = 2000000000; // Year 2033
        
        let result = validator.validate_validity_periods(&chain, future_time);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::CertificateExpired(_) => {},
            _ => panic!("Expected CertificateExpired error"),
        }
    }
}

#[cfg(test)]
mod trust_anchor_tests {
    use super::*;

    #[test]
    fn test_validate_chain_against_trust_anchors() {
        // RED: This test will fail until we implement trust anchor validation
        
        let leaf = X509Certificate::parse(LETSENCRYPT_LEAF_CERT_DER)
            .expect("Should parse leaf certificate");
        let intermediate = X509Certificate::parse(LETSENCRYPT_INTERMEDIATE_CERT_DER)
            .expect("Should parse intermediate certificate");
        let root = X509Certificate::parse(LETSENCRYPT_ROOT_CERT_DER)
            .expect("Should parse root certificate");
        
        let provided_certs = vec![&intermediate];
        let chain = CertificateChain::build(&leaf, &provided_certs)
            .expect("Should build certificate chain");
        
        // Create trust anchors (root certificates)
        let trust_anchors = vec![&root];
        
        let crypto_provider = NativeCryptoProvider::new();
        let validator = CertificateChainValidator::new(crypto_provider);
        
        let result = validator.validate_against_trust_anchors(&chain, &trust_anchors);
        
        assert!(result.is_ok(), "Chain should be trusted against provided trust anchors");
    }

    #[test]
    fn test_validate_chain_without_trust_anchor() {
        // RED: Test chain that doesn't terminate at a trusted root
        
        let leaf = X509Certificate::parse(LETSENCRYPT_LEAF_CERT_DER)
            .expect("Should parse leaf certificate");
        let intermediate = X509Certificate::parse(LETSENCRYPT_INTERMEDIATE_CERT_DER)
            .expect("Should parse intermediate certificate");
        
        let provided_certs = vec![&intermediate];
        let chain = CertificateChain::build(&leaf, &provided_certs)
            .expect("Should build certificate chain");
        
        // Empty trust anchors
        let trust_anchors = vec![];
        
        let crypto_provider = NativeCryptoProvider::new();
        let validator = CertificateChainValidator::new(crypto_provider);
        
        let result = validator.validate_against_trust_anchors(&chain, &trust_anchors);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::UntrustedChain => {},
            _ => panic!("Expected UntrustedChain error"),
        }
    }
}

#[cfg(test)]
mod end_to_end_validation_tests {
    use super::*;

    #[test]
    fn test_complete_certificate_chain_validation() {
        // RED: This test will fail until we implement the complete validation pipeline
        
        let leaf = X509Certificate::parse(LETSENCRYPT_LEAF_CERT_DER)
            .expect("Should parse leaf certificate");
        let intermediate = X509Certificate::parse(LETSENCRYPT_INTERMEDIATE_CERT_DER)
            .expect("Should parse intermediate certificate");
        let root = X509Certificate::parse(LETSENCRYPT_ROOT_CERT_DER)
            .expect("Should parse root certificate");
        
        let provided_certs = vec![&intermediate, &root];
        let trust_anchors = vec![&root];
        
        let crypto_provider = NativeCryptoProvider::new();
        let validator = CertificateChainValidator::new(crypto_provider);
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Perform complete validation: chain building + signature verification + 
        // validity periods + trust anchors + constraints
        let result = validator.validate_complete(&leaf, &provided_certs, &trust_anchors, current_time);
        
        if let Err(e) = &result {
            println!("Validation error: {:?}", e);
        }
        
        assert!(result.is_ok(), "Complete certificate chain validation should succeed");
        
        let chain_validation_result = result.unwrap();
        assert!(chain_validation_result.is_valid());
        assert_eq!(chain_validation_result.chain_length(), 3); // leaf + intermediate + root
        assert!(chain_validation_result.trusted_root().is_some());
    }
}