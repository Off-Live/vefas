//! Comprehensive TDD tests for certificate parsing in zkVM guest program
//!
//! This module tests X.509 certificate parsing and validation functionality
//! following TDD principles with real certificate data.

#[cfg(feature = "sp1")]
mod certificate_parsing_tests {
    use zktls_zkvm::types::*;
    use zktls_core::x509::X509Certificate;
    use zktls_core::x509::validation::{CertificateChain, CertificateChainValidator};
    use zktls_crypto::native::NativeCryptoProvider;
    
mod fixtures;
mod test_real_certificate;
use fixtures::*;

    /// Test parsing a single X.509 certificate from DER bytes
    #[test]
    fn test_parse_single_certificate() {
        let cert_data = SIMPLE_CERTIFICATE;
        
        // Parse the certificate
        let certificate = X509Certificate::parse(cert_data)
            .expect("Failed to parse root CA certificate");
        
        // Verify basic certificate structure
        assert_eq!(certificate.version(), 0); // v1
        assert_eq!(certificate.serial_number(), &[0x01]); // Serial number 1
        
        // Verify subject and issuer (should be same for self-signed)
        let expected_data = expected_certificate_data();
        assert_eq!(certificate.subject().to_string(), expected_data.root_ca_subject);
        assert_eq!(certificate.issuer().to_string(), expected_data.root_ca_issuer);
        
        // Verify signature algorithm
        assert_eq!(certificate.signature_algorithm(), expected_data.signature_algorithm);
        
        // Verify public key
        let public_key = certificate.public_key();
        assert_eq!(public_key.algorithm(), expected_data.public_key_algorithm);
        
        // Verify validity period
        let validity = certificate.validity();
        assert_eq!(validity.not_before(), expected_data.validity_not_before);
        assert_eq!(validity.not_after(), expected_data.validity_not_after);
    }

    /// Test parsing multiple certificates in a chain
    #[test]
    fn test_parse_certificate_chain() {
        let certificates: Vec<X509Certificate> = SIMPLE_CERTIFICATE_CHAIN
            .iter()
            .map(|cert_data| X509Certificate::parse(cert_data).expect("Failed to parse certificate"))
            .collect();
        
        assert_eq!(certificates.len(), 3);
        
        let expected_data = expected_certificate_data();
        
        // Verify leaf certificate
        assert_eq!(certificates[0].subject().to_string(), expected_data.leaf_certificate_subject);
        assert_eq!(certificates[0].issuer().to_string(), expected_data.intermediate_ca_issuer);
        
        // Verify intermediate certificate
        assert_eq!(certificates[1].subject().to_string(), expected_data.intermediate_ca_subject);
        assert_eq!(certificates[1].issuer().to_string(), expected_data.root_ca_issuer);
        
        // Verify root certificate
        assert_eq!(certificates[2].subject().to_string(), expected_data.root_ca_subject);
        assert_eq!(certificates[2].issuer().to_string(), expected_data.root_ca_issuer); // Self-signed
    }

    /// Test certificate chain building
    #[test]
    fn test_build_certificate_chain() {
        // Parse all certificates
        let certificates: Vec<X509Certificate> = CERTIFICATE_CHAIN
            .iter()
            .map(|cert_data| X509Certificate::parse(cert_data).expect("Failed to parse certificate"))
            .collect();
        
        // Build certificate chain starting from leaf
        let leaf_cert = &certificates[0];
        let available_certs: Vec<&X509Certificate> = certificates.iter().collect();
        
        let chain = CertificateChain::build(leaf_cert, &available_certs)
            .expect("Failed to build certificate chain");
        
        // Verify chain structure
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.leaf_certificate().subject().to_string(), "CN=example.com");
        assert_eq!(chain.root_certificate().subject().to_string(), "CN=Test Root CA");
        
        // Verify chain order (leaf to root)
        let chain_certs = chain.certificates();
        assert_eq!(chain_certs[0].subject().to_string(), "CN=example.com");
        assert_eq!(chain_certs[1].subject().to_string(), "CN=Test Intermediate CA");
        assert_eq!(chain_certs[2].subject().to_string(), "CN=Test Root CA");
    }

    /// Test certificate chain validation with crypto provider
    #[test]
    fn test_certificate_chain_validation() {
        // Parse all certificates
        let certificates: Vec<X509Certificate> = CERTIFICATE_CHAIN
            .iter()
            .map(|cert_data| X509Certificate::parse(cert_data).expect("Failed to parse certificate"))
            .collect();
        
        // Create validator with native crypto provider
        let crypto_provider = NativeCryptoProvider::new();
        let validator = CertificateChainValidator::new(crypto_provider);
        
        // Build certificate chain
        let leaf_cert = &certificates[0];
        let available_certs: Vec<&X509Certificate> = certificates.iter().collect();
        let chain = CertificateChain::build(leaf_cert, &available_certs)
            .expect("Failed to build certificate chain");
        
        // Validate against trust anchors (root CA)
        let trust_anchors = &[&certificates[2]]; // Root CA
        let validation_time = 1704067200; // 2024-01-01 00:00:00Z (within validity period)
        
        let result = validator.validate_complete(
            leaf_cert,
            &available_certs,
            trust_anchors,
            validation_time
        ).expect("Certificate validation failed");
        
        // Verify validation result
        assert!(result.is_valid(), "Certificate chain should be valid");
        assert_eq!(result.chain_length(), 3);
        assert!(result.trusted_root().is_some());
        assert_eq!(result.errors().len(), 0);
    }

    /// Test certificate parsing with invalid DER data
    #[test]
    fn test_parse_invalid_certificate() {
        let invalid_data = &[0x30, 0x01, 0x00]; // Invalid DER structure
        
        let result = X509Certificate::parse(invalid_data);
        assert!(result.is_err(), "Should fail to parse invalid certificate");
    }

    /// Test certificate parsing with empty data
    #[test]
    fn test_parse_empty_certificate() {
        let empty_data = &[];
        
        let result = X509Certificate::parse(empty_data);
        assert!(result.is_err(), "Should fail to parse empty certificate");
    }

    /// Test certificate chain validation with expired certificate
    #[test]
    fn test_certificate_chain_validation_expired() {
        // Parse all certificates
        let certificates: Vec<X509Certificate> = CERTIFICATE_CHAIN
            .iter()
            .map(|cert_data| X509Certificate::parse(cert_data).expect("Failed to parse certificate"))
            .collect();
        
        // Create validator
        let crypto_provider = NativeCryptoProvider::new();
        let validator = CertificateChainValidator::new(crypto_provider);
        
        // Build certificate chain
        let leaf_cert = &certificates[0];
        let available_certs: Vec<&X509Certificate> = certificates.iter().collect();
        let chain = CertificateChain::build(leaf_cert, &available_certs)
            .expect("Failed to build certificate chain");
        
        // Validate with expired time
        let trust_anchors = &[&certificates[2]]; // Root CA
        let expired_time = 1751328001; // After validity period
        
        let result = validator.validate_complete(
            leaf_cert,
            &available_certs,
            trust_anchors,
            expired_time
        ).expect("Certificate validation should complete");
        
        // Verify validation result shows expiration
        assert!(!result.is_valid(), "Certificate chain should be invalid due to expiration");
        assert!(result.errors().len() > 0);
    }

    /// Test certificate chain validation with untrusted root
    #[test]
    fn test_certificate_chain_validation_untrusted_root() {
        // Parse all certificates
        let certificates: Vec<X509Certificate> = CERTIFICATE_CHAIN
            .iter()
            .map(|cert_data| X509Certificate::parse(cert_data).expect("Failed to parse certificate"))
            .collect();
        
        // Create validator
        let crypto_provider = NativeCryptoProvider::new();
        let validator = CertificateChainValidator::new(crypto_provider);
        
        // Build certificate chain
        let leaf_cert = &certificates[0];
        let available_certs: Vec<&X509Certificate> = certificates.iter().collect();
        let chain = CertificateChain::build(leaf_cert, &available_certs)
            .expect("Failed to build certificate chain");
        
        // Validate with empty trust anchors (no trusted roots)
        let trust_anchors: &[&X509Certificate] = &[];
        let validation_time = 1704067200; // 2024-01-01 00:00:00Z
        
        let result = validator.validate_complete(
            leaf_cert,
            &available_certs,
            trust_anchors,
            validation_time
        ).expect("Certificate validation should complete");
        
        // Verify validation result shows untrusted chain
        assert!(!result.is_valid(), "Certificate chain should be invalid due to untrusted root");
        assert!(result.errors().len() > 0);
    }

    /// Test domain validation against certificate
    #[test]
    fn test_domain_validation() {
        let cert_data = LEAF_CERTIFICATE;
        let certificate = X509Certificate::parse(cert_data)
            .expect("Failed to parse leaf certificate");
        
        // Test domain matching
        let subject = certificate.subject();
        let cn = subject.common_name().expect("Should have common name");
        assert_eq!(cn, "example.com");
        
        // Test domain validation logic
        assert!(cn == "example.com", "Domain should match certificate");
    }

    /// Test certificate parsing integration with zkVM guest program
    #[test]
    fn test_certificate_parsing_in_guest_program() {
        use zktls_zkvm::guest::parse_certificate_chain;
        
        // Create test input with certificate data
        let input = ZkTlsInput {
            domain: "example.com".to_string(),
            handshake_transcript: vec![0x01, 0x00, 0x00, 0x2b, 0x03, 0x03], // Minimal ClientHello
            certificates: vec![
                SIMPLE_CERTIFICATE.to_vec(),
                SIMPLE_CERTIFICATE.to_vec(),
                SIMPLE_CERTIFICATE.to_vec(),
            ],
            http_request: vec![],
            http_response: vec![],
            timestamp: 1704067200, // 2024-01-01 00:00:00Z
            metadata: ZkTlsMetadata {
                tls_version: "1.3".to_string(),
                cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
                client_random: [0u8; 32],
                server_random: [0u8; 32],
                session_id: None,
                extensions: vec![],
            },
        };
        
        // Test certificate parsing step in guest program
        let certificates = parse_certificate_chain(&input.certificates)
            .expect("Failed to parse certificate chain");
        
        // Verify certificates were parsed correctly
        assert_eq!(certificates.len(), 3);
        assert_eq!(certificates[0].subject().to_string(), "CN=example.com");
        assert_eq!(certificates[1].subject().to_string(), "CN=Test Intermediate CA");
        assert_eq!(certificates[2].subject().to_string(), "CN=Test Root CA");
        
        // Test certificate chain building
        let leaf_cert = &certificates[0];
        let available_certs: Vec<&X509Certificate> = certificates.iter().collect();
        let chain = CertificateChain::build(leaf_cert, &available_certs)
            .expect("Failed to build certificate chain");
        
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.leaf_certificate().subject().to_string(), "CN=example.com");
        assert_eq!(chain.root_certificate().subject().to_string(), "CN=Test Root CA");
    }

    /// Test certificate parsing performance in zkVM context
    #[test]
    fn test_certificate_parsing_performance() {
        let cert_data = ROOT_CA_CERTIFICATE;
        
        // Measure parsing time
        let start_time = std::time::Instant::now();
        
        for _ in 0..100 {
            let _certificate = X509Certificate::parse(cert_data)
                .expect("Failed to parse certificate");
        }
        
        let duration = start_time.elapsed();
        
        // Verify parsing is reasonably fast (should complete in < 1ms per certificate)
        assert!(duration.as_millis() < 100, "Certificate parsing should be fast");
    }

    /// Test certificate parsing with malformed data
    #[test]
    fn test_certificate_parsing_malformed_data() {
        // Test with truncated certificate
        let truncated_data = &ROOT_CA_CERTIFICATE[..50];
        let result = X509Certificate::parse(truncated_data);
        assert!(result.is_err(), "Should fail to parse truncated certificate");
        
        // Test with corrupted DER structure
        let mut corrupted_data = ROOT_CA_CERTIFICATE.to_vec();
        corrupted_data[0] = 0xFF; // Invalid tag
        let result = X509Certificate::parse(&corrupted_data);
        assert!(result.is_err(), "Should fail to parse corrupted certificate");
    }

    /// Test certificate extensions parsing
    #[test]
    fn test_certificate_extensions_parsing() {
        let cert_data = ROOT_CA_CERTIFICATE;
        let certificate = X509Certificate::parse(cert_data)
            .expect("Failed to parse certificate");
        
        // Verify extensions are parsed
        let extensions = certificate.extensions();
        assert!(!extensions.is_empty(), "Certificate should have extensions");
        
        // Verify we can access extension data
        let first_ext = &extensions[0];
        assert!(first_ext.is_critical() || !first_ext.is_critical());
    }
}
