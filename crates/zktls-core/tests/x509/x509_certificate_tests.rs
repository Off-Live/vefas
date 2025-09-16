//! X.509 certificate parsing tests following strict TDD methodology
//! 
//! Tests are organized following RFC 5280 X.509 certificate structure:
//! 1. Basic certificate parsing (version, serial, signature algorithm)
//! 2. Subject/Issuer Distinguished Name parsing
//! 3. Public key information extraction
//! 4. Extension handling (Critical extensions: Key Usage, Extended Key Usage, SAN)
//! 5. Certificate validation and constraints

use zktls_core::x509::{X509Certificate, ExtensionType};

/// Test fixture for ECDSA certificate
const TEST_ECDSA_CERT_DER: &[u8] = include_bytes!("fixtures/certificates/test_ecdsa_cert.der");

/// Test fixture for RSA certificate  
const TEST_RSA_CERT_DER: &[u8] = include_bytes!("fixtures/certificates/test_rsa_cert.der");

#[cfg(test)]
mod certificate_parsing_tests {
    use super::*;

    #[test]
    fn test_parse_ecdsa_certificate_basic_fields() {
        // RED: This test will fail until we implement X509Certificate::parse
        let cert = X509Certificate::parse(TEST_ECDSA_CERT_DER)
            .expect("Should parse valid ECDSA certificate");
        
        // Verify basic fields based on OpenSSL output above
        assert_eq!(cert.version(), 3); // Version 3 (0x2 + 1)
        assert_eq!(
            cert.serial_number(), 
            &[0x68, 0xd0, 0x13, 0x1d, 0x0f, 0x91, 0x29, 0x77, 0x07, 0x15, 0xe6, 0x22, 0x66, 0x3e, 0x82, 0x78, 0x07, 0x07, 0x80, 0x35]
        );
        
        // Verify signature algorithm
        assert_eq!(cert.signature_algorithm(), "ecdsa-with-SHA256");
    }

    #[test]
    fn test_parse_rsa_certificate_basic_fields() {
        // RED: This test will fail until we implement RSA certificate parsing
        let cert = X509Certificate::parse(TEST_RSA_CERT_DER)
            .expect("Should parse valid RSA certificate");
        
        assert_eq!(cert.version(), 3);
        assert!(!cert.serial_number().is_empty());
        assert_eq!(cert.signature_algorithm(), "sha256WithRSAEncryption");
    }

    #[test]
    fn test_parse_subject_distinguished_name() {
        // RED: This will fail until we implement DN parsing
        let cert = X509Certificate::parse(TEST_ECDSA_CERT_DER)
            .expect("Should parse valid certificate");
            
        let subject = cert.subject();
        assert_eq!(subject.common_name(), Some("test.bytebitlabs.com"));
        assert_eq!(subject.organization(), None);
        assert_eq!(subject.country(), None);
    }

    #[test]
    fn test_parse_issuer_distinguished_name() {
        // RED: This will fail until we implement DN parsing
        let cert = X509Certificate::parse(TEST_ECDSA_CERT_DER)
            .expect("Should parse valid certificate");
            
        let issuer = cert.issuer();
        assert_eq!(issuer.common_name(), Some("test.bytebitlabs.com"));
    }

    #[test]
    fn test_parse_ecdsa_public_key() {
        // RED: This will fail until we implement public key parsing
        let cert = X509Certificate::parse(TEST_ECDSA_CERT_DER)
            .expect("Should parse valid certificate");
            
        let public_key = cert.public_key();
        assert!(matches!(public_key.algorithm(), "id-ecPublicKey"));
        
        // Verify ECDSA P-256 curve
        assert_eq!(public_key.curve_oid(), Some("1.2.840.10045.3.1.7")); // prime256v1
        
        // Verify public key point (uncompressed format starting with 0x04)
        let key_data = public_key.key_data();
        assert_eq!(key_data.len(), 65); // 1 byte format + 32 bytes x + 32 bytes y
        assert_eq!(key_data[0], 0x04); // Uncompressed point format
    }

    #[test]
    fn test_parse_rsa_public_key() {
        // RED: This will fail until we implement RSA public key parsing
        let cert = X509Certificate::parse(TEST_RSA_CERT_DER)
            .expect("Should parse valid certificate");
            
        let public_key = cert.public_key();
        assert!(matches!(public_key.algorithm(), "rsaEncryption"));
        
        // RSA public key contains modulus and exponent
        assert!(!public_key.key_data().is_empty());
    }

    #[test]
    fn test_parse_validity_period() {
        // RED: This will fail until we implement validity parsing
        let cert = X509Certificate::parse(TEST_ECDSA_CERT_DER)
            .expect("Should parse valid certificate");
            
        let validity = cert.validity();
        assert!(validity.not_before() > 0); // Unix timestamp
        assert!(validity.not_after() > validity.not_before());
        assert_eq!(validity.not_after() - validity.not_before(), 365 * 24 * 3600); // 1 year
    }

    #[test]
    fn test_parse_extensions() {
        // RED: This will fail until we implement extension parsing
        let cert = X509Certificate::parse(TEST_ECDSA_CERT_DER)
            .expect("Should parse valid certificate");
            
        let extensions = cert.extensions();
        assert!(!extensions.is_empty());
        
        // Verify expected extensions from OpenSSL output
        assert!(extensions.iter().any(|ext| matches!(ext.extension_type(), ExtensionType::SubjectKeyIdentifier(_))));
        assert!(extensions.iter().any(|ext| matches!(ext.extension_type(), ExtensionType::AuthorityKeyIdentifier(_))));
        assert!(extensions.iter().any(|ext| matches!(ext.extension_type(), ExtensionType::BasicConstraints(_))));
    }

    #[test]
    fn test_basic_constraints_extension() {
        // RED: This will fail until we implement Basic Constraints parsing
        let cert = X509Certificate::parse(TEST_ECDSA_CERT_DER)
            .expect("Should parse valid certificate");
            
        let basic_constraints_ext = cert.basic_constraints()
            .expect("Certificate should have Basic Constraints extension");
            
        if let ExtensionType::BasicConstraints(basic_constraints) = basic_constraints_ext.extension_type() {
            assert!(basic_constraints.is_ca()); // CA:TRUE from OpenSSL output
            assert!(basic_constraints.is_critical()); // marked as critical
        } else {
            panic!("Expected BasicConstraints extension");
        }
    }

    #[test]
    fn test_invalid_certificate_data() {
        // RED: This will fail until we implement proper error handling
        let invalid_der = &[0xFF, 0xFF, 0xFF, 0xFF];
        let result = X509Certificate::parse(invalid_der);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_with_subject_alternative_name() {
        // TODO: Create a certificate with SAN for this test
        // For now, this is a placeholder for SAN extension testing
    }
}

#[cfg(test)]
mod tbs_data_extraction_tests {
    use super::*;

    /// Test TBS (To-Be-Signed) data extraction from X.509 certificates
    /// 
    /// This test verifies that we can correctly extract the TBS portion of 
    /// a certificate, which is required for signature verification.
    #[test]
    fn test_tbs_data_extraction_basic() {
        // RED: This test will fail until we implement proper TBS data extraction
        let cert = X509Certificate::parse(TEST_ECDSA_CERT_DER)
            .expect("Certificate should parse");
        
        // The TBS data should NOT be the same as raw data (which includes signature)
        let tbs_data = cert.tbs_certificate_data();
        let raw_data = cert.raw_data();
        
        assert_ne!(tbs_data, raw_data, "TBS data should be different from raw certificate data");
        
        // TBS data should be shorter than raw data (excludes signature algorithm and signature value)
        assert!(tbs_data.len() < raw_data.len(), "TBS data should be shorter than full certificate");
        
        // TBS data should start with SEQUENCE tag (0x30)
        assert_eq!(tbs_data[0], 0x30, "TBS data should start with SEQUENCE tag");
        
        // Verify TBS data ends before signature algorithm in the raw data
        // This is a structural check to ensure we're extracting the right portion
        assert!(tbs_data.len() < raw_data.len() - 64, "TBS should exclude signature portion");
    }

    /// Test TBS data extraction preserves ASN.1 structure
    #[test]
    fn test_tbs_data_asn1_structure() {
        // RED: This test will fail until we implement proper TBS data extraction
        let cert = X509Certificate::parse(TEST_RSA_CERT_DER)
            .expect("RSA certificate should parse");
        let tbs_data = cert.tbs_certificate_data();
        
        // TBS data should be valid ASN.1 DER SEQUENCE
        assert_eq!(tbs_data[0], 0x30, "TBS must start with SEQUENCE tag");
        
        // Parse length to ensure valid DER encoding
        let length_byte = tbs_data[1];
        if length_byte & 0x80 == 0 {
            // Short form - length should match remaining data
            let declared_length = length_byte as usize;
            assert_eq!(tbs_data.len(), declared_length + 2, "Short form length should match");
        } else {
            // Long form - extract multi-byte length
            let length_octets = (length_byte & 0x7f) as usize;
            assert!(length_octets > 0 && length_octets <= 4, "Length octets should be reasonable");
            assert!(tbs_data.len() > length_octets + 2, "Must have enough bytes for long form");
        }
    }

    /// Test that TBS extraction works with self-signed certificates
    #[test]  
    fn test_tbs_data_self_signed_certificate() {
        // RED: This test will fail until we implement proper TBS data extraction
        let cert = X509Certificate::parse(TEST_ECDSA_CERT_DER)
            .expect("Certificate should parse");
        
        let tbs_data = cert.tbs_certificate_data();
        let signature_bytes = cert.signature_bytes();
        
        // TBS data and signature should be non-empty and different
        assert!(!tbs_data.is_empty(), "TBS data should not be empty");
        assert!(!signature_bytes.is_empty(), "Signature should not be empty");
        assert_ne!(tbs_data, signature_bytes, "TBS data should not equal signature bytes");
        
        // Verify TBS data starts with SEQUENCE and has reasonable length
        assert_eq!(tbs_data[0], 0x30, "TBS data should start with SEQUENCE tag");
        assert!(tbs_data.len() > 100, "TBS data should be substantial for real certificate");
        assert!(tbs_data.len() < cert.raw_data().len(), "TBS should be subset of raw data");
    }
}

#[cfg(test)]
mod distinguished_name_tests {
    use super::*;

    #[test]
    fn test_parse_simple_distinguished_name() {
        // RED: This will fail until we implement DN parsing
        // This will test parsing of "CN=test.bytebitlabs.com"
        
        // We'll need to extract the Subject field from the test certificate
        // and test DN parsing separately
    }

    #[test]
    fn test_parse_complex_distinguished_name() {
        // RED: Future test for more complex DNs with multiple components
        // "CN=example.com, O=Example Corp, C=US"
    }
}

#[cfg(test)]
mod public_key_tests {
    use super::*;

    #[test]
    fn test_ecdsa_p256_public_key_validation() {
        // RED: This will fail until we implement public key validation
        let cert = X509Certificate::parse(TEST_ECDSA_CERT_DER)
            .expect("Should parse valid certificate");
            
        let public_key = cert.public_key();
        
        // Validate that the public key point is on the P-256 curve
        assert!(public_key.validate_curve_point().is_ok());
    }

    #[test]
    fn test_rsa_public_key_validation() {
        // RED: This will fail until we implement RSA key validation
        let cert = X509Certificate::parse(TEST_RSA_CERT_DER)
            .expect("Should parse valid certificate");
            
        let public_key = cert.public_key();
        
        // Validate RSA modulus and exponent
        assert!(public_key.validate_rsa_params().is_ok());
    }
}