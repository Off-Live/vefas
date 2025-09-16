//! Test real X.509 certificate parsing
//!
//! This test module validates that our ASN.1 parser can correctly parse
//! real X.509 certificates generated with OpenSSL.

use zktls_core::x509::X509Certificate;
use crate::certificate_parsing_tests::fixtures::REAL_ROOT_CA_CERTIFICATE;

#[test]
fn test_parse_real_certificate() {
    // Test parsing a real X.509 certificate
    let result = X509Certificate::parse(REAL_ROOT_CA_CERTIFICATE);
    
    match result {
        Ok(cert) => {
            println!("Successfully parsed real certificate");
            println!("Subject: {:?}", cert.subject());
            println!("Issuer: {:?}", cert.issuer());
            println!("Serial number: {:?}", cert.serial_number());
            println!("Public key: {:?}", cert.public_key());
            
            // Verify basic certificate properties
            assert_eq!(cert.subject().common_name(), Some("Test Root CA"));
            assert_eq!(cert.issuer().common_name(), Some("Test Root CA"));
            assert_eq!(cert.version(), 3); // X.509 v3 certificate
            
            // Verify it's a CA certificate
            if let Some(basic_constraints) = cert.basic_constraints() {
                // Check if it's a CA certificate by examining the extension
                match basic_constraints.extension_type() {
                    zktls_core::x509::ExtensionType::BasicConstraints(constraints) => {
                        assert!(constraints.is_ca());
                    },
                    _ => panic!("Expected BasicConstraints extension"),
                }
            }
        },
        Err(e) => {
            panic!("Failed to parse real certificate: {:?}", e);
        }
    }
}

#[test]
fn test_real_certificate_structure() {
    // Test that the real certificate has the expected structure
    let cert = X509Certificate::parse(REAL_ROOT_CA_CERTIFICATE).unwrap();
    
    // Verify certificate structure
    assert!(!cert.raw_data().is_empty());
    assert!(!cert.tbs_certificate_data().is_empty());
    assert!(!cert.signature_bytes().is_empty());
    
    // Verify TBS certificate structure
    assert_eq!(cert.version(), 3);
    assert!(!cert.serial_number().is_empty());
    assert!(!cert.signature_algorithm().is_empty());
    assert!(cert.issuer().common_name().is_some());
    assert!(cert.subject().common_name().is_some());
    assert!(!cert.public_key().algorithm().is_empty());
}

#[test]
fn test_real_certificate_extensions() {
    // Test parsing extensions from real certificate
    let cert = X509Certificate::parse(REAL_ROOT_CA_CERTIFICATE).unwrap();
    
    // Real certificate should have extensions
    let extensions = cert.extensions();
    assert!(!extensions.is_empty(), "Real certificate should have extensions");
    
    // Check for common extensions
    let mut has_key_usage = false;
    let mut has_basic_constraints = false;
    let mut has_subject_key_identifier = false;
    let mut has_authority_key_identifier = false;
    
    for ext in extensions {
        match ext.extension_type() {
            zktls_core::x509::ExtensionType::KeyUsage(_) => has_key_usage = true,
            zktls_core::x509::ExtensionType::BasicConstraints(_) => has_basic_constraints = true,
            zktls_core::x509::ExtensionType::SubjectKeyIdentifier(_) => has_subject_key_identifier = true,
            zktls_core::x509::ExtensionType::AuthorityKeyIdentifier(_) => has_authority_key_identifier = true,
            _ => {}
        }
    }
    
    // CA certificates should have these extensions
    assert!(has_key_usage, "CA certificate should have Key Usage extension");
    assert!(has_basic_constraints, "CA certificate should have Basic Constraints extension");
    assert!(has_subject_key_identifier, "Certificate should have Subject Key Identifier extension");
    assert!(has_authority_key_identifier, "Self-signed certificate should have Authority Key Identifier extension");
}
