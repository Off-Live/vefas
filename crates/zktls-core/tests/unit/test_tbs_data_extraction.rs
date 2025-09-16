use zktls_core::x509::certificate::X509Certificate;

/// Test TBS (To-Be-Signed) data extraction from X.509 certificates
/// 
/// This test verifies that we can correctly extract the TBS portion of 
/// a certificate, which is required for signature verification.
#[test]
fn test_tbs_data_extraction() {
    // Use self-signed test certificate with predictable structure
    let cert_der = include_bytes!("../../../fixtures/certificates/self_signed.der");
    
    let cert = X509Certificate::parse(cert_der).expect("Certificate should parse");
    
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

/// Test TBS data extraction with real Let's Encrypt certificate
#[test] 
fn test_tbs_data_real_certificate() {
    // Use a real Let's Encrypt certificate for testing
    let cert_der = include_bytes!("../../../fixtures/certificates/letsencrypt_leaf.der");
    
    let cert = X509Certificate::parse(cert_der).expect("Real certificate should parse");
    
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

/// Test TBS data extraction preserves ASN.1 structure
#[test]
fn test_tbs_data_asn1_structure() {
    let cert_der = include_bytes!("../../../fixtures/certificates/test_ecdsa_cert.der");
    
    let cert = X509Certificate::parse(cert_der).expect("ECDSA certificate should parse");
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

/// Test that TBS extraction fails gracefully with malformed input
#[test]
fn test_tbs_data_extraction_invalid_certificate() {
    // Malformed certificate - too short to contain proper structure
    let malformed_der = &[0x30, 0x05, 0x01, 0x02, 0x03];
    
    // Parsing should fail, so we don't get to TBS extraction
    let result = X509Certificate::parse(malformed_der);
    assert!(result.is_err(), "Malformed certificate should fail to parse");
}