//! Cross-platform consistency tests for VEFAS shared utilities
//!
//! This test suite ensures that the shared utilities in vefas-crypto produce
//! identical results across different zkVM platforms (SP1 and RISC0).

use vefas_crypto::{
    http_utils::{hex_lower, parse_http_data, parse_http_request, parse_http_response, HttpData},
    input_validation::{parse_der_length, validate_tls_record_header, SafeParser},
    tls_parser::{
        cipher_suite_name, parse_handshake_header, parse_server_cipher_suite, remove_tls13_padding,
        validate_certificate_verify, validate_client_hello, validate_finished_message,
        validate_server_hello,
    },
    validation::{
        domain_matches, validate_certificate_chain_structure, validate_certificate_message,
        validate_der_structure, validate_x509_certificate,
    },
};
use vefas_types::VefasError;

/// Derive AEAD nonce from IV and sequence number
/// This is a test utility function for nonce derivation consistency
fn derive_aead_nonce(iv: &[u8], sequence_number: u64) -> Result<[u8; 12], VefasError> {
    if iv.len() != 12 {
        return Err(VefasError::invalid_input(
            "derive_aead_nonce",
            "IV must be exactly 12 bytes",
        ));
    }
    
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(iv);
    
    // XOR the last 8 bytes with the sequence number
    let seq_bytes = sequence_number.to_be_bytes();
    for (i, byte) in seq_bytes.iter().enumerate() {
        nonce[4 + i] ^= byte;
    }
    
    Ok(nonce)
}

#[test]
fn safe_parser_consistency() {
    let test_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut parser = SafeParser::new(&test_data);

    // Test u8 reading
    assert_eq!(parser.read_u8(), Some(0x01));
    assert_eq!(parser.remaining(), 7);

    // Test u16 reading
    assert_eq!(parser.read_u16(), Some(0x0203));
    assert_eq!(parser.remaining(), 5);

    // Test u24 reading
    assert_eq!(parser.read_u24(), Some(0x040506));
    assert_eq!(parser.remaining(), 2);

    // Test bytes reading
    assert_eq!(parser.read_bytes(2), Some(&[0x07, 0x08][..]));
    assert_eq!(parser.remaining(), 0);

    // Test out of bounds
    assert_eq!(parser.read_u8(), None);
}

#[test]
fn der_length_parsing_consistency() {
    // Short form
    let short_form = [0x05];
    assert_eq!(parse_der_length(&short_form), Some((5, 1)));

    // Long form
    let long_form = [0x82, 0x01, 0x00]; // Length 256 in long form
    assert_eq!(parse_der_length(&long_form), Some((256, 3)));

    // Invalid cases
    assert_eq!(parse_der_length(&[0x80]), None); // Indefinite length
    assert_eq!(parse_der_length(&[]), None); // Empty
}

#[test]
fn tls_record_validation_consistency() {
    // Valid application data record
    let valid_record = [23, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
    let result = validate_tls_record_header(&valid_record);
    assert!(result.is_ok());
    let (content_type, version, len) = result.unwrap();
    assert_eq!(content_type, 23);
    assert_eq!(version, 0x0303);
    assert_eq!(len, 5);

    // Invalid content type
    let invalid_record = [99, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
    assert!(validate_tls_record_header(&invalid_record).is_err());

    // Length mismatch
    let mismatch_record = [23, 0x03, 0x03, 0x00, 0x10, 1, 2, 3]; // Claims 16 bytes but only has 3
    assert!(validate_tls_record_header(&mismatch_record).is_err());
}

#[test]
fn handshake_parsing_consistency() {
    // Valid ClientHello
    let client_hello = [0x01, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5];
    let result = parse_handshake_header(&client_hello);
    assert!(result.is_some());
    let (msg_type, len, body) = result.unwrap();
    assert_eq!(msg_type, 0x01);
    assert_eq!(len, 5);
    assert_eq!(body, &[1, 2, 3, 4, 5]);

    // Valid ServerHello
    let server_hello = [0x02, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
    let result = parse_handshake_header(&server_hello);
    assert!(result.is_some());
    let (msg_type, len, body) = result.unwrap();
    assert_eq!(msg_type, 0x02);
    assert_eq!(len, 3);
    assert_eq!(body, &[0xAA, 0xBB, 0xCC]);

    // Invalid handshake type
    let invalid_hs = [0xFF, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
    assert!(parse_handshake_header(&invalid_hs).is_none());

    // Length overflow
    let overflow_hs = [0x01, 0xFF, 0xFF, 0xFF, 0xAA]; // Claims huge length
    assert!(parse_handshake_header(&overflow_hs).is_none());
}

#[test]
fn cipher_suite_parsing_consistency() {
    // Build minimal valid ServerHello with TLS_AES_128_GCM_SHA256
    let mut server_hello = Vec::new();
    server_hello.extend_from_slice(&[0x02, 0x00, 0x00, 38]); // handshake header
    server_hello.extend_from_slice(&[0x03, 0x03]); // legacy_version
    server_hello.extend_from_slice(&[0u8; 32]); // random
    server_hello.push(0); // session_id_length
    server_hello.extend_from_slice(&[0x13, 0x01]); // cipher_suite (TLS_AES_128_GCM_SHA256)
    server_hello.push(0); // compression_method

    let result = parse_server_cipher_suite(&server_hello);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0x1301);
    assert_eq!(cipher_suite_name(0x1301), "TLS_AES_128_GCM_SHA256");

    // Test unsupported cipher suite
    let mut bad_server_hello = Vec::new();
    bad_server_hello.extend_from_slice(&[0x02, 0x00, 0x00, 38]); // handshake header
    bad_server_hello.extend_from_slice(&[0x03, 0x03]); // legacy_version
    bad_server_hello.extend_from_slice(&[0u8; 32]); // random
    bad_server_hello.push(0); // session_id_length
    bad_server_hello.extend_from_slice(&[0x00, 0x35]); // unsupported cipher suite
    bad_server_hello.push(0); // compression_method

    let result = parse_server_cipher_suite(&bad_server_hello);
    assert!(result.is_err());
}

#[test]
fn certificate_validation_consistency() {
    // Test DER structure validation
    let valid_der = [0x30, 0x03, 0x01, 0x02, 0x03]; // SEQUENCE { 1, 2, 3 }
    assert!(validate_der_structure(&valid_der, 0).is_ok());

    let invalid_der = [0x31, 0x03, 0x01, 0x02, 0x03]; // SET instead of SEQUENCE
    assert!(validate_der_structure(&invalid_der, 0).is_err());

    // Test certificate size limits
    let too_short = vec![0u8; 50];
    assert!(validate_x509_certificate(&too_short, 0).is_err());

    let too_large = vec![0u8; 10000];
    assert!(validate_x509_certificate(&too_large, 0).is_err());

    // Test empty certificate chain
    let empty_chain: Vec<Vec<u8>> = vec![];
    assert!(validate_certificate_chain_structure(&empty_chain).is_err());

    // Test too long certificate chain
    let long_chain: Vec<Vec<u8>> = vec![vec![0u8; 100]; 15];
    assert!(validate_certificate_chain_structure(&long_chain).is_err());
}

#[test]
fn domain_matching_consistency() {
    // Direct match
    let cert_with_domain = b"random\x30DERbytes...example.com...more";
    assert!(domain_matches(cert_with_domain, "example.com").unwrap());

    // Wildcard match
    let cert_with_wildcard = b"...*.example.com...";
    assert!(domain_matches(cert_with_wildcard, "api.example.com").unwrap());

    // No match
    let cert_without_domain = b"no domains here";
    assert!(!domain_matches(cert_without_domain, "example.com").unwrap());

    // Empty domain
    assert!(!domain_matches(cert_with_domain, "").unwrap());
}

#[test]
fn http_parsing_consistency() {
    let request_data =
        b"GET /api/test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\ntest body";
    let response_data =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\ntest body";

    let http_data = HttpData::new(request_data.to_vec(), response_data.to_vec());
    let result = parse_http_data(&http_data);
    assert!(result.is_ok());

    let (method, path, status_code) = result.unwrap();
    assert_eq!(method, "GET");
    assert_eq!(path, "/api/test");
    assert_eq!(status_code, 200);

    // Test individual parsing
    let request = parse_http_request(request_data).unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/test");
    assert_eq!(request.version, "HTTP/1.1");
    assert_eq!(request.headers.len(), 2);

    let response = parse_http_response(response_data).unwrap();
    assert_eq!(response.status_code, 200);
    assert_eq!(response.status_text, "OK");
    assert_eq!(response.version, "HTTP/1.1");
    assert_eq!(response.headers.len(), 2);
}

#[test]
fn hex_encoding_consistency() {
    let test_data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    assert_eq!(hex_lower(&test_data), "0123456789abcdef");

    let empty_data = [];
    assert_eq!(hex_lower(&empty_data), "");

    let single_byte = [0xFF];
    assert_eq!(hex_lower(&single_byte), "ff");
}

#[test]
fn aead_nonce_derivation_consistency() {
    // Test identity case (sequence 0)
    let iv = [1u8; 12];
    let nonce = derive_aead_nonce(&iv, 0).expect("nonce derivation failed");
    assert_eq!(nonce, iv);

    // Test XOR behavior
    let zero_iv = [0u8; 12];
    let seq = 0x0102030405060708u64;
    let nonce = derive_aead_nonce(&zero_iv, seq).expect("nonce derivation failed");
    assert_eq!(&nonce[..4], &[0, 0, 0, 0]);
    assert_eq!(&nonce[4..], &seq.to_be_bytes());

    // Test invalid IV length
    let bad_iv = [0u8; 10];
    assert!(derive_aead_nonce(&bad_iv, 0).is_err());
}

#[test]
fn tls13_padding_removal_consistency() {
    // Valid case with padding and content type
    let mut plaintext = vec![1, 2, 3, 4, 0x16, 0, 0, 0]; // data + content type + padding
    let result = remove_tls13_padding(&mut plaintext);
    assert!(result.is_ok());
    assert_eq!(plaintext, vec![1, 2, 3, 4]);

    // Just content type, no padding
    let mut plaintext2 = vec![1, 2, 3, 0x16];
    let result = remove_tls13_padding(&mut plaintext2);
    assert!(result.is_ok());
    assert_eq!(plaintext2, vec![1, 2, 3]);

    // Empty plaintext
    let mut empty = vec![];
    assert!(remove_tls13_padding(&mut empty).is_err());

    // Only padding
    let mut only_padding = vec![0, 0, 0];
    assert!(remove_tls13_padding(&mut only_padding).is_err());
}

#[test]
fn message_validation_consistency() {
    // Valid messages
    let client_hello = [0x01, 0x00, 0x00, 0x00]; // ClientHello with empty body
    assert!(validate_client_hello(&client_hello).is_ok());

    let server_hello = [0x02, 0x00, 0x00, 0x00]; // ServerHello with empty body
    assert!(validate_server_hello(&server_hello).is_ok());

    let cert_verify = [0x0f, 0x00, 0x00, 0x00]; // CertificateVerify with empty body
    assert!(validate_certificate_verify(&cert_verify).is_ok());

    let finished = [0x14, 0x00, 0x00, 0x00]; // Finished with empty body
    assert!(validate_finished_message(&finished).is_ok());

    // Wrong message types
    let wrong_type = [0x99, 0x00, 0x00, 0x00]; // Invalid type
    assert!(validate_client_hello(&wrong_type).is_err());
    assert!(validate_server_hello(&wrong_type).is_err());
    assert!(validate_certificate_verify(&wrong_type).is_err());
    assert!(validate_finished_message(&wrong_type).is_err());

    // Malformed headers
    let too_short = [0x01, 0x00];
    assert!(validate_client_hello(&too_short).is_err());
}

#[test]
fn error_categorization_consistency() {
    // Test that errors have consistent categories
    let invalid_input_err = VefasError::invalid_input("test_field", "test reason");
    assert_eq!(invalid_input_err.category(), "input");

    let crypto_err = VefasError::crypto_error(
        vefas_types::errors::CryptoErrorType::InvalidKeyLength,
        "test crypto error",
    );
    assert_eq!(crypto_err.category(), "crypto");
}

#[test]
fn cross_platform_cipher_suite_handling() {
    // Test all supported cipher suites
    let supported_suites = [0x1301, 0x1302, 0x1303];
    let expected_names = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ];

    for (suite, expected) in supported_suites.iter().zip(expected_names.iter()) {
        assert_eq!(cipher_suite_name(*suite), *expected);
    }

    // Test unknown cipher suite
    assert_eq!(cipher_suite_name(0x9999), "UNKNOWN");
}

#[test]
fn cross_platform_validation_behavior() {
    // Test that validation functions behave consistently

    // Empty certificate chain
    let cert_msg = [0x0b, 0x00, 0x00, 0x00]; // Certificate handshake with empty body
    let empty_chain: Vec<Vec<u8>> = vec![];
    let result = validate_certificate_message(&cert_msg, &empty_chain);
    assert!(result.is_err());

    // Wrong handshake type for certificate message
    let wrong_msg = [0x01, 0x00, 0x00, 0x00]; // ClientHello instead of Certificate
    let chain = vec![vec![0u8; 200]]; // Valid-sized certificate
    let result = validate_certificate_message(&wrong_msg, &chain);
    assert!(result.is_err());
}

#[test]
fn parser_edge_cases_consistency() {
    let mut parser = SafeParser::new(&[1, 2, 3]);

    // Test seek operations
    assert!(parser.seek(1));
    assert_eq!(parser.offset(), 1);
    assert_eq!(parser.read_u8(), Some(2));

    // Test invalid seek
    assert!(!parser.seek(10));
    assert_eq!(parser.offset(), 2); // Should remain unchanged

    // Test reset
    parser.reset();
    assert_eq!(parser.offset(), 0);
    assert_eq!(parser.read_u8(), Some(1));

    // Test peek operations
    assert_eq!(parser.peek_u8(), Some(2));
    assert_eq!(parser.offset(), 1); // Should not advance

    // Test skip
    assert!(parser.skip(1));
    assert_eq!(parser.offset(), 2);
    assert_eq!(parser.read_u8(), Some(3));

    // Test skip beyond bounds
    assert!(!parser.skip(10));
    assert_eq!(parser.offset(), 3); // Should remain at end
}

#[cfg(test)]
mod platform_specific_tests {
    use super::*;

    // These tests would ideally run with both SP1 and RISC0 crypto providers
    // to ensure identical behavior, but for now we test the shared utilities
    // that both platforms use.

    #[test]
    fn shared_utilities_deterministic() {
        // Ensure shared utilities produce deterministic results
        let test_data = b"test data for deterministic verification";

        // Multiple calls should produce identical results
        let hash1 = hex_lower(test_data);
        let hash2 = hex_lower(test_data);
        assert_eq!(hash1, hash2);

        // Parser should behave deterministically
        let mut parser1 = SafeParser::new(test_data);
        let mut parser2 = SafeParser::new(test_data);

        assert_eq!(parser1.read_u32(), parser2.read_u32());
        assert_eq!(parser1.remaining(), parser2.remaining());
    }

    #[test]
    fn shared_validation_comprehensive() {
        // Test that shared validation logic is comprehensive

        // Test various invalid inputs that should be caught consistently
        let invalid_inputs = vec![
            vec![],             // Empty
            vec![0],            // Too short
            vec![0xFF; 100000], // Too large
        ];

        for input in invalid_inputs {
            // Should consistently reject invalid certificates
            assert!(validate_x509_certificate(&input, 0).is_err());

            // Should consistently reject invalid DER
            if !input.is_empty() {
                assert!(validate_der_structure(&input, 0).is_err());
            }
        }
    }

    #[test]
    fn error_handling_cross_platform() {
        // Ensure error handling is consistent across platforms

        // Test error creation and formatting
        let errors = vec![
            VefasError::invalid_input("test", "reason"),
            VefasError::crypto_error(
                vefas_types::errors::CryptoErrorType::InvalidKeyLength,
                "msg",
            ),
            VefasError::tls_error(vefas_types::errors::TlsErrorType::InvalidHandshake, "msg"),
        ];

        for error in errors {
            // All errors should have non-empty categories
            assert!(!error.category().is_empty());

            // All errors should format consistently
            let formatted = format!("{:?}", error);
            assert!(!formatted.is_empty());
        }
    }
}
