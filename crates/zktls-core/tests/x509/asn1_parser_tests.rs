//! Comprehensive ASN.1 DER parser tests
//!
//! These tests define the expected behavior of the ASN.1 DER parser,
//! following strict TDD methodology. Tests are based on real certificate
//! data and known test vectors.

use hex_literal::hex;
use zktls_core::asn1::*;

/// Test DER length parsing - short form (< 128 bytes)
#[test] 
fn test_parse_length_short_form() {
    // Length = 5 (0x05)
    let input = &[0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
    
    let result = DerParser::parse_length(input);
    assert!(result.is_ok());
    
    let (remaining, length) = result.unwrap();
    assert_eq!(length.value, 5);
    assert_eq!(length.encoded_len, 1);
    assert_eq!(remaining, &[0x01, 0x02, 0x03, 0x04, 0x05]);
}

/// Test DER length parsing - long form (>= 128 bytes)
#[test]
fn test_parse_length_long_form() {
    // Length = 255 (0x81 0xFF) - long form with 1 byte
    let input = &[0x81, 0xFF, 0x01, 0x02];
    
    let result = DerParser::parse_length(input);
    assert!(result.is_ok());
    
    let (remaining, length) = result.unwrap();
    assert_eq!(length.value, 255);
    assert_eq!(length.encoded_len, 2);
    assert_eq!(remaining, &[0x01, 0x02]);
}

/// Test DER length parsing - multi-byte long form
#[test]
fn test_parse_length_multi_byte() {
    // Length = 1024 (0x82 0x04 0x00) - long form with 2 bytes
    let input = &[0x82, 0x04, 0x00, 0xAA, 0xBB];
    
    let result = DerParser::parse_length(input);
    assert!(result.is_ok());
    
    let (remaining, length) = result.unwrap();
    assert_eq!(length.value, 1024);
    assert_eq!(length.encoded_len, 3);
    assert_eq!(remaining, &[0xAA, 0xBB]);
}

/// Test rejection of indefinite length (BER only, not allowed in DER)
#[test]
fn test_reject_indefinite_length() {
    // Indefinite length = 0x80
    let input = &[0x80, 0x01, 0x02];
    
    let result = DerParser::parse_length(input);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Asn1Error::IndefiniteLength);
}

/// Test rejection of non-minimal length encoding
#[test]
fn test_reject_non_minimal_length() {
    // Length = 127, but encoded in long form (0x81 0x7F) - should be 0x7F
    let input = &[0x81, 0x7F, 0x01, 0x02];
    
    let result = DerParser::parse_length(input);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Asn1Error::NonMinimalLength);
}

/// Test INTEGER parsing - valid positive integer
#[test]
fn test_parse_integer_positive() {
    // INTEGER value: 255 (0x00FF to avoid negative interpretation)
    let content = &[0x00, 0xFF];
    
    let result = DerParser::parse_integer(content);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), &[0x00, 0xFF]);
}

/// Test INTEGER parsing - valid negative integer  
#[test]
fn test_parse_integer_negative() {
    // INTEGER value: -1 (0xFF)
    let content = &[0xFF];
    
    let result = DerParser::parse_integer(content);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), &[0xFF]);
}

/// Test INTEGER parsing - reject empty integer
#[test]
fn test_reject_empty_integer() {
    let content = &[];
    
    let result = DerParser::parse_integer(content);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Asn1Error::InvalidInteger);
}

/// Test INTEGER parsing - reject unnecessary leading zeros
#[test]
fn test_reject_integer_leading_zeros() {
    // Invalid: 255 encoded as 0x00 0x00 0xFF (unnecessary leading zero)
    let content = &[0x00, 0x00, 0xFF];
    
    let result = DerParser::parse_integer(content);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Asn1Error::InvalidInteger);
}

/// Test BIT STRING parsing - valid with no unused bits
#[test]
fn test_parse_bit_string_no_unused() {
    // BIT STRING: unused bits = 0, data = [0xFF, 0x00]
    let content = &[0x00, 0xFF, 0x00];
    
    let result = DerParser::parse_bit_string(content);
    assert!(result.is_ok());
    
    let (data, unused_bits) = result.unwrap();
    assert_eq!(unused_bits, 0);
    assert_eq!(data, &[0xFF, 0x00]);
}

/// Test BIT STRING parsing - valid with unused bits
#[test]
fn test_parse_bit_string_with_unused() {
    // BIT STRING: unused bits = 3, data = [0xF8] (11111000)
    let content = &[0x03, 0xF8];
    
    let result = DerParser::parse_bit_string(content);
    assert!(result.is_ok());
    
    let (data, unused_bits) = result.unwrap();
    assert_eq!(unused_bits, 3);
    assert_eq!(data, &[0xF8]);
}

/// Test BIT STRING parsing - reject invalid unused bits
#[test]
fn test_reject_bit_string_invalid_unused() {
    // Invalid: unused bits = 8 (must be 0-7)
    let content = &[0x08, 0xFF];
    
    let result = DerParser::parse_bit_string(content);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Asn1Error::InvalidBitString);
}

/// Test BIT STRING parsing - reject non-zero trailing bits
#[test]
fn test_reject_bit_string_non_zero_trailing() {
    // Invalid: unused bits = 3, but trailing bits are not zero (0xF9 = 11111001)
    let content = &[0x03, 0xF9];
    
    let result = DerParser::parse_bit_string(content);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Asn1Error::InvalidBitString);
}

/// Test OBJECT IDENTIFIER parsing - valid OID
#[test]
fn test_parse_oid_valid() {
    // OID: 1.2.840.113549 (RSA encryption OID)
    // Encoding: 40*1 + 2 = 42 (0x2A), 840 (0x86 0x48), 113549 (0x86 0xF7 0x0D)
    let content = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D];
    
    let result = DerParser::parse_oid(content);
    assert!(result.is_ok());
    
    let oid_components = result.unwrap();
    assert_eq!(oid_components, vec![1, 2, 840, 113549]);
}

/// Test OBJECT IDENTIFIER parsing - reject empty OID
#[test]
fn test_reject_empty_oid() {
    let content = &[];
    
    let result = DerParser::parse_oid(content);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Asn1Error::InvalidOid);
}

/// Test OBJECT IDENTIFIER parsing - reject truncated OID
#[test]
fn test_reject_truncated_oid() {
    // Truncated: starts multi-byte component but doesn't complete it
    let content = &[0x2A, 0x86]; // Missing continuation
    
    let result = DerParser::parse_oid(content);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Asn1Error::InvalidOid);
}

/// Test complete DER value parsing - simple INTEGER
#[test]
fn test_parse_der_value_integer() {
    // DER: INTEGER tag (0x02), length (0x01), value (0x05)
    let input = &[0x02, 0x01, 0x05];
    
    let result = DerParser::parse_value(input, 0);
    assert!(result.is_ok());
    
    let (remaining, value) = result.unwrap();
    assert_eq!(remaining, &[]);
    assert_eq!(value.tag.tag, 0x02);
    assert_eq!(value.content, &[0x05]);
    assert_eq!(value.total_len, 3);
}

/// Test complete DER value parsing - SEQUENCE
#[test]
fn test_parse_der_value_sequence() {
    // DER: SEQUENCE tag (0x30), length (0x06), content: INTEGER(1) + INTEGER(2)
    // Content: 02 01 01 02 01 02
    let input = hex!("30 06 02 01 01 02 01 02");
    
    let result = DerParser::parse_value(&input, 0);
    assert!(result.is_ok());
    
    let (remaining, value) = result.unwrap();
    assert_eq!(remaining, &[]);
    assert_eq!(value.tag.tag, 0x30);
    assert_eq!(value.content, &hex!("02 01 01 02 01 02"));
    assert_eq!(value.total_len, 8);
}

/// Test SEQUENCE iteration
#[test]  
fn test_sequence_iteration() {
    // SEQUENCE content: INTEGER(1) + INTEGER(2)
    let content = hex!("02 01 01 02 01 02");
    
    let result = DerParser::parse_sequence(&content, 1);
    assert!(result.is_ok());
    
    let mut iter = result.unwrap();
    
    // First element: INTEGER(1)
    let first = iter.next();
    assert!(first.is_some());
    let first_value = first.unwrap();
    assert!(first_value.is_ok());
    let first_value = first_value.unwrap();
    assert_eq!(first_value.tag.tag, 0x02);
    assert_eq!(first_value.content, &[0x01]);
    
    // Second element: INTEGER(2)
    let second = iter.next();
    assert!(second.is_some());
    let second_value = second.unwrap();
    assert!(second_value.is_ok());
    let second_value = second_value.unwrap();
    assert_eq!(second_value.tag.tag, 0x02);
    assert_eq!(second_value.content, &[0x02]);
    
    // No more elements
    let third = iter.next();
    assert!(third.is_none());
}

/// Test maximum depth enforcement
#[test]
fn test_max_depth_enforcement() {
    // Create deeply nested SEQUENCE
    let input = &[0x30, 0x02, 0x30, 0x00]; // SEQUENCE { SEQUENCE {} }
    
    // Should fail at maximum depth
    let result = DerParser::parse_value(input, zktls_core::asn1::types::MAX_SEQUENCE_DEPTH);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Asn1Error::MaxDepthExceeded);
}

/// Test malformed input handling
#[test]
fn test_malformed_input_handling() {
    // Truncated input - tag but no length
    let input = &[0x02];
    
    let result = DerParser::parse_value(input, 0);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Asn1Error::UnexpectedEof);
}

/// Test insufficient data for declared length
#[test]
fn test_insufficient_data() {
    // Tag + length declares 5 bytes, but only 3 available
    let input = &[0x02, 0x05, 0x01, 0x02, 0x03];
    
    let result = DerParser::parse_value(input, 0);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Asn1Error::InsufficientData { expected: 5, available: 3 });
}