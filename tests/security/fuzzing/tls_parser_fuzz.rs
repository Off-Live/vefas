//! Fuzzing tests for TLS parsing functions to identify security vulnerabilities
//!
//! This module implements comprehensive fuzzing for all TLS parsing components
//! to detect buffer overflows, malformed input handling, and other security issues.

use proptest::prelude::*;
use std::collections::HashMap;
use vefas_crypto::tls_parser::*;
use vefas_types::{TlsHandshakeMessage, TlsRecord, VefasCanonicalBundle};

/// Maximum size for fuzzing input to prevent memory exhaustion
const MAX_FUZZ_SIZE: usize = 65536;

/// Fuzzing strategy for arbitrary byte sequences
fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..MAX_FUZZ_SIZE)
}

/// Fuzzing strategy for malformed TLS records
fn malformed_tls_record() -> impl Strategy<Value = Vec<u8>> {
    (
        0u8..=255,         // content_type
        0u16..=65535,      // version
        0u16..=65535,      // length (can be wrong)
        arbitrary_bytes(), // payload
    )
        .prop_map(|(content_type, version, length, mut payload)| {
            let mut record = Vec::new();
            record.push(content_type);
            record.extend_from_slice(&version.to_be_bytes());
            record.extend_from_slice(&length.to_be_bytes());

            // Sometimes make payload size mismatch declared length
            if !payload.is_empty()
                && proptest::bool::ANY
                    .new_tree(&mut proptest::test_runner::TestRunner::default())
                    .unwrap()
                    .current()
            {
                let wrong_size = (length as usize).saturating_add(1).min(MAX_FUZZ_SIZE);
                payload.resize(wrong_size, 0);
            }

            record.extend_from_slice(&payload);
            record
        })
}

/// Fuzzing strategy for malformed handshake messages
fn malformed_handshake_message() -> impl Strategy<Value = Vec<u8>> {
    (
        0u8..=255,         // msg_type
        0u32..=16777215,   // length (24-bit)
        arbitrary_bytes(), // payload
    )
        .prop_map(|(msg_type, length, mut payload)| {
            let mut message = Vec::new();
            message.push(msg_type);

            // Encode 24-bit length (big-endian)
            let length_bytes = [
                ((length >> 16) & 0xFF) as u8,
                ((length >> 8) & 0xFF) as u8,
                (length & 0xFF) as u8,
            ];
            message.extend_from_slice(&length_bytes);

            // Sometimes create length/payload mismatches
            if !payload.is_empty()
                && proptest::bool::ANY
                    .new_tree(&mut proptest::test_runner::TestRunner::default())
                    .unwrap()
                    .current()
            {
                let wrong_size = (length as usize).saturating_add(1).min(MAX_FUZZ_SIZE);
                payload.resize(wrong_size, 0);
            }

            message.extend_from_slice(&payload);
            message
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Fuzz TLS record parsing with arbitrary malformed input
    #[test]
    fn fuzz_tls_record_parsing(data in malformed_tls_record()) {
        // Parsing should never panic, only return errors
        let result = std::panic::catch_unwind(|| {
            if let Ok(parser) = TlsRecordParser::new() {
                let _ = parser.parse_record(&data);
            }
        });

        // Ensure no panics occurred
        prop_assert!(result.is_ok(), "TLS record parsing panicked on malformed input");
    }

    /// Fuzz handshake message parsing with arbitrary malformed input
    #[test]
    fn fuzz_handshake_message_parsing(data in malformed_handshake_message()) {
        let result = std::panic::catch_unwind(|| {
            if let Ok(parser) = TlsHandshakeParser::new() {
                let _ = parser.parse_handshake_message(&data);
            }
        });

        prop_assert!(result.is_ok(), "Handshake message parsing panicked on malformed input");
    }

    /// Fuzz certificate parsing with arbitrary data
    #[test]
    fn fuzz_certificate_parsing(data in arbitrary_bytes()) {
        let result = std::panic::catch_unwind(|| {
            if let Ok(parser) = CertificateParser::new() {
                let _ = parser.parse_certificate_chain(&data);
            }
        });

        prop_assert!(result.is_ok(), "Certificate parsing panicked on malformed input");
    }

    /// Fuzz bundle validation with malformed bundles
    #[test]
    fn fuzz_bundle_validation(
        domain in "[a-zA-Z0-9.-]{1,253}",
        client_random in arbitrary_bytes(),
        server_random in arbitrary_bytes(),
        records in prop::collection::vec(arbitrary_bytes(), 0..10)
    ) {
        let result = std::panic::catch_unwind(|| {
            // Create a potentially malformed bundle
            let bundle = VefasCanonicalBundle {
                domain: domain.clone(),
                client_random,
                server_random,
                handshake_messages: vec![], // Empty handshake
                application_records: records,
                http_request_data: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
                expected_status: 200,
                session_keys: Default::default(),
                cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
                tls_version: "1.3".to_string(),
            };

            // Validation should handle malformed data gracefully
            if let Ok(validator) = BundleValidator::new() {
                let _ = validator.validate_bundle(&bundle);
            }
        });

        prop_assert!(result.is_ok(), "Bundle validation panicked on malformed input");
    }
}

/// Test edge cases that could cause integer overflows or memory issues
#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_oversized_length_fields() {
        // Test maximum possible length values
        let max_u16 = u16::MAX;
        let max_u24 = 0xFFFFFF;

        // TLS record with maximum length
        let mut record = vec![0x17]; // application_data
        record.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2
        record.extend_from_slice(&max_u16.to_be_bytes()); // Max length
        record.resize(record.len() + 100, 0); // But provide less data

        let result = std::panic::catch_unwind(|| {
            if let Ok(parser) = TlsRecordParser::new() {
                let _ = parser.parse_record(&record);
            }
        });
        assert!(result.is_ok(), "Should handle oversized length gracefully");

        // Handshake message with maximum length
        let mut handshake = vec![0x01]; // ClientHello
        let length_bytes = [
            ((max_u24 >> 16) & 0xFF) as u8,
            ((max_u24 >> 8) & 0xFF) as u8,
            (max_u24 & 0xFF) as u8,
        ];
        handshake.extend_from_slice(&length_bytes);
        handshake.resize(handshake.len() + 100, 0); // Provide less data than claimed

        let result = std::panic::catch_unwind(|| {
            if let Ok(parser) = TlsHandshakeParser::new() {
                let _ = parser.parse_handshake_message(&handshake);
            }
        });
        assert!(
            result.is_ok(),
            "Should handle oversized handshake length gracefully"
        );
    }

    #[test]
    fn test_zero_length_fields() {
        // Test zero-length records and messages
        let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x00]; // Empty application data

        let result = std::panic::catch_unwind(|| {
            if let Ok(parser) = TlsRecordParser::new() {
                let _ = parser.parse_record(&record);
            }
        });
        assert!(
            result.is_ok(),
            "Should handle zero-length records gracefully"
        );

        let handshake = vec![0x01, 0x00, 0x00, 0x00]; // Empty ClientHello

        let result = std::panic::catch_unwind(|| {
            if let Ok(parser) = TlsHandshakeParser::new() {
                let _ = parser.parse_handshake_message(&handshake);
            }
        });
        assert!(
            result.is_ok(),
            "Should handle zero-length handshake gracefully"
        );
    }

    #[test]
    fn test_malformed_certificate_chain() {
        // Test various malformed certificate scenarios
        let test_cases = vec![
            vec![],                       // Empty certificate list
            vec![0x00, 0x00, 0x00],       // Zero-length certificate
            vec![0xFF, 0xFF, 0xFF, 0x01], // Oversized certificate length with minimal data
            b"-----BEGIN CERTIFICATE-----\nmalformed\n-----END CERTIFICATE-----".to_vec(),
        ];

        for case in test_cases {
            let result = std::panic::catch_unwind(|| {
                if let Ok(parser) = CertificateParser::new() {
                    let _ = parser.parse_certificate_chain(&case);
                }
            });
            assert!(
                result.is_ok(),
                "Should handle malformed certificates gracefully"
            );
        }
    }

    #[test]
    fn test_bundle_with_inconsistent_data() {
        // Test bundles with internally inconsistent data
        let bundle = VefasCanonicalBundle {
            domain: "example.com".to_string(),
            client_random: vec![0; 32],
            server_random: vec![0; 32],
            handshake_messages: vec![],
            application_records: vec![vec![0xFF; 1000]], // Large record
            http_request_data: b"INVALID HTTP REQUEST".to_vec(), // Invalid HTTP
            expected_status: 999,                        // Invalid status code
            session_keys: Default::default(),
            cipher_suite: "INVALID_CIPHER".to_string(), // Invalid cipher
            tls_version: "1.4".to_string(),             // Invalid version
        };

        let result = std::panic::catch_unwind(|| {
            if let Ok(validator) = BundleValidator::new() {
                let _ = validator.validate_bundle(&bundle);
            }
        });
        assert!(
            result.is_ok(),
            "Should handle inconsistent bundle data gracefully"
        );
    }
}

/// Performance tests to ensure fuzzing doesn't reveal DoS vulnerabilities
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_parsing_performance_bounds() {
        // Ensure parsing large inputs completes within reasonable time
        let large_input = vec![0u8; 64 * 1024]; // 64KB of zeros

        let start = Instant::now();
        let result = std::panic::catch_unwind(|| {
            if let Ok(parser) = TlsRecordParser::new() {
                let _ = parser.parse_record(&large_input);
            }
        });
        let elapsed = start.elapsed();

        assert!(
            result.is_ok(),
            "Should handle large input without panicking"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "Parsing should complete within 1 second"
        );
    }

    #[test]
    fn test_nested_structure_limits() {
        // Ensure deeply nested or recursive structures don't cause stack overflow
        let mut nested_record = vec![0x16, 0x03, 0x03]; // Handshake record header

        // Create deeply nested handshake messages
        for _ in 0..1000 {
            nested_record.extend_from_slice(&[0x01, 0x00, 0x00, 0x04]); // Nested message header
            nested_record.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Minimal payload
        }

        let result = std::panic::catch_unwind(|| {
            if let Ok(parser) = TlsRecordParser::new() {
                let _ = parser.parse_record(&nested_record);
            }
        });
        assert!(
            result.is_ok(),
            "Should handle deeply nested structures gracefully"
        );
    }
}
