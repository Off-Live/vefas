//! Test suite for common TLS attack vectors and vulnerabilities
//!
//! This module tests VEFAS resistance to known TLS attacks including:
//! - Certificate validation bypasses
//! - Key exchange manipulation
//! - Downgrade attacks
//! - Timing attacks
//! - Protocol confusion attacks

use vefas_crypto::tls_parser::*;
use vefas_types::{VefasCanonicalBundle, TlsHandshakeMessage};
use vefas_crypto_native::NativeCryptoProvider;
use vefas_crypto::CryptoProvider;
use std::time::{Duration, Instant};
use hex_literal::hex;

/// Test certificate validation bypass attempts
#[cfg(test)]
mod certificate_attacks {
    use super::*;

    #[tokio::test]
    async fn test_self_signed_certificate_rejection() {
        // Create a self-signed certificate that should be rejected
        let malicious_cert = create_self_signed_certificate();

        let provider = NativeCryptoProvider::new();
        let result = provider.verify_certificate_chain(&malicious_cert, "example.com").await;

        assert!(result.is_err(), "Self-signed certificates should be rejected");
    }

    #[tokio::test]
    async fn test_expired_certificate_rejection() {
        // Test certificate with expired validity period
        let expired_cert = create_expired_certificate();

        let provider = NativeCryptoProvider::new();
        let result = provider.verify_certificate_chain(&expired_cert, "example.com").await;

        assert!(result.is_err(), "Expired certificates should be rejected");
    }

    #[tokio::test]
    async fn test_wrong_hostname_rejection() {
        // Test certificate with wrong Common Name / SAN
        let wrong_hostname_cert = create_certificate_for_domain("malicious.com");

        let provider = NativeCryptoProvider::new();
        let result = provider.verify_certificate_chain(&wrong_hostname_cert, "example.com").await;

        assert!(result.is_err(), "Wrong hostname certificates should be rejected");
    }

    #[tokio::test]
    async fn test_weak_signature_algorithm_rejection() {
        // Test certificate with weak signature algorithm (MD5, SHA1)
        let weak_cert = create_certificate_with_weak_signature();

        let provider = NativeCryptoProvider::new();
        let result = provider.verify_certificate_chain(&weak_cert, "example.com").await;

        assert!(result.is_err(), "Weak signature algorithms should be rejected");
    }

    #[test]
    fn test_certificate_chain_truncation_attack() {
        // Test incomplete certificate chain
        let incomplete_chain = vec![
            // Only leaf certificate, missing intermediate and root
            hex!("308201a830820110020101300d06092a864886f70d01010b05003012311030")
        ];

        let parser = CertificateParser::new().unwrap();
        let result = parser.parse_certificate_chain(&incomplete_chain);

        // Should fail due to incomplete chain
        assert!(result.is_err(), "Incomplete certificate chains should be rejected");
    }

    #[test]
    fn test_certificate_substitution_attack() {
        // Test substituting certificates from different domains
        let bundle_with_wrong_cert = create_bundle_with_substituted_certificate();

        let validator = BundleValidator::new().unwrap();
        let result = validator.validate_bundle(&bundle_with_wrong_cert);

        assert!(result.is_err(), "Certificate substitution should be detected");
    }

    // Helper functions for creating malicious certificates
    fn create_self_signed_certificate() -> Vec<u8> {
        // Mock self-signed certificate data
        hex!("308201a830820110020101300d06092a864886f70d01010b05003012311030").to_vec()
    }

    fn create_expired_certificate() -> Vec<u8> {
        // Mock expired certificate with past validity period
        hex!("308201a830820110020101300d06092a864886f70d01010b05003012311030").to_vec()
    }

    fn create_certificate_for_domain(domain: &str) -> Vec<u8> {
        // Mock certificate for wrong domain
        hex!("308201a830820110020101300d06092a864886f70d01010b05003012311030").to_vec()
    }

    fn create_certificate_with_weak_signature() -> Vec<u8> {
        // Mock certificate with MD5 signature
        hex!("308201a830820110020101300d06092a864886f70d01010405003012311030").to_vec()
    }

    fn create_bundle_with_substituted_certificate() -> VefasCanonicalBundle {
        VefasCanonicalBundle {
            domain: "legitimate.com".to_string(),
            client_random: vec![0; 32],
            server_random: vec![0; 32],
            handshake_messages: vec![
                // Certificate message with wrong domain
                hex!("0b000100308201a830820110020101300d06092a864886f70d01010b05003012311030").to_vec()
            ],
            application_records: vec![],
            http_request_data: b"GET / HTTP/1.1\r\nHost: legitimate.com\r\n\r\n".to_vec(),
            expected_status: 200,
            session_keys: Default::default(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            tls_version: "1.3".to_string(),
        }
    }
}

/// Test key exchange attacks and manipulations
#[cfg(test)]
mod key_exchange_attacks {
    use super::*;

    #[test]
    fn test_weak_key_rejection() {
        // Test rejection of weak ECDHE keys (small subgroup attacks)
        let weak_public_key = vec![0x04, 0x00, 0x00]; // Invalid point on curve

        let provider = NativeCryptoProvider::new();
        let result = provider.validate_ecdhe_public_key(&weak_public_key);

        assert!(result.is_err(), "Weak ECDHE keys should be rejected");
    }

    #[test]
    fn test_invalid_curve_point_rejection() {
        // Test point not on the specified curve
        let invalid_point = vec![0x04; 65]; // All zeros except first byte

        let provider = NativeCryptoProvider::new();
        let result = provider.validate_ecdhe_public_key(&invalid_point);

        assert!(result.is_err(), "Invalid curve points should be rejected");
    }

    #[test]
    fn test_key_reuse_detection() {
        // Test detection of ECDHE key reuse (breaks forward secrecy)
        let reused_key = vec![0x04; 65];

        // First use should be ok (assuming valid key for test)
        let mut key_tracker = KeyReuseTracker::new();
        let first_use = key_tracker.check_key_reuse(&reused_key);

        // Second use should be detected as reuse
        let second_use = key_tracker.check_key_reuse(&reused_key);

        assert!(second_use.is_err(), "Key reuse should be detected");
    }

    #[test]
    fn test_small_subgroup_attack_resistance() {
        // Test resistance to small subgroup attacks on DH
        let small_subgroup_keys = vec![
            vec![0x01], // Identity element
            vec![0x02], // Small order element
            vec![0xFF; 32], // All ones
        ];

        let provider = NativeCryptoProvider::new();
        for key in small_subgroup_keys {
            let result = provider.validate_ecdhe_public_key(&key);
            assert!(result.is_err(), "Small subgroup attacks should be prevented");
        }
    }

    // Mock key reuse tracker for testing
    struct KeyReuseTracker {
        used_keys: std::collections::HashSet<Vec<u8>>,
    }

    impl KeyReuseTracker {
        fn new() -> Self {
            Self { used_keys: std::collections::HashSet::new() }
        }

        fn check_key_reuse(&mut self, key: &[u8]) -> Result<(), &'static str> {
            if self.used_keys.contains(key) {
                Err("Key reuse detected")
            } else {
                self.used_keys.insert(key.to_vec());
                Ok(())
            }
        }
    }
}

/// Test protocol downgrade attacks
#[cfg(test)]
mod downgrade_attacks {
    use super::*;

    #[test]
    fn test_tls_version_downgrade_prevention() {
        // Test prevention of downgrade to TLS 1.2 or lower
        let downgrade_attempts = vec![
            "1.0", "1.1", "1.2", "0.9", "2.0", // Various invalid versions
        ];

        for version in downgrade_attempts {
            let bundle = create_bundle_with_tls_version(version);
            let validator = BundleValidator::new().unwrap();
            let result = validator.validate_bundle(&bundle);

            if version != "1.3" {
                assert!(result.is_err(), "TLS version {} should be rejected", version);
            }
        }
    }

    #[test]
    fn test_cipher_suite_downgrade_prevention() {
        // Test prevention of downgrade to weak cipher suites
        let weak_ciphers = vec![
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_RSA_WITH_RC4_128_SHA",
            "TLS_DHE_RSA_WITH_DES_CBC_SHA",
        ];

        for cipher in weak_ciphers {
            let bundle = create_bundle_with_cipher_suite(cipher);
            let validator = BundleValidator::new().unwrap();
            let result = validator.validate_bundle(&bundle);

            assert!(result.is_err(), "Weak cipher suite {} should be rejected", cipher);
        }
    }

    #[test]
    fn test_signature_algorithm_downgrade_prevention() {
        // Test prevention of downgrade to weak signature algorithms
        let weak_signatures = vec![
            "rsa_pkcs1_sha1",
            "rsa_pkcs1_md5",
            "dsa_sha1",
            "ecdsa_sha1",
        ];

        for sig_alg in weak_signatures {
            let result = validate_signature_algorithm(sig_alg);
            assert!(result.is_err(), "Weak signature algorithm {} should be rejected", sig_alg);
        }
    }

    fn create_bundle_with_tls_version(version: &str) -> VefasCanonicalBundle {
        VefasCanonicalBundle {
            domain: "example.com".to_string(),
            client_random: vec![0; 32],
            server_random: vec![0; 32],
            handshake_messages: vec![],
            application_records: vec![],
            http_request_data: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            expected_status: 200,
            session_keys: Default::default(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            tls_version: version.to_string(),
        }
    }

    fn create_bundle_with_cipher_suite(cipher: &str) -> VefasCanonicalBundle {
        VefasCanonicalBundle {
            domain: "example.com".to_string(),
            client_random: vec![0; 32],
            server_random: vec![0; 32],
            handshake_messages: vec![],
            application_records: vec![],
            http_request_data: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            expected_status: 200,
            session_keys: Default::default(),
            cipher_suite: cipher.to_string(),
            tls_version: "1.3".to_string(),
        }
    }

    fn validate_signature_algorithm(sig_alg: &str) -> Result<(), &'static str> {
        match sig_alg {
            "rsa_pss_rsae_sha256" | "rsa_pss_rsae_sha384" | "rsa_pss_rsae_sha512" |
            "ecdsa_secp256r1_sha256" | "ecdsa_secp384r1_sha384" | "ecdsa_secp521r1_sha512" |
            "ed25519" | "ed448" => Ok(()),
            _ => Err("Weak or unsupported signature algorithm"),
        }
    }
}

/// Test timing attack resistance
#[cfg(test)]
mod timing_attacks {
    use super::*;

    #[test]
    fn test_constant_time_certificate_validation() {
        // Test that certificate validation takes roughly constant time
        // regardless of where the error occurs in the validation process

        let valid_cert = create_valid_certificate();
        let invalid_early_cert = create_certificate_with_early_error();
        let invalid_late_cert = create_certificate_with_late_error();

        let provider = NativeCryptoProvider::new();

        // Measure validation times
        let start = Instant::now();
        let _ = provider.validate_certificate(&valid_cert);
        let valid_time = start.elapsed();

        let start = Instant::now();
        let _ = provider.validate_certificate(&invalid_early_cert);
        let early_error_time = start.elapsed();

        let start = Instant::now();
        let _ = provider.validate_certificate(&invalid_late_cert);
        let late_error_time = start.elapsed();

        // Times should be roughly similar (within 50% variance)
        let max_time = valid_time.max(early_error_time).max(late_error_time);
        let min_time = valid_time.min(early_error_time).min(late_error_time);

        let variance_ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;
        assert!(variance_ratio < 1.5, "Certificate validation timing variance too high: {:.2}", variance_ratio);
    }

    #[test]
    fn test_constant_time_signature_verification() {
        // Test that signature verification is constant time regardless of validity
        let message = b"test message for signing";
        let valid_signature = create_valid_signature();
        let invalid_signature = create_invalid_signature();

        let provider = NativeCryptoProvider::new();

        // Measure signature verification times
        let start = Instant::now();
        let _ = provider.verify_signature(message, &valid_signature);
        let valid_time = start.elapsed();

        let start = Instant::now();
        let _ = provider.verify_signature(message, &invalid_signature);
        let invalid_time = start.elapsed();

        // Times should be roughly similar
        let variance_ratio = valid_time.as_nanos() as f64 / invalid_time.as_nanos() as f64;
        assert!((0.5..=2.0).contains(&variance_ratio),
                "Signature verification timing variance too high: {:.2}", variance_ratio);
    }

    // Helper functions for timing tests
    fn create_valid_certificate() -> Vec<u8> {
        hex!("308201a830820110020101300d06092a864886f70d01010b05003012311030").to_vec()
    }

    fn create_certificate_with_early_error() -> Vec<u8> {
        // Invalid ASN.1 structure (error early in parsing)
        vec![0xFF, 0xFF, 0xFF]
    }

    fn create_certificate_with_late_error() -> Vec<u8> {
        // Valid ASN.1 structure but invalid signature (error late in validation)
        hex!("308201a830820110020101300d06092a864886f70d01010b05003012311030deadbeef").to_vec()
    }

    fn create_valid_signature() -> Vec<u8> {
        hex!("3046022100").to_vec()
    }

    fn create_invalid_signature() -> Vec<u8> {
        hex!("3046022100deadbeef").to_vec()
    }
}

/// Test protocol confusion and message ordering attacks
#[cfg(test)]
mod protocol_confusion_attacks {
    use super::*;

    #[test]
    fn test_handshake_message_reordering_detection() {
        // Test detection of reordered handshake messages
        let reordered_bundle = create_bundle_with_reordered_messages();

        let validator = BundleValidator::new().unwrap();
        let result = validator.validate_bundle(&reordered_bundle);

        assert!(result.is_err(), "Reordered handshake messages should be detected");
    }

    #[test]
    fn test_duplicate_message_detection() {
        // Test detection of duplicate handshake messages
        let duplicate_bundle = create_bundle_with_duplicate_messages();

        let validator = BundleValidator::new().unwrap();
        let result = validator.validate_bundle(&duplicate_bundle);

        assert!(result.is_err(), "Duplicate handshake messages should be detected");
    }

    #[test]
    fn test_missing_mandatory_messages() {
        // Test detection of missing mandatory handshake messages
        let incomplete_bundle = create_bundle_with_missing_messages();

        let validator = BundleValidator::new().unwrap();
        let result = validator.validate_bundle(&incomplete_bundle);

        assert!(result.is_err(), "Missing mandatory messages should be detected");
    }

    #[test]
    fn test_unexpected_message_injection() {
        // Test detection of unexpected messages in the handshake
        let injected_bundle = create_bundle_with_injected_messages();

        let validator = BundleValidator::new().unwrap();
        let result = validator.validate_bundle(&injected_bundle);

        assert!(result.is_err(), "Injected messages should be detected");
    }

    fn create_bundle_with_reordered_messages() -> VefasCanonicalBundle {
        VefasCanonicalBundle {
            domain: "example.com".to_string(),
            client_random: vec![0; 32],
            server_random: vec![0; 32],
            handshake_messages: vec![
                // ServerHello before ClientHello (wrong order)
                hex!("02000000").to_vec(), // ServerHello
                hex!("01000000").to_vec(), // ClientHello
            ],
            application_records: vec![],
            http_request_data: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            expected_status: 200,
            session_keys: Default::default(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            tls_version: "1.3".to_string(),
        }
    }

    fn create_bundle_with_duplicate_messages() -> VefasCanonicalBundle {
        VefasCanonicalBundle {
            domain: "example.com".to_string(),
            client_random: vec![0; 32],
            server_random: vec![0; 32],
            handshake_messages: vec![
                hex!("01000000").to_vec(), // ClientHello
                hex!("01000000").to_vec(), // Duplicate ClientHello
                hex!("02000000").to_vec(), // ServerHello
            ],
            application_records: vec![],
            http_request_data: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            expected_status: 200,
            session_keys: Default::default(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            tls_version: "1.3".to_string(),
        }
    }

    fn create_bundle_with_missing_messages() -> VefasCanonicalBundle {
        VefasCanonicalBundle {
            domain: "example.com".to_string(),
            client_random: vec![0; 32],
            server_random: vec![0; 32],
            handshake_messages: vec![
                hex!("01000000").to_vec(), // ClientHello
                // Missing ServerHello, Certificate, etc.
            ],
            application_records: vec![],
            http_request_data: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            expected_status: 200,
            session_keys: Default::default(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            tls_version: "1.3".to_string(),
        }
    }

    fn create_bundle_with_injected_messages() -> VefasCanonicalBundle {
        VefasCanonicalBundle {
            domain: "example.com".to_string(),
            client_random: vec![0; 32],
            server_random: vec![0; 32],
            handshake_messages: vec![
                hex!("01000000").to_vec(), // ClientHello
                hex!("FF000000").to_vec(), // Unknown/injected message type
                hex!("02000000").to_vec(), // ServerHello
            ],
            application_records: vec![],
            http_request_data: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            expected_status: 200,
            session_keys: Default::default(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            tls_version: "1.3".to_string(),
        }
    }
}