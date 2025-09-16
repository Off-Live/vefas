//! Session Key Derivation Tests for zkTLS Verification
//!
//! This module contains comprehensive TDD tests for session key derivation
//! functionality in the zkVM guest program, following TLS 1.3 specification (RFC 8446).

#[cfg(feature = "sp1")]
mod session_key_derivation_tests {
    use zktls_zkvm::types::*;
    use zktls_zkvm::guest::{HandshakeData, derive_session_keys};
    use zktls_core::tls::key_schedule::{Tls13KeySchedule, HandshakeTrafficSecrets, ApplicationTrafficSecrets};
    use zktls_crypto::native::NativeCryptoProvider;
    use zktls_crypto::KeyExchange;
    
    mod fixtures;
    use fixtures::*;

    /// Test X25519 ECDHE shared secret computation
    #[test]
    fn test_x25519_ecdhe_shared_secret() {
        let crypto_provider = NativeCryptoProvider::new();
        
        // Test with known test vectors
        let client_private = CLIENT_PRIVATE_KEY.to_vec();
        let server_public = SERVER_PUBLIC_KEY;
        
        // Compute shared secret
        let shared_secret = crypto_provider.x25519_diffie_hellman(&client_private, server_public)
            .expect("Failed to compute X25519 shared secret");
        
        // Verify shared secret length
        assert_eq!(shared_secret.len(), 32, "X25519 shared secret should be 32 bytes");
        
        // Verify against expected value
        assert_eq!(shared_secret, EXPECTED_SHARED_SECRET, "Shared secret should match expected value");
    }

    /// Test TLS 1.3 key schedule initialization
    #[test]
    fn test_tls13_key_schedule_initialization() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Derive early secret
        key_schedule.derive_early_secret(None)
            .expect("Failed to derive early secret");
        
        // Test that we can proceed to handshake secret derivation
        let shared_secret = EXPECTED_SHARED_SECRET.to_vec();
        key_schedule.derive_handshake_secret(&shared_secret)
            .expect("Failed to derive handshake secret");
    }

    /// Test handshake secret derivation
    #[test]
    fn test_handshake_secret_derivation() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Derive early secret first
        key_schedule.derive_early_secret(None)
            .expect("Failed to derive early secret");
        
        // Derive handshake secret using shared secret
        let shared_secret = EXPECTED_SHARED_SECRET.to_vec();
        key_schedule.derive_handshake_secret(&shared_secret)
            .expect("Failed to derive handshake secret");
        
        // Test that we can derive handshake traffic secrets
        let handshake_transcript = HANDSHAKE_TRANSCRIPT.to_vec();
        let traffic_secrets = key_schedule.derive_handshake_traffic_secrets(&handshake_transcript)
            .expect("Failed to derive handshake traffic secrets");
        
        assert_eq!(traffic_secrets.client_handshake_traffic_secret.len(), 32);
        assert_eq!(traffic_secrets.server_handshake_traffic_secret.len(), 32);
    }

    /// Test master secret derivation
    #[test]
    fn test_master_secret_derivation() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Complete the key schedule up to master secret
        key_schedule.derive_early_secret(None)
            .expect("Failed to derive early secret");
        
        let shared_secret = EXPECTED_SHARED_SECRET.to_vec();
        key_schedule.derive_handshake_secret(&shared_secret)
            .expect("Failed to derive handshake secret");
        
        // Derive master secret
        key_schedule.derive_master_secret()
            .expect("Failed to derive master secret");
        
        // Test that we can derive application traffic secrets
        let application_transcript = APPLICATION_TRANSCRIPT.to_vec();
        let traffic_secrets = key_schedule.derive_application_traffic_secrets(&application_transcript)
            .expect("Failed to derive application traffic secrets");
        
        assert_eq!(traffic_secrets.client_application_traffic_secret.len(), 32);
        assert_eq!(traffic_secrets.server_application_traffic_secret.len(), 32);
    }

    /// Test handshake traffic secrets derivation
    #[test]
    fn test_handshake_traffic_secrets_derivation() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Complete key schedule
        key_schedule.derive_early_secret(None)
            .expect("Failed to derive early secret");
        
        let shared_secret = EXPECTED_SHARED_SECRET.to_vec();
        key_schedule.derive_handshake_secret(&shared_secret)
            .expect("Failed to derive handshake secret");
        
        // Derive handshake traffic secrets
        let handshake_transcript = HANDSHAKE_TRANSCRIPT.to_vec();
        let traffic_secrets = key_schedule.derive_handshake_traffic_secrets(&handshake_transcript)
            .expect("Failed to derive handshake traffic secrets");
        
        // Verify traffic secrets structure
        assert_eq!(traffic_secrets.client_handshake_traffic_secret.len(), 32);
        assert_eq!(traffic_secrets.server_handshake_traffic_secret.len(), 32);
        
        // Verify secrets are different
        assert_ne!(
            traffic_secrets.client_handshake_traffic_secret,
            traffic_secrets.server_handshake_traffic_secret,
            "Client and server handshake traffic secrets should be different"
        );
    }

    /// Test application traffic secrets derivation
    #[test]
    fn test_application_traffic_secrets_derivation() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Complete key schedule
        key_schedule.derive_early_secret(None)
            .expect("Failed to derive early secret");
        
        let shared_secret = EXPECTED_SHARED_SECRET.to_vec();
        key_schedule.derive_handshake_secret(&shared_secret)
            .expect("Failed to derive handshake secret");
        
        key_schedule.derive_master_secret()
            .expect("Failed to derive master secret");
        
        // Derive application traffic secrets
        let application_transcript = APPLICATION_TRANSCRIPT.to_vec();
        let traffic_secrets = key_schedule.derive_application_traffic_secrets(&application_transcript)
            .expect("Failed to derive application traffic secrets");
        
        // Verify traffic secrets structure
        assert_eq!(traffic_secrets.client_application_traffic_secret.len(), 32);
        assert_eq!(traffic_secrets.server_application_traffic_secret.len(), 32);
        
        // Verify secrets are different
        assert_ne!(
            traffic_secrets.client_application_traffic_secret,
            traffic_secrets.server_application_traffic_secret,
            "Client and server application traffic secrets should be different"
        );
    }

    /// Test traffic keys derivation for AES-GCM
    #[test]
    fn test_traffic_keys_derivation_aes_gcm() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Complete key schedule
        key_schedule.derive_early_secret(None)
            .expect("Failed to derive early secret");
        
        let shared_secret = EXPECTED_SHARED_SECRET.to_vec();
        key_schedule.derive_handshake_secret(&shared_secret)
            .expect("Failed to derive handshake secret");
        
        let handshake_transcript = HANDSHAKE_TRANSCRIPT.to_vec();
        let traffic_secrets = key_schedule.derive_handshake_traffic_secrets(&handshake_transcript)
            .expect("Failed to derive handshake traffic secrets");
        
        // Derive traffic keys for client
        let client_keys = key_schedule.derive_traffic_keys(
            &traffic_secrets.client_handshake_traffic_secret,
            16 // AES-128-GCM key length
        ).expect("Failed to derive client traffic keys");
        
        // Verify key structure
        assert_eq!(client_keys.key.len(), 16, "AES-128-GCM key should be 16 bytes");
        assert_eq!(client_keys.iv.len(), 12, "AES-GCM IV should be 12 bytes");
    }

    /// Test session key derivation integration with handshake data
    #[test]
    fn test_session_key_derivation_integration() {
        // Create handshake data with key exchange information
        let handshake_data = HandshakeData {
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            client_random: CLIENT_RANDOM,
            server_random: SERVER_RANDOM,
            key_exchange_params: EXPECTED_SHARED_SECRET.to_vec(),
        };
        
        // Test session key derivation
        let session_keys = derive_session_keys(&handshake_data)
            .expect("Failed to derive session keys");
        
        // Verify session keys structure
        assert_eq!(session_keys.handshake_secret.len(), 32);
        assert_eq!(session_keys.master_secret.len(), 32);
        assert_eq!(session_keys.client_write_key.len(), 16);
        assert_eq!(session_keys.server_write_key.len(), 16);
        assert_eq!(session_keys.client_write_iv.len(), 12);
        assert_eq!(session_keys.server_write_iv.len(), 12);
        
        // Verify keys are not all zeros (should be derived from real data)
        assert_ne!(session_keys.handshake_secret, [0u8; 32]);
        assert_ne!(session_keys.master_secret, [0u8; 32]);
        assert_ne!(session_keys.client_write_key, [0u8; 16]);
        assert_ne!(session_keys.server_write_key, [0u8; 16]);
    }

    /// Test session key derivation with invalid handshake data
    #[test]
    fn test_session_key_derivation_invalid_data() {
        // Test with empty key exchange params
        let handshake_data = HandshakeData {
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            client_random: CLIENT_RANDOM,
            server_random: SERVER_RANDOM,
            key_exchange_params: vec![], // Empty - should cause error
        };
        
        let result = derive_session_keys(&handshake_data);
        assert!(result.is_err(), "Should fail with missing client hello");
    }

    /// Test session key derivation performance
    #[test]
    fn test_session_key_derivation_performance() {
        let handshake_data = HandshakeData {
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            client_random: CLIENT_RANDOM,
            server_random: SERVER_RANDOM,
            key_exchange_params: EXPECTED_SHARED_SECRET.to_vec(),
        };
        
        // Measure derivation time
        let start = std::time::Instant::now();
        
        for _ in 0..100 {
            let _session_keys = derive_session_keys(&handshake_data)
                .expect("Failed to derive session keys");
        }
        
        let duration = start.elapsed();
        let avg_time = duration.as_millis() / 100;
        
        // Session key derivation should be fast (under 10ms per operation)
        assert!(avg_time < 10, "Session key derivation should be fast, got {}ms average", avg_time);
    }

    /// Test session key derivation with different cipher suites
    #[test]
    fn test_session_key_derivation_different_cipher_suites() {
        let cipher_suites = vec![
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384", 
            "TLS_CHACHA20_POLY1305_SHA256",
        ];
        
        for cipher_suite in cipher_suites {
            let handshake_data = HandshakeData {
                tls_version: "1.3".to_string(),
                cipher_suite: cipher_suite.to_string(),
                client_random: CLIENT_RANDOM,
                server_random: SERVER_RANDOM,
                key_exchange_params: EXPECTED_SHARED_SECRET.to_vec(),
            };
            
            let session_keys = derive_session_keys(&handshake_data)
                .expect(&format!("Failed to derive session keys for {}", cipher_suite));
            
            // Verify keys are derived (not all zeros)
            assert_ne!(session_keys.handshake_secret, [0u8; 32], "Handshake secret should be derived for {}", cipher_suite);
            assert_ne!(session_keys.master_secret, [0u8; 32], "Master secret should be derived for {}", cipher_suite);
        }
    }
}
