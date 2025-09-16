//! SP1 integration tests for zkTLS verification
//! 
//! These tests verify that the zkTLS guest program works correctly
//! with the SP1 zkVM platform.

#[cfg(feature = "sp1")]
mod sp1_tests {
    use zktls_zkvm::*;
    use zktls_zkvm::sp1::utils;
    use zktls_zkvm::guest::{
        generate_request_commitment,
        generate_response_commitment,
        generate_certificate_chain_hash,
        generate_handshake_transcript_hash,
        verify_proof_claim,
    };

    #[test]
    fn test_sp1_guest_program_structure() {
        // Test that the guest program can be instantiated
        let input = utils::create_test_input();
        assert_eq!(input.domain, "example.com");
        assert_eq!(input.handshake_transcript.len(), 8);
        assert_eq!(input.certificates.len(), 2);
        assert_eq!(input.http_request.len(), 8);
        assert_eq!(input.http_response.len(), 8);
    }

    #[test]
    fn test_sp1_zk_tls_error_types() {
        // Test that all error types are properly defined
        let invalid_input_error = ZkTlsError::InvalidInput("test".to_string());
        let certificate_error = ZkTlsError::CertificateError("test".to_string());
        let crypto_error = ZkTlsError::CryptoError("test".to_string());
        let serialization_error = ZkTlsError::SerializationError("test".to_string());

        // Test error formatting
        assert!(invalid_input_error.to_string().contains("Invalid input"));
        assert!(certificate_error.to_string().contains("Certificate error"));
        assert!(crypto_error.to_string().contains("Crypto error"));
        assert!(serialization_error.to_string().contains("Serialization error"));
    }

    #[test]
    fn test_sp1_guest_program_commitments() {
        // Test commitment generation
        let data = b"test data for commitment generation";
        
        let request_commitment = generate_request_commitment(data).unwrap();
        let response_commitment = generate_response_commitment(data).unwrap();
        let certificate_chain_hash = generate_certificate_chain_hash(&[data.to_vec()]).unwrap();
        let handshake_transcript_hash = generate_handshake_transcript_hash(data).unwrap();
        
        // All commitments should be 32 bytes
        assert_eq!(request_commitment.len(), 32);
        assert_eq!(response_commitment.len(), 32);
        assert_eq!(certificate_chain_hash.len(), 32);
        assert_eq!(handshake_transcript_hash.len(), 32);
        
        // Identical input should produce identical commitments
        let request_commitment2 = generate_request_commitment(data).unwrap();
        assert_eq!(request_commitment, request_commitment2);
        
        // Different input should produce different commitments
        let different_data = b"different test data";
        let different_commitment = generate_request_commitment(different_data).unwrap();
        assert_ne!(request_commitment, different_commitment);
    }

    #[test]
    fn test_sp1_guest_program_proof_claim_validation() {
        // Test proof claim validation
        let valid_claim = ZkTlsProofClaim {
            domain: "example.com".to_string(),
            request_commitment: [1u8; 32],
            response_commitment: [2u8; 32],
            status_code: 200,
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            certificate_chain_hash: [3u8; 32],
            handshake_transcript_hash: [4u8; 32],
            timestamp: 1234567890,
            execution_metadata: ExecutionMetadata {
                cycles: 1000,
                memory_usage: 1024,
                execution_time_ms: 100,
                platform: "sp1".to_string(),
                proof_time_ms: 50,
            },
        };

        let invalid_claim = ZkTlsProofClaim {
            domain: "".to_string(), // Empty domain should fail
            request_commitment: [1u8; 32],
            response_commitment: [2u8; 32],
            status_code: 200,
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            certificate_chain_hash: [3u8; 32],
            handshake_transcript_hash: [4u8; 32],
            timestamp: 1234567890,
            execution_metadata: ExecutionMetadata {
                cycles: 1000,
                memory_usage: 1024,
                execution_time_ms: 100,
                platform: "sp1".to_string(),
                proof_time_ms: 50,
            },
        };

        assert!(verify_proof_claim(&valid_claim).is_ok());
        assert!(verify_proof_claim(&invalid_claim).is_err());
    }

    #[test]
    fn test_sp1_constraints_validation() {
        let valid_input = utils::create_test_input();
        assert!(utils::validate_sp1_constraints(&valid_input).is_ok());
        
        // Test oversized handshake transcript
        let mut invalid_input = valid_input.clone();
        invalid_input.handshake_transcript = vec![0; 2 * 1024 * 1024]; // 2MB
        assert!(utils::validate_sp1_constraints(&invalid_input).is_err());
        
        // Test too many certificates
        let mut invalid_input = valid_input.clone();
        invalid_input.certificates = vec![vec![0; 1000]; 15]; // 15 certificates
        assert!(utils::validate_sp1_constraints(&invalid_input).is_err());
        
        // Test oversized certificate
        let mut invalid_input = valid_input.clone();
        invalid_input.certificates = vec![vec![0; 65 * 1024]]; // 65KB certificate
        assert!(utils::validate_sp1_constraints(&invalid_input).is_err());
    }

    #[test]
    fn test_sp1_execution_metadata() {
        let metadata = utils::get_sp1_execution_metadata();
        assert_eq!(metadata.platform, "sp1");
        assert_eq!(metadata.cycles, 0); // Will be set by runtime
        assert_eq!(metadata.memory_usage, 0); // Will be set by runtime
    }

    #[test]
    fn test_sp1_serialization() {
        // Test that all types can be serialized and deserialized
        let input = utils::create_test_input();
        let serialized = bincode::serialize(&input).unwrap();
        let deserialized: ZkTlsInput = bincode::deserialize(&serialized).unwrap();
        
        assert_eq!(input.domain, deserialized.domain);
        assert_eq!(input.handshake_transcript, deserialized.handshake_transcript);
        assert_eq!(input.certificates, deserialized.certificates);
        assert_eq!(input.http_request, deserialized.http_request);
        assert_eq!(input.http_response, deserialized.http_response);
        assert_eq!(input.timestamp, deserialized.timestamp);
        assert_eq!(input.metadata.tls_version, deserialized.metadata.tls_version);
        assert_eq!(input.metadata.cipher_suite, deserialized.metadata.cipher_suite);
    }
}