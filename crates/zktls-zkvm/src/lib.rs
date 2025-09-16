//! Shared zkTLS business logic
//! 
//! This crate provides platform-agnostic zkTLS verification logic that can be used
//! by any zkVM platform (SP1, RISC0, future zkVMs). It contains the core business
//! logic for TLS verification without any platform-specific dependencies.

pub mod types;
pub mod guest;

// Re-export commonly used types and functions
pub use types::*;
pub use guest::verify_zktls_session;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_agnostic_types() {
        let input = ZkTlsInput {
            domain: "example.com".to_string(),
            handshake_transcript: vec![1, 2, 3, 4],
            certificates: vec![vec![5, 6, 7, 8]],
            http_request: vec![9, 10, 11, 12],
            http_response: vec![13, 14, 15, 16],
            timestamp: 1234567890,
            metadata: ZkTlsMetadata {
                tls_version: "1.3".to_string(),
                cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
                client_random: [0u8; 32],
                server_random: [0u8; 32],
                session_id: None,
                extensions: vec![],
            },
        };

        let claim = ZkTlsProofClaim {
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
                platform: "test".to_string(),
                proof_time_ms: 50,
            },
        };

        assert_eq!(input.domain, claim.domain);
        assert_eq!(input.timestamp, claim.timestamp);
    }

    #[test]
    fn test_verification_result() {
        let claim = ZkTlsProofClaim {
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
                platform: "test".to_string(),
                proof_time_ms: 50,
            },
        };

        let stats = ExecutionMetadata {
            cycles: 1000,
            memory_usage: 1024,
            execution_time_ms: 100,
            platform: "test".to_string(),
            proof_time_ms: 50,
        };

        let success_result = ZkTlsVerificationResult::success(claim.clone(), stats.clone());
        assert!(success_result.is_success());
        assert!(!success_result.is_failure());
        assert_eq!(success_result.claim, Some(claim));

        let error = ZkTlsError::HandshakeError("Test error".to_string());
        let failure_result = ZkTlsVerificationResult::failure(error.clone(), stats);
        assert!(!failure_result.is_success());
        assert!(failure_result.is_failure());
        assert_eq!(failure_result.error, Some(error));
    }
}