//! Platform-agnostic types for multi-zkVM support
//! 
//! This module defines the input/output structures that work across
//! different zkVM platforms (SP1, RISC0, future zkVMs).

use serde::{Deserialize, Serialize};

/// Platform-agnostic input structure for zkTLS verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkTlsInput {
    /// The target domain for TLS verification
    pub domain: String,
    /// Complete TLS handshake transcript (ClientHello through Finished)
    pub handshake_transcript: Vec<u8>,
    /// X.509 certificate chain (leaf, intermediate, root)
    pub certificates: Vec<Vec<u8>>,
    /// HTTP request data (method, headers, body)
    pub http_request: Vec<u8>,
    /// HTTP response data (status, headers, body)
    pub http_response: Vec<u8>,
    /// Timestamp for certificate validation
    pub timestamp: u64,
    /// Additional metadata for verification
    pub metadata: ZkTlsMetadata,
}

/// Metadata for zkTLS verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkTlsMetadata {
    /// TLS version (e.g., "1.3")
    pub tls_version: String,
    /// Cipher suite used
    pub cipher_suite: String,
    /// Client random (32 bytes)
    pub client_random: [u8; 32],
    /// Server random (32 bytes)
    pub server_random: [u8; 32],
    /// Session ID (if any)
    pub session_id: Option<Vec<u8>>,
    /// Additional extensions
    pub extensions: Vec<u8>,
}

/// Platform-agnostic output structure for zkTLS proof claims
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZkTlsProofClaim {
    /// The verified domain
    pub domain: String,
    /// SHA-256 commitment of the HTTP request
    pub request_commitment: [u8; 32],
    /// SHA-256 commitment of the HTTP response
    pub response_commitment: [u8; 32],
    /// HTTP status code
    pub status_code: u16,
    /// TLS version used
    pub tls_version: String,
    /// Cipher suite used
    pub cipher_suite: String,
    /// SHA-256 hash of the certificate chain
    pub certificate_chain_hash: [u8; 32],
    /// SHA-256 hash of the TLS handshake transcript
    pub handshake_transcript_hash: [u8; 32],
    /// Timestamp of the verification
    pub timestamp: u64,
    /// Execution metadata
    pub execution_metadata: ExecutionMetadata,
}

/// Execution metadata for proof claims
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionMetadata {
    /// Number of execution cycles
    pub cycles: u64,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// zkVM platform used
    pub platform: String,
    /// Proof generation time in milliseconds
    pub proof_time_ms: u64,
}

/// Error types for zkTLS verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ZkTlsError {
    /// Invalid input data
    InvalidInput(String),
    /// TLS handshake verification failed
    HandshakeError(String),
    /// TLS protocol error
    ProtocolError(String),
    /// Certificate validation failed
    CertificateError(String),
    /// HTTP parsing failed
    HttpError(String),
    /// Cryptographic operation failed
    CryptoError(String),
    /// zkVM execution failed
    ExecutionError(String),
    /// Serialization/deserialization failed
    SerializationError(String),
}

impl std::fmt::Display for ZkTlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkTlsError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            ZkTlsError::HandshakeError(msg) => write!(f, "Handshake error: {}", msg),
            ZkTlsError::ProtocolError(msg) => write!(f, "TLS protocol error: {}", msg),
            ZkTlsError::CertificateError(msg) => write!(f, "Certificate error: {}", msg),
            ZkTlsError::HttpError(msg) => write!(f, "HTTP error: {}", msg),
            ZkTlsError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            ZkTlsError::ExecutionError(msg) => write!(f, "Execution error: {}", msg),
            ZkTlsError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for ZkTlsError {}

/// Result type for zkTLS operations
pub type ZkTlsResult<T> = Result<T, ZkTlsError>;

/// Platform-agnostic verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkTlsVerificationResult {
    /// The proof claim if verification succeeded
    pub claim: Option<ZkTlsProofClaim>,
    /// Error if verification failed
    pub error: Option<ZkTlsError>,
    /// Execution statistics
    pub stats: ExecutionMetadata,
}

impl ZkTlsVerificationResult {
    /// Create a successful verification result
    pub fn success(claim: ZkTlsProofClaim, stats: ExecutionMetadata) -> Self {
        Self {
            claim: Some(claim),
            error: None,
            stats,
        }
    }

    /// Create a failed verification result
    pub fn failure(error: ZkTlsError, stats: ExecutionMetadata) -> Self {
        Self {
            claim: None,
            error: Some(error),
            stats,
        }
    }

    /// Check if verification was successful
    pub fn is_success(&self) -> bool {
        self.claim.is_some() && self.error.is_none()
    }

    /// Check if verification failed
    pub fn is_failure(&self) -> bool {
        self.error.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_tls_input_serialization() {
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

        let serialized = bincode::serialize(&input).unwrap();
        let deserialized: ZkTlsInput = bincode::deserialize(&serialized).unwrap();
        
        assert_eq!(input.domain, deserialized.domain);
        assert_eq!(input.handshake_transcript, deserialized.handshake_transcript);
    }

    #[test]
    fn test_zk_tls_proof_claim_serialization() {
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
                platform: "sp1".to_string(),
                proof_time_ms: 50,
            },
        };

        let serialized = bincode::serialize(&claim).unwrap();
        let deserialized: ZkTlsProofClaim = bincode::deserialize(&serialized).unwrap();
        
        assert_eq!(claim, deserialized);
    }

    #[test]
    fn test_verification_result_success() {
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
                platform: "sp1".to_string(),
                proof_time_ms: 50,
            },
        };

        let stats = ExecutionMetadata {
            cycles: 1000,
            memory_usage: 1024,
            execution_time_ms: 100,
            platform: "sp1".to_string(),
            proof_time_ms: 50,
        };

        let result = ZkTlsVerificationResult::success(claim.clone(), stats);
        
        assert!(result.is_success());
        assert!(!result.is_failure());
        assert_eq!(result.claim, Some(claim));
        assert_eq!(result.error, None);
    }

    #[test]
    fn test_verification_result_failure() {
        let error = ZkTlsError::HandshakeError("Invalid handshake".to_string());
        let stats = ExecutionMetadata {
            cycles: 1000,
            memory_usage: 1024,
            execution_time_ms: 100,
            platform: "sp1".to_string(),
            proof_time_ms: 50,
        };

        let result = ZkTlsVerificationResult::failure(error.clone(), stats);
        
        assert!(!result.is_success());
        assert!(result.is_failure());
        assert_eq!(result.claim, None);
        assert_eq!(result.error, Some(error));
    }
}