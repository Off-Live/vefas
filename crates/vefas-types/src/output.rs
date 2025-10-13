//! zkVM-specific types for VEFAS proof claims
//!
//! This module defines the simplified proof claim structure that matches
//! the new host-rustls + guest-verifier architecture specification.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem::size_of;
use serde::{Deserialize, Serialize};

use crate::{
    errors::{VefasError, VefasResult},
    utils::format_decimal,
    MAX_DOMAIN_LENGTH, VEFAS_PROTOCOL_VERSION,
};

/// Simplified proof claim structure for the new architecture
///
/// This matches the exact specification from README.md and represents
/// the output of the minimal guest verifier in the revolutionary
/// host-rustls + guest-verifier architecture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefasProofClaim {
    /// Protocol version for compatibility
    pub version: u16,

    /// Target domain that was verified
    pub domain: String,

    /// HTTP method that was executed (e.g., "GET", "POST")
    pub method: String,

    /// HTTP path that was accessed (e.g., "/api/v1/data")
    pub path: String,

    /// SHA-256 hash commitment of the HTTP request (binary format)
    pub request_commitment: [u8; 32],

    /// SHA-256 hash commitment of the HTTP response (binary format)
    pub response_commitment: [u8; 32],

    /// SHA-256 hash of the complete HTTP request (hex string format for compatibility)
    pub request_hash: String,

    /// SHA-256 hash of the complete HTTP response (hex string format for compatibility)
    pub response_hash: String,

    /// HTTP status code from the response
    pub status_code: u16,

    /// TLS version used (e.g., "1.3")
    pub tls_version: String,

    /// Cipher suite used (e.g., "TLS_AES_256_GCM_SHA384")
    pub cipher_suite: String,

    /// SHA-256 hash of the certificate chain (binary format)
    pub certificate_chain_hash: [u8; 32],

    /// SHA-256 hash of the handshake transcript (binary format)
    pub handshake_transcript_hash: [u8; 32],

    /// SHA-256 fingerprint of server's leaf certificate (for verifier binding)
    pub cert_fingerprint: [u8; 32],

    /// Unique proof identifier for binding zk proof to verifier attestations
    pub proof_id: [u8; 32],

    /// Unix timestamp when the session was captured
    pub timestamp: u64,

    /// Performance metrics breakdown for detailed analysis
    pub performance: VefasPerformanceMetrics,

    /// Execution metadata from the zkVM
    pub execution_metadata: VefasExecutionMetadata,
}

/// Performance metrics breakdown for simplified zkVM execution
/// 
/// Reflects the new architecture where zkVM focuses on Merkle proof verification
/// and HTTP data integrity, while verifier nodes handle PKI validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefasPerformanceMetrics {
    /// Total execution cycles
    pub total_cycles: u64,
    /// Cycles spent on Merkle proof verification (main zkVM operation)
    pub merkle_verification_cycles: u64,
    /// Cycles spent on HTTP data extraction and parsing
    pub http_parsing_cycles: u64,
    /// Cycles spent on cryptographic operations (hashing, commitments)
    pub crypto_operations_cycles: u64,
    /// Memory usage estimate (bytes)
    pub memory_usage: usize,
}

/// Execution metadata for zkVM proof generation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefasExecutionMetadata {
    /// Number of execution cycles in the zkVM
    pub cycles: u64,

    /// Memory usage during execution (bytes)
    pub memory_usage: u64,

    /// Execution time in milliseconds
    pub execution_time_ms: u64,

    /// Proof generation time in milliseconds
    pub proof_time_ms: u64,

    /// Platform identifier (e.g., "SP1", "RISC0")
    pub platform: String,
}

/// Complete proof package including claim and cryptographic proof
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefasProof {
    /// The verified claim
    pub claim: VefasProofClaim,

    /// The cryptographic proof (platform-specific format)
    pub proof: Vec<u8>,

    /// Proof format identifier
    pub proof_format: String,

    /// Public inputs to the proof verification
    pub public_inputs: Vec<u8>,
}

impl VefasProofClaim {
    /// Create a new proof claim with validation
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: String,
        method: String,
        path: String,
        request_commitment: [u8; 32],
        response_commitment: [u8; 32],
        request_hash: String,
        response_hash: String,
        status_code: u16,
        tls_version: String,
        cipher_suite: String,
        certificate_chain_hash: [u8; 32],
        handshake_transcript_hash: [u8; 32],
        cert_fingerprint: [u8; 32],
        proof_id: [u8; 32],
        timestamp: u64,
        performance: VefasPerformanceMetrics,
        execution_metadata: VefasExecutionMetadata,
    ) -> VefasResult<Self> {
        let claim = Self {
            version: VEFAS_PROTOCOL_VERSION,
            domain,
            method,
            path,
            request_commitment,
            response_commitment,
            request_hash,
            response_hash,
            status_code,
            tls_version,
            cipher_suite,
            certificate_chain_hash,
            handshake_transcript_hash,
            cert_fingerprint,
            proof_id,
            timestamp,
            performance,
            execution_metadata,
        };

        claim.validate()?;
        Ok(claim)
    }

    /// Validate the proof claim
    pub fn validate(&self) -> VefasResult<()> {
        // Check protocol version
        if self.version != VEFAS_PROTOCOL_VERSION {
            return Err(VefasError::version_mismatch(
                VEFAS_PROTOCOL_VERSION,
                self.version,
            ));
        }

        // Validate domain name
        if self.domain.is_empty() {
            return Err(VefasError::invalid_input(
                "domain",
                "Domain cannot be empty",
            ));
        }

        if self.domain.len() > MAX_DOMAIN_LENGTH {
            return Err(VefasError::invalid_input(
                "domain",
                &("Domain too long: ".to_string()
                    + &format_decimal(self.domain.len())
                    + " characters (max "
                    + &format_decimal(MAX_DOMAIN_LENGTH)
                    + ")"),
            ));
        }

        // Validate HTTP status code
        if !(100..=599).contains(&self.status_code) {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidStatusCode,
                &("Invalid HTTP status code: ".to_string()
                    + &format_decimal(self.status_code as usize)),
            ));
        }

        // Validate TLS version
        if self.tls_version.is_empty() {
            return Err(VefasError::tls_error(
                crate::errors::TlsErrorType::UnsupportedVersion,
                "TLS version cannot be empty",
            ));
        }

        // Validate cipher suite
        if self.cipher_suite.is_empty() {
            return Err(VefasError::tls_error(
                crate::errors::TlsErrorType::UnsupportedCipherSuite,
                "Cipher suite cannot be empty",
            ));
        }

        // Validate execution metadata
        self.execution_metadata.validate()?;

        Ok(())
    }

    /// Get the total memory footprint of this claim
    pub fn memory_footprint(&self) -> usize {
        size_of::<Self>()
            + self.domain.len()
            + self.tls_version.len()
            + self.cipher_suite.len()
            + self.execution_metadata.memory_footprint()
    }

    /// Generate a unique claim identifier
    pub fn claim_id(&self) -> [u8; 32] {
        // In a real implementation, this would use SHA-256 of all fields
        // For now, we'll use a simple deterministic hash based on domain and timestamp
        let mut hash = [0u8; 32];

        // Combine domain bytes and timestamp for deterministic ID
        let domain_bytes = self.domain.as_bytes();
        let timestamp_bytes = self.timestamp.to_le_bytes();

        for (i, &byte) in domain_bytes
            .iter()
            .chain(timestamp_bytes.iter())
            .take(32)
            .enumerate()
        {
            hash[i] = byte;
        }

        hash
    }

    /// Check if this claim represents a successful verification
    pub fn is_successful(&self) -> bool {
        // Basic heuristic: 2xx status codes indicate success
        (200..300).contains(&self.status_code)
    }

    /// Get human-readable status description
    pub fn status_description(&self) -> &'static str {
        match self.status_code {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            _ => "Unknown",
        }
    }
}

impl VefasExecutionMetadata {
    /// Create new execution metadata
    pub fn new(
        cycles: u64,
        memory_usage: usize,
        execution_time_ms: u64,
        platform: String,
        proof_time_ms: u64,
    ) -> VefasResult<Self> {
        let metadata = Self {
            cycles,
            memory_usage: memory_usage as u64,
            execution_time_ms,
            platform,
            proof_time_ms,
        };

        metadata.validate()?;
        Ok(metadata)
    }

    /// Validate execution metadata
    pub fn validate(&self) -> VefasResult<()> {
        // Validate platform
        if self.platform.is_empty() {
            return Err(VefasError::zkvm_error(
                "unknown",
                "Platform cannot be empty",
            ));
        }

        // Validate known platforms
        if !["sp1", "risc0"].contains(&self.platform.as_str()) {
            return Err(VefasError::zkvm_error(
                &self.platform,
                &("Unsupported platform: ".to_string() + &self.platform),
            ));
        }

        // Basic sanity checks
        if self.cycles == 0 {
            return Err(VefasError::zkvm_error(
                &self.platform,
                "Execution cycles cannot be zero",
            ));
        }

        if self.memory_usage == 0 {
            return Err(VefasError::zkvm_error(
                &self.platform,
                "Memory usage cannot be zero",
            ));
        }

        Ok(())
    }

    /// Get memory footprint
    pub fn memory_footprint(&self) -> usize {
        size_of::<Self>() + self.platform.len()
    }

    /// Calculate cycles per millisecond
    pub fn cycles_per_ms(&self) -> u64 {
        if self.execution_time_ms == 0 {
            0
        } else {
            self.cycles / self.execution_time_ms
        }
    }

    /// Calculate memory usage per cycle
    pub fn memory_per_cycle(&self) -> f64 {
        if self.cycles == 0 {
            0.0
        } else {
            self.memory_usage as f64 / self.cycles as f64
        }
    }
}

impl VefasProof {
    /// Create a new proof with validation
    pub fn new(
        claim: VefasProofClaim,
        proof: Vec<u8>,
        proof_format: String,
        public_inputs: Vec<u8>,
    ) -> VefasResult<Self> {
        if proof.is_empty() {
            return Err(VefasError::invalid_input("proof", "proof cannot be empty"));
        }

        if proof_format.is_empty() {
            return Err(VefasError::invalid_input(
                "proof_format",
                "proof_format cannot be empty",
            ));
        }

        Ok(Self {
            claim,
            proof,
            proof_format,
            public_inputs,
        })
    }

    /// Calculate total memory footprint in bytes
    pub fn memory_footprint(&self) -> usize {
        size_of::<Self>()
            + self.claim.memory_footprint()
            + self.proof.len()
            + self.proof_format.len()
            + self.public_inputs.len()
    }

    /// Serialize to deterministic byte representation
    pub fn serialize(&self) -> VefasResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| VefasError::serialization_error(&e.to_string()))
    }

    /// Deserialize from byte representation
    pub fn deserialize(data: &[u8]) -> VefasResult<Self> {
        serde_json::from_slice(data).map_err(|e| VefasError::serialization_error(&e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn create_test_execution_metadata() -> VefasExecutionMetadata {
        VefasExecutionMetadata::new(
            1_000_000,         // cycles
            2048,              // memory_usage
            150,               // execution_time_ms
            "sp1".to_string(), // platform
            75,                // proof_time_ms
        )
        .unwrap()
    }

    fn create_test_performance_metrics() -> VefasPerformanceMetrics {
        VefasPerformanceMetrics {
            total_cycles: 1_000_000,
            merkle_verification_cycles: 100_000,
            http_parsing_cycles: 60_000,
            crypto_operations_cycles: 240_000,
            memory_usage: 2048,
        }
    }

    fn create_test_proof_claim() -> VefasProofClaim {
        VefasProofClaim::new(
            "example.com".to_string(),            // domain
            "GET".to_string(),                    // method
            "/api/test".to_string(),              // path
            [1u8; 32],                            // request_commitment
            [2u8; 32],                            // response_commitment
            "req_hash_abc123".to_string(),        // request_hash
            "resp_hash_def456".to_string(),       // response_hash
            200,                                  // status_code
            "1.3".to_string(),                    // tls_version
            "TLS_AES_256_GCM_SHA384".to_string(), // cipher_suite
            [3u8; 32],                            // certificate_chain_hash
            [4u8; 32],                            // handshake_transcript_hash
            [5u8; 32],                            // cert_fingerprint
            [6u8; 32],                            // proof_id
            1640995200,                           // timestamp (2022-01-01)
            create_test_performance_metrics(),    // performance
            create_test_execution_metadata(),     // execution_metadata
        )
        .unwrap()
    }

    #[test]
    fn test_proof_claim_creation_and_validation() {
        let claim = create_test_proof_claim();
        assert_eq!(claim.domain, "example.com");
        assert_eq!(claim.status_code, 200);
        assert_eq!(claim.version, VEFAS_PROTOCOL_VERSION);
        assert!(claim.validate().is_ok());
        assert!(claim.is_successful());
        assert_eq!(claim.status_description(), "OK");
    }

    #[test]
    fn test_proof_claim_validation_empty_domain() {
        let mut claim = create_test_proof_claim();
        claim.domain = String::new();
        assert!(claim.validate().is_err());
    }

    #[test]
    fn test_proof_claim_validation_invalid_status_code() {
        let mut claim = create_test_proof_claim();
        claim.status_code = 999;
        assert!(claim.validate().is_err());
    }

    #[test]
    fn test_proof_claim_validation_empty_tls_version() {
        let mut claim = create_test_proof_claim();
        claim.tls_version = String::new();
        assert!(claim.validate().is_err());
    }

    #[test]
    fn test_proof_claim_validation_empty_cipher_suite() {
        let mut claim = create_test_proof_claim();
        claim.cipher_suite = String::new();
        assert!(claim.validate().is_err());
    }

    #[test]
    fn test_execution_metadata_validation() {
        let metadata = create_test_execution_metadata();
        assert!(metadata.validate().is_ok());
        assert_eq!(metadata.platform, "sp1");
        assert_eq!(metadata.cycles_per_ms(), 6666); // 1_000_000 / 150
    }

    #[test]
    fn test_execution_metadata_invalid_platform() {
        let mut metadata = create_test_execution_metadata();
        metadata.platform = "invalid".to_string();
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn test_execution_metadata_zero_cycles() {
        let mut metadata = create_test_execution_metadata();
        metadata.cycles = 0;
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn test_proof_claim_memory_footprint() {
        let claim = create_test_proof_claim();
        let footprint = claim.memory_footprint();
        assert!(footprint > 0);

        // Should include domain and other string lengths
        let expected_min = claim.domain.len() + claim.tls_version.len() + claim.cipher_suite.len();
        assert!(footprint >= expected_min);
    }

    #[test]
    fn test_claim_id_deterministic() {
        let claim1 = create_test_proof_claim();
        let claim2 = create_test_proof_claim();

        let id1 = claim1.claim_id();
        let id2 = claim2.claim_id();

        // Same claim should produce same ID
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_claim_id_different_for_different_claims() {
        let claim1 = create_test_proof_claim();
        let mut claim2 = create_test_proof_claim();
        claim2.domain = "different.com".to_string();

        let id1 = claim1.claim_id();
        let id2 = claim2.claim_id();

        // Different claims should produce different IDs
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_proof_claim_serialization() {
        let claim = create_test_proof_claim();

        let serialized = serde_json::to_string(&claim).unwrap();
        let deserialized: VefasProofClaim = serde_json::from_str(&serialized).unwrap();

        assert_eq!(claim, deserialized);
    }

    #[test]
    fn test_success_status_detection() {
        let mut claim = create_test_proof_claim();

        // Test successful status codes
        claim.status_code = 200;
        assert!(claim.is_successful());
        claim.status_code = 201;
        assert!(claim.is_successful());
        claim.status_code = 204;
        assert!(claim.is_successful());

        // Test error status codes
        claim.status_code = 400;
        assert!(!claim.is_successful());
        claim.status_code = 404;
        assert!(!claim.is_successful());
        claim.status_code = 500;
        assert!(!claim.is_successful());
    }

    #[test]
    fn test_status_descriptions() {
        let mut claim = create_test_proof_claim();

        claim.status_code = 200;
        assert_eq!(claim.status_description(), "OK");
        claim.status_code = 404;
        assert_eq!(claim.status_description(), "Not Found");
        claim.status_code = 500;
        assert_eq!(claim.status_description(), "Internal Server Error");
        claim.status_code = 999;
        assert_eq!(claim.status_description(), "Unknown");
    }

    #[test]
    fn test_execution_metadata_calculations() {
        let metadata = create_test_execution_metadata();

        assert_eq!(metadata.cycles_per_ms(), 6666); // 1_000_000 / 150
        assert!((metadata.memory_per_cycle() - 0.002048).abs() < 0.000001); // 2048 / 1_000_000

        // Test edge cases
        let mut metadata_zero_time = metadata.clone();
        metadata_zero_time.execution_time_ms = 0;
        assert_eq!(metadata_zero_time.cycles_per_ms(), 0);

        let mut metadata_zero_cycles = metadata;
        metadata_zero_cycles.cycles = 1; // Can't be zero due to validation
        assert!(metadata_zero_cycles.memory_per_cycle() > 0.0);
    }

    #[test]
    fn test_version_validation() {
        let mut claim = create_test_proof_claim();
        claim.version = 999;
        assert!(claim.validate().is_err());
    }

    #[test]
    fn test_proof_creation() {
        let claim = create_test_proof_claim();

        let proof = VefasProof::new(
            claim,
            alloc::vec![1, 2, 3, 4, 5],
            "SP1".to_string(),
            alloc::vec![6, 7, 8, 9],
        )
        .unwrap();

        assert_eq!(proof.proof_format, "SP1");
        assert!(!proof.proof.is_empty());
    }

    #[test]
    fn test_proof_serialization() {
        let claim = create_test_proof_claim();
        let proof = VefasProof::new(
            claim,
            alloc::vec![1, 2, 3, 4, 5],
            "SP1".to_string(),
            alloc::vec![6, 7, 8, 9],
        )
        .unwrap();

        let serialized = proof.serialize().unwrap();
        let deserialized = VefasProof::deserialize(&serialized).unwrap();
        assert_eq!(proof, deserialized);
    }
}
