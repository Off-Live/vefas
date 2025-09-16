//! HTTP Request/Response Cryptographic Commitments
//!
//! This module implements cryptographic commitment schemes for HTTP requests and responses
//! to enable verifiable claims in zkTLS proofs. Commitments provide binding and hiding
//! properties essential for zero-knowledge verification.
//!
//! # Commitment Schemes
//!
//! ## HTTP Request Commitments
//! ```text
//! request_commitment = SHA-256(method || uri || headers_hash || body_hash)
//! ```
//! Where:
//! - `method`: HTTP method string (GET, POST, etc.)
//! - `uri`: Complete request URI with query parameters
//! - `headers_hash`: SHA-256 of canonical header representation
//! - `body_hash`: SHA-256 of request body (empty hash for GET requests)
//!
//! ## HTTP Response Commitments
//! ```text
//! response_commitment = SHA-256(status_code || headers_hash || body_commitment)
//! ```
//! Where:
//! - `status_code`: HTTP status code as big-endian u16 bytes
//! - `headers_hash`: SHA-256 of canonical header representation
//! - `body_commitment`: Either SHA-256 hash or Merkle root for large bodies
//!
//! # Features
//!
//! - **Deterministic**: Same input always produces same commitment
//! - **Binding**: Cannot change committed data without detection
//! - **zkVM Optimized**: Efficient operations using cryptographic precompiles
//! - **Selective Disclosure**: Merkle tree commitments enable partial revelation
//! - **RFC Compliant**: Follows TLS 1.3 and HTTP/1.1 standards

use crate::http::{HttpRequest, HttpResponse, HttpHeaders};
use crate::errors::{ZkTlsError, ZkTlsResult};
use zktls_crypto::traits::Hash;
use zktls_crypto::native::NativeCryptoProvider;

use alloc::{vec::Vec, string::String, format};

pub use super::merkle::{MerkleTreeCommitment, SelectiveProof, MerkleProof};

/// HTTP Request Commitment Generator
///
/// Generates cryptographic commitments for HTTP requests using SHA-256.
/// Commitments are deterministic and suitable for zkVM proof generation.
pub struct HttpRequestCommitment;

impl HttpRequestCommitment {
    /// Generate SHA-256 commitment for HTTP request
    ///
    /// # Arguments
    /// * `request` - HTTP request to commit to
    ///
    /// # Returns
    /// 32-byte SHA-256 commitment
    ///
    /// # Commitment Format
    /// ```text
    /// commitment = SHA-256(method || uri || headers_hash || body_hash)
    /// ```
    ///
    /// # Example
    /// ```rust,no_run
    /// use zktls_core::http::{HttpRequest, commitment::HttpRequestCommitment};
    ///
    /// let request = HttpRequest::get("/api/data", "example.com")?;
    /// let commitment = HttpRequestCommitment::generate(&request)?;
    /// assert_eq!(commitment.len(), 32);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate(request: &HttpRequest) -> ZkTlsResult<[u8; 32]> {
        let crypto = NativeCryptoProvider::new();
        
        // Serialize request components for commitment
        let mut commitment_data = Vec::new();
        
        // 1. HTTP Method
        commitment_data.extend_from_slice(request.method().as_str().as_bytes());
        commitment_data.push(0x00); // Separator
        
        // 2. Request URI
        commitment_data.extend_from_slice(request.path().as_bytes());
        commitment_data.push(0x00); // Separator
        
        // 3. Headers Hash (canonical representation)
        let headers_hash = Self::hash_headers_canonical(request.headers());
        commitment_data.extend_from_slice(&headers_hash);
        
        // 4. Body Hash
        let body_hash = if request.body().is_empty() {
            crypto.sha256(b"") // Empty body hash for GET requests
        } else {
            crypto.sha256(request.body())
        };
        commitment_data.extend_from_slice(&body_hash);
        
        // Generate final commitment
        Ok(crypto.sha256(&commitment_data))
    }
    
    /// Verify commitment against original request
    ///
    /// # Arguments
    /// * `commitment` - The commitment to verify
    /// * `request` - The original request
    ///
    /// # Returns
    /// `true` if commitment matches request, `false` otherwise
    pub fn verify(commitment: &[u8; 32], request: &HttpRequest) -> ZkTlsResult<bool> {
        let generated_commitment = Self::generate(request)?;
        Ok(*commitment == generated_commitment)
    }
    
    /// Generate canonical hash of HTTP headers
    ///
    /// Headers are sorted by name (case-insensitive) to ensure deterministic ordering.
    /// Format: "name1:value1\nname2:value2\n"
    fn hash_headers_canonical(headers: &HttpHeaders) -> [u8; 32] {
        let crypto = NativeCryptoProvider::new();
        
        // Sort headers by name for deterministic ordering
        let mut header_pairs: Vec<(String, String)> = headers.iter()
            .map(|(name, value)| (name.to_lowercase(), value.clone()))
            .collect();
        header_pairs.sort_by(|a, b| a.0.cmp(&b.0));
        
        // Serialize headers canonically
        let mut canonical_headers = String::new();
        for (name, value) in header_pairs {
            canonical_headers.push_str(&name);
            canonical_headers.push(':');
            canonical_headers.push_str(&value);
            canonical_headers.push('\n');
        }
        
        crypto.sha256(canonical_headers.as_bytes())
    }
}

/// HTTP Response Commitment Generator
///
/// Generates cryptographic commitments for HTTP responses using SHA-256.
/// For large response bodies, uses Merkle tree commitments for selective disclosure.
pub struct HttpResponseCommitment;

impl HttpResponseCommitment {
    /// Threshold for switching to Merkle tree commitments (1KB)
    pub const MERKLE_THRESHOLD: usize = 1024;
    
    /// Generate SHA-256 commitment for HTTP response
    ///
    /// # Arguments
    /// * `response` - HTTP response to commit to
    ///
    /// # Returns
    /// 32-byte SHA-256 commitment
    ///
    /// # Commitment Format
    /// ```text
    /// commitment = SHA-256(status_code || headers_hash || body_commitment)
    /// ```
    ///
    /// For bodies larger than 1KB, `body_commitment` is a Merkle tree root.
    pub fn generate(response: &HttpResponse) -> ZkTlsResult<[u8; 32]> {
        let crypto = NativeCryptoProvider::new();
        
        let mut commitment_data = Vec::new();
        
        // 1. Status Code (big-endian u16)
        let status_bytes = response.status().to_be_bytes();
        commitment_data.extend_from_slice(&status_bytes);
        
        // 2. Headers Hash (canonical representation)
        let headers_hash = Self::hash_headers_canonical(response.headers());
        commitment_data.extend_from_slice(&headers_hash);
        
        // 3. Body Commitment (SHA-256 or Merkle root)
        let body_commitment = if response.body().len() > Self::MERKLE_THRESHOLD {
            // Use Merkle tree for large bodies
            let merkle_tree = MerkleTreeCommitment::generate(response.body(), 256)?;
            *merkle_tree.root()
        } else {
            // Use simple SHA-256 for small bodies
            crypto.sha256(response.body())
        };
        commitment_data.extend_from_slice(&body_commitment);
        
        Ok(crypto.sha256(&commitment_data))
    }
    
    /// Verify commitment against original response
    pub fn verify(commitment: &[u8; 32], response: &HttpResponse) -> ZkTlsResult<bool> {
        let generated_commitment = Self::generate(response)?;
        Ok(*commitment == generated_commitment)
    }
    
    /// Generate canonical hash of HTTP headers (same as request implementation)
    fn hash_headers_canonical(headers: &HttpHeaders) -> [u8; 32] {
        let crypto = NativeCryptoProvider::new();
        
        let mut header_pairs: Vec<(String, String)> = headers.iter()
            .map(|(name, value)| (name.to_lowercase(), value.clone()))
            .collect();
        header_pairs.sort_by(|a, b| a.0.cmp(&b.0));
        
        let mut canonical_headers = String::new();
        for (name, value) in header_pairs {
            canonical_headers.push_str(&name);
            canonical_headers.push(':');
            canonical_headers.push_str(&value);
            canonical_headers.push('\n');
        }
        
        crypto.sha256(canonical_headers.as_bytes())
    }
}

/// General commitment scheme utilities
pub struct CommitmentScheme;

impl CommitmentScheme {
    /// Serialize commitment for zkVM input
    ///
    /// Commitments are serialized as raw 32-byte arrays for efficient zkVM processing.
    pub fn serialize_for_zkvm(commitment: &[u8; 32]) -> ZkTlsResult<Vec<u8>> {
        Ok(commitment.to_vec())
    }
    
    /// Deserialize commitment from zkVM output
    pub fn deserialize_from_zkvm(data: &[u8]) -> ZkTlsResult<[u8; 32]> {
        if data.len() != 32 {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Invalid commitment length: expected 32 bytes, got {}", data.len())
            ));
        }
        
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(data);
        Ok(commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpMethod;
    
    #[test]
    fn test_canonical_header_ordering() {
        let mut headers = HttpHeaders::new();
        headers.insert("Z-Last", "last");
        headers.insert("A-First", "first");
        headers.insert("M-Middle", "middle");
        
        let hash1 = HttpRequestCommitment::hash_headers_canonical(&headers);
        
        // Create same headers in different insertion order
        let mut headers2 = HttpHeaders::new();
        headers2.insert("M-Middle", "middle");
        headers2.insert("Z-Last", "last");
        headers2.insert("A-First", "first");
        
        let hash2 = HttpRequestCommitment::hash_headers_canonical(&headers2);
        
        // Should produce identical hashes despite different insertion order
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_commitment_serialization() {
        let commitment = [0x42u8; 32];
        
        let serialized = CommitmentScheme::serialize_for_zkvm(&commitment).unwrap();
        assert_eq!(serialized.len(), 32);
        
        let deserialized = CommitmentScheme::deserialize_from_zkvm(&serialized).unwrap();
        assert_eq!(commitment, deserialized);
    }
    
    #[test]
    fn test_commitment_deserialization_invalid_length() {
        let invalid_data = alloc::vec![0x42u8; 16]; // Wrong length
        
        let result = CommitmentScheme::deserialize_from_zkvm(&invalid_data);
        assert!(result.is_err());
    }
}