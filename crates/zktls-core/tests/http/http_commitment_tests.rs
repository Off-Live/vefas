//! Tests for HTTP Request/Response Cryptographic Commitments
//!
//! This module tests cryptographic commitment schemes for HTTP requests and responses
//! to enable verifiable claims in zkTLS proofs. Tests follow strict TDD methodology.
//!
//! # Commitment Schemes Tested
//!
//! - **HTTP Request Commitments**: SHA-256(method || uri || headers_hash || body_hash)
//! - **HTTP Response Commitments**: SHA-256(status_code || headers_hash || body_commitment)
//! - **Merkle Tree Commitments**: For large response bodies enabling selective disclosure
//! - **Deterministic Generation**: Consistent commitments for zkVM proof generation
//! - **Commitment Verification**: Functions to verify commitments against original data

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use zktls_core::http::{HttpRequest, HttpResponse, HttpMethod};
    use zktls_core::http::commitment::{
        HttpRequestCommitment, HttpResponseCommitment, CommitmentScheme, MerkleTreeCommitment
    };

    #[test]
    fn test_http_request_commitment_get_simple() {
        // RED: This test should fail initially since commitment module doesn't exist
        
        // Create a simple GET request
        let request = HttpRequest::get("/api/data", "example.com")
            .expect("Failed to create GET request");
        
        // Generate commitment
        let commitment = HttpRequestCommitment::generate(&request)
            .expect("Failed to generate request commitment");
        
        // Verify commitment structure
        assert_eq!(commitment.len(), 32); // SHA-256 produces 32 bytes
        
        // Verify deterministic behavior - same request should produce same commitment
        let commitment2 = HttpRequestCommitment::generate(&request)
            .expect("Failed to generate second commitment");
        assert_eq!(commitment, commitment2);
        
        // Known test vector for GET /api/data with Host: example.com
        // This will be calculated once the implementation exists
        let expected_commitment = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        // TODO: Update with actual expected value after implementation
        // assert_eq!(commitment, expected_commitment);
    }

    #[test]
    fn test_http_request_commitment_post_with_body() {
        // RED: Test POST request with JSON body commitment
        
        let json_body = r#"{"username": "alice", "action": "transfer", "amount": 100}"#;
        let request = HttpRequest::post_json("/api/transfer", "bank.example.com", json_body)
            .expect("Failed to create POST request");
        
        let commitment = HttpRequestCommitment::generate(&request)
            .expect("Failed to generate POST commitment");
        
        assert_eq!(commitment.len(), 32);
        
        // Verify that POST commitment differs from GET commitment
        let get_request = HttpRequest::get("/api/transfer", "bank.example.com")
            .expect("Failed to create GET request");
        let get_commitment = HttpRequestCommitment::generate(&get_request)
            .expect("Failed to generate GET commitment");
        
        assert_ne!(commitment, get_commitment);
    }

    #[test]
    fn test_http_response_commitment_success() {
        // RED: Test HTTP response commitment generation
        
        let raw_response = b"HTTP/1.1 200 OK\r\n\
                           Content-Type: application/json\r\n\
                           Content-Length: 25\r\n\
                           \r\n\
                           {\"result\": \"success\"}";
        
        let response = HttpResponse::parse(raw_response)
            .expect("Failed to parse HTTP response");
        
        let commitment = HttpResponseCommitment::generate(&response)
            .expect("Failed to generate response commitment");
        
        assert_eq!(commitment.len(), 32);
        
        // Verify deterministic behavior
        let commitment2 = HttpResponseCommitment::generate(&response)
            .expect("Failed to generate second commitment");
        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_http_response_commitment_different_status_codes() {
        // RED: Verify different status codes produce different commitments
        
        let response_200 = b"HTTP/1.1 200 OK\r\n\r\nSuccess";
        let response_404 = b"HTTP/1.1 404 Not Found\r\n\r\nNot Found";
        
        let parsed_200 = HttpResponse::parse(response_200).unwrap();
        let parsed_404 = HttpResponse::parse(response_404).unwrap();
        
        let commitment_200 = HttpResponseCommitment::generate(&parsed_200).unwrap();
        let commitment_404 = HttpResponseCommitment::generate(&parsed_404).unwrap();
        
        assert_ne!(commitment_200, commitment_404);
    }

    #[test]
    fn test_merkle_tree_commitment_large_payload() {
        // RED: Test Merkle tree commitment for large response bodies
        
        // Create a large response body (>1KB to trigger Merkle tree usage)
        let large_body = "A".repeat(2048);
        let raw_response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            large_body.len(),
            large_body
        );
        
        let response = HttpResponse::parse(raw_response.as_bytes())
            .expect("Failed to parse large response");
        
        // Generate Merkle tree commitment
        let merkle_commitment = MerkleTreeCommitment::generate(response.body(), 256)
            .expect("Failed to generate Merkle commitment");
        
        assert_eq!(merkle_commitment.root().len(), 32); // Merkle root is 32 bytes
        assert!(merkle_commitment.leaf_count() > 1); // Should have multiple leaves for 2048 bytes
        
        // Verify we can get proofs for specific chunks
        let proof = merkle_commitment.get_proof(0)
            .expect("Failed to get proof for first chunk");
        
        assert!(!proof.siblings.is_empty()); // Should have sibling hashes for proof
    }

    #[test]
    fn test_commitment_verification_functions() {
        // RED: Test commitment verification against original data
        
        let request = HttpRequest::get("/verify", "test.com").unwrap();
        let commitment = HttpRequestCommitment::generate(&request).unwrap();
        
        // Verify commitment matches original request
        assert!(HttpRequestCommitment::verify(&commitment, &request).unwrap());
        
        // Verify commitment fails with different request
        let different_request = HttpRequest::get("/different", "test.com").unwrap();
        assert!(!HttpRequestCommitment::verify(&commitment, &different_request).unwrap());
    }

    #[test]
    fn test_canonical_header_serialization() {
        // RED: Test that header ordering is deterministic for commitment generation
        
        let mut request1 = HttpRequest::get("/test", "example.com").unwrap();
        request1.set_header("Authorization", "Bearer token123");
        request1.set_header("Accept", "application/json");
        
        let mut request2 = HttpRequest::get("/test", "example.com").unwrap();
        request2.set_header("Accept", "application/json"); // Different insertion order
        request2.set_header("Authorization", "Bearer token123");
        
        let commitment1 = HttpRequestCommitment::generate(&request1).unwrap();
        let commitment2 = HttpRequestCommitment::generate(&request2).unwrap();
        
        // Should produce same commitment despite different insertion order
        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_partial_body_commitment_selective_disclosure() {
        // RED: Test that we can commit to parts of response body while hiding others
        
        let json_response = r#"{
            "public_data": "visible_to_verifier",
            "private_data": "hidden_from_verifier", 
            "amount": 12345,
            "timestamp": "2024-01-01T00:00:00Z"
        }"#;
        
        let raw_response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            json_response.len(),
            json_response
        );
        
        let response = HttpResponse::parse(raw_response.as_bytes()).unwrap();
        let merkle_commitment = MerkleTreeCommitment::generate(response.body(), 64).unwrap();
        
        // Should be able to prove specific chunks without revealing entire body
        let chunk_indices = vec![0, 2]; // Prove only specific chunks
        let selective_proof = merkle_commitment.get_selective_proof(&chunk_indices).unwrap();
        
        assert_eq!(selective_proof.revealed_chunks.len(), 2);
        assert!(selective_proof.verify(&merkle_commitment.root()).unwrap());
    }

    #[test]
    fn test_commitment_scheme_zkvm_compatibility() {
        // RED: Test that commitments are suitable for zkVM proof generation
        
        let request = HttpRequest::post_json(
            "/api/zkproof",
            "zk.example.com",
            r#"{"proof_request": "sensitive_computation"}"#
        ).unwrap();
        
        let commitment = HttpRequestCommitment::generate(&request).unwrap();
        
        // Commitment should be deterministic and exactly 32 bytes for zkVM efficiency
        assert_eq!(commitment.len(), 32);
        
        // Should be able to serialize for zkVM input
        let serialized = CommitmentScheme::serialize_for_zkvm(&commitment).unwrap();
        assert!(!serialized.is_empty());
        
        // Should be able to deserialize in zkVM
        let deserialized = CommitmentScheme::deserialize_from_zkvm(&serialized).unwrap();
        assert_eq!(commitment, deserialized);
    }
}