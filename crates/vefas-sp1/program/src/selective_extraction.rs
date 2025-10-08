//! Selective Disclosure Field Extraction for SP1 Guest
//!
//! This module provides extraction functions for the 6 Merkle fields:
//! - 4 user-verifiable fields (HttpRequest, HttpResponse, Domain, Timestamp)
//! - 2 internal composite fields (HandshakeProof, CryptoWitness)

use alloc::{vec::Vec, string::{String, ToString}, format};
use vefas_types::{VefasError, VefasResult, VefasCanonicalBundle};
use vefas_crypto::{FieldId, MerkleProof};

/// Extract HTTP request from Merkle proof
pub fn extract_http_request(bundle: &VefasCanonicalBundle) -> VefasResult<Vec<u8>> {
    let proof_bytes = bundle.get_merkle_proof(FieldId::HttpRequest as u8)
        .ok_or_else(|| VefasError::invalid_input("http_request", "Merkle proof not found"))?;
    
    let proof: MerkleProof = bincode::deserialize(proof_bytes)
        .map_err(|e| VefasError::invalid_input("http_request", &format!("Failed to deserialize: {}", e)))?;
    
    Ok(proof.leaf_value)
}

/// Extract HTTP response from Merkle proof
pub fn extract_http_response(bundle: &VefasCanonicalBundle) -> VefasResult<Vec<u8>> {
    let proof_bytes = bundle.get_merkle_proof(FieldId::HttpResponse as u8)
        .ok_or_else(|| VefasError::invalid_input("http_response", "Merkle proof not found"))?;
    
    let proof: MerkleProof = bincode::deserialize(proof_bytes)
        .map_err(|e| VefasError::invalid_input("http_response", &format!("Failed to deserialize: {}", e)))?;
    
    Ok(proof.leaf_value)
}

/// Extract domain from Merkle proof
pub fn extract_domain(bundle: &VefasCanonicalBundle) -> VefasResult<String> {
    let proof_bytes = bundle.get_merkle_proof(FieldId::Domain as u8)
        .ok_or_else(|| VefasError::invalid_input("domain", "Merkle proof not found"))?;
    
    let proof: MerkleProof = bincode::deserialize(proof_bytes)
        .map_err(|e| VefasError::invalid_input("domain", &format!("Failed to deserialize: {}", e)))?;
    
    let domain = core::str::from_utf8(&proof.leaf_value)
        .map_err(|_| VefasError::invalid_input("domain", "Invalid UTF-8"))?
        .to_string();
    
    Ok(domain)
}

/// Extract timestamp from Merkle proof
pub fn extract_timestamp(bundle: &VefasCanonicalBundle) -> VefasResult<u64> {
    let proof_bytes = bundle.get_merkle_proof(FieldId::Timestamp as u8)
        .ok_or_else(|| VefasError::invalid_input("timestamp", "Merkle proof not found"))?;
    
    let proof: MerkleProof = bincode::deserialize(proof_bytes)
        .map_err(|e| VefasError::invalid_input("timestamp", &format!("Failed to deserialize: {}", e)))?;
    
    if proof.leaf_value.len() != 8 {
        return Err(VefasError::invalid_input("timestamp", &format!("Expected 8 bytes, got {}", proof.leaf_value.len())));
    }
    
    let timestamp = u64::from_be_bytes([
        proof.leaf_value[0], proof.leaf_value[1], proof.leaf_value[2], proof.leaf_value[3],
        proof.leaf_value[4], proof.leaf_value[5], proof.leaf_value[6], proof.leaf_value[7],
    ]);
    
    Ok(timestamp)
}

/// Extract cipher suite from CryptoWitness composite field
///
/// Format: [shared_secret(32)][cipher_suite(2)]
pub fn extract_cipher_suite(bundle: &VefasCanonicalBundle) -> VefasResult<u16> {
    let proof_bytes = bundle.get_merkle_proof(FieldId::CryptoWitness as u8)
        .ok_or_else(|| VefasError::invalid_input("crypto_witness", "Merkle proof not found"))?;
    
    let proof: MerkleProof = bincode::deserialize(proof_bytes)
        .map_err(|e| VefasError::invalid_input("crypto_witness", &format!("Failed to deserialize: {}", e)))?;
    
    if proof.leaf_value.len() != 34 {
        return Err(VefasError::invalid_input("crypto_witness", &format!("Expected 34 bytes, got {}", proof.leaf_value.len())));
    }
    
    // Cipher suite is last 2 bytes
    let cipher_suite = u16::from_be_bytes([proof.leaf_value[32], proof.leaf_value[33]]);
    
    Ok(cipher_suite)
}

/// Extract shared secret from CryptoWitness composite field
pub fn extract_shared_secret(bundle: &VefasCanonicalBundle) -> VefasResult<[u8; 32]> {
    let proof_bytes = bundle.get_merkle_proof(FieldId::CryptoWitness as u8)
        .ok_or_else(|| VefasError::invalid_input("crypto_witness", "Merkle proof not found"))?;
    
    let proof: MerkleProof = bincode::deserialize(proof_bytes)
        .map_err(|e| VefasError::invalid_input("crypto_witness", &format!("Failed to deserialize: {}", e)))?;
    
    if proof.leaf_value.len() != 34 {
        return Err(VefasError::invalid_input("crypto_witness", &format!("Expected 34 bytes, got {}", proof.leaf_value.len())));
    }
    
    // Shared secret is first 32 bytes
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&proof.leaf_value[..32]);
    
    Ok(shared_secret)
}

/// Parse canonical HTTP request to extract method and path
///
/// Format: METHOD\nPATH\nheaders...\n\nbody
pub fn parse_http_request(canonical_bytes: &[u8]) -> VefasResult<(String, String)> {
    let text = core::str::from_utf8(canonical_bytes)
        .map_err(|_| VefasError::invalid_input("http_request", "Invalid UTF-8"))?;
    
    let mut lines = text.lines();
    
    // First line: METHOD
    let method = lines.next()
        .ok_or_else(|| VefasError::invalid_input("http_request", "Missing method"))?
        .to_string();
    
    // Second line: PATH
    let path = lines.next()
        .ok_or_else(|| VefasError::invalid_input("http_request", "Missing path"))?
        .to_string();
    
    Ok((method, path))
}

/// Parse canonical HTTP response to extract status code
///
/// Format: STATUS_CODE\nheaders...\n\nbody
pub fn parse_http_response(canonical_bytes: &[u8]) -> VefasResult<u16> {
    let text = core::str::from_utf8(canonical_bytes)
        .map_err(|_| VefasError::invalid_input("http_response", "Invalid UTF-8"))?;
    
    let mut lines = text.lines();
    
    // First line: STATUS_CODE
    let status_line = lines.next()
        .ok_or_else(|| VefasError::invalid_input("http_response", "Missing status code"))?;
    
    let status_code: u16 = status_line.parse()
        .map_err(|_| VefasError::invalid_input("http_response", &format!("Invalid status code: {}", status_line)))?;
    
    Ok(status_code)
}
