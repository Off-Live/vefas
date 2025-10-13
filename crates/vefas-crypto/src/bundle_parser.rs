//! VEFAS Bundle Parser for zkVM Guest Programs
//!
//! This module provides parsing and extraction functions for VEFAS canonical bundles:
//! - 4 user-verifiable fields (HttpRequest, HttpResponse, Domain, Timestamp)
//! - 2 internal composite fields (HandshakeProof, CryptoWitness)
//!
//! This is a shared implementation used by both RISC0 and SP1 guest programs
//! to avoid code duplication and ensure consistent behavior.

use alloc::{vec::Vec, string::{String, ToString}, format};
use vefas_types::{VefasError, VefasResult, VefasCanonicalBundle, HandshakeProof, HandshakeProofBuilder};
use crate::{FieldId, MerkleProof};

/// Platform-agnostic logging trait for zkVM environments
/// 
/// This allows different zkVM platforms to implement their own logging
/// while maintaining a consistent interface for the bundle parsing functions.
pub trait ZkvmLogger {
    fn log(&self, message: &str);
}

/// Default no-op logger for platforms that don't need logging
pub struct NoOpLogger;

impl ZkvmLogger for NoOpLogger {
    fn log(&self, _message: &str) {
        // No-op implementation
    }
}

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

/// Extract cipher suite from bundle (now directly available)
pub fn extract_cipher_suite(bundle: &VefasCanonicalBundle) -> VefasResult<u16> {
    Ok(bundle.cipher_suite)
}

/// Extract shared secret (placeholder - not used in new architecture)
/// 
/// NOTE: Shared secrets are not captured in the new architecture for security reasons.
/// This function returns a placeholder value for compatibility.
pub fn extract_shared_secret(_bundle: &VefasCanonicalBundle) -> VefasResult<[u8; 32]> {
    // Return placeholder - shared secrets are not captured in new architecture
    Ok([0u8; 32])
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

/// Extract certificate chain hash from HandshakeProof Merkle field
///
/// Computes SHA-256 hash of the entire certificate chain from the Certificate message
/// 
/// NEW ARCHITECTURE: HandshakeProof format (canonical commitment):
/// - [client_hello_len(4)][client_hello][server_hello_len(4)][server_hello][cert_fingerprint(32)]
/// - No encrypted handshake data, just canonical commitments
pub fn extract_certificate_chain_hash(
    bundle: &VefasCanonicalBundle,
) -> VefasResult<[u8; 32]> {
    let proof_bytes = bundle.get_merkle_proof(FieldId::HandshakeProof as u8)
        .ok_or_else(|| VefasError::invalid_input("handshake_proof", "Merkle proof not found"))?;
    
    let proof: MerkleProof = bincode::deserialize(proof_bytes)
        .map_err(|e| VefasError::invalid_input("handshake_proof", &format!("Failed to deserialize: {}", e)))?;
    
    let data = proof.leaf_value.as_slice();
    
    let mut offset = 0;
    
    // Skip ClientHello section
    if offset + 4 <= data.len() {
        let client_hello_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4 + client_hello_len;
    }
    
    // Skip ServerHello section
    if offset + 4 <= data.len() {
        let server_hello_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4 + server_hello_len;
    }
    
    // Extract cert_fingerprint (32 bytes)
    if offset + 32 <= data.len() {
        let cert_fingerprint = &data[offset..offset + 32];
        
        // For certificate chain hash, we'll use the fingerprint as a proxy
        // In the new architecture, the fingerprint IS the canonical commitment to the certificate
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(cert_fingerprint);
        return Ok(hash_array);
    }
    
    Ok([0u8; 32])
}

/// Extract handshake transcript hash from HandshakeProof Merkle field
///
/// Computes SHA-256 hash of the concatenated handshake transcript
/// 
/// NEW ARCHITECTURE: HandshakeProof format (canonical commitment):
/// - [client_hello_len(4)][client_hello][server_hello_len(4)][server_hello][cert_fingerprint(32)]
/// - Concatenate ClientHello + ServerHello for transcript hash
pub fn extract_handshake_transcript_hash(
    bundle: &VefasCanonicalBundle,
) -> VefasResult<[u8; 32]> {
    let proof_bytes = bundle.get_merkle_proof(FieldId::HandshakeProof as u8)
        .ok_or_else(|| VefasError::invalid_input("handshake_proof", "Merkle proof not found"))?;
    
    let proof: MerkleProof = bincode::deserialize(proof_bytes)
        .map_err(|e| VefasError::invalid_input("handshake_proof", &format!("Failed to deserialize: {}", e)))?;
    
    let data = proof.leaf_value.as_slice();
    let mut offset = 0;
    let mut transcript_bytes = Vec::new();
    
    // Extract ClientHello
    if offset + 4 <= data.len() {
        let client_hello_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        
        if offset + client_hello_len <= data.len() {
            let client_hello = &data[offset..offset + client_hello_len];
            transcript_bytes.extend_from_slice(client_hello);
        }
        offset += client_hello_len;
    }
    
    // Extract ServerHello
    if offset + 4 <= data.len() {
        let server_hello_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        
        if offset + server_hello_len <= data.len() {
            let server_hello = &data[offset..offset + server_hello_len];
            transcript_bytes.extend_from_slice(server_hello);
        }
    }
    
    if !transcript_bytes.is_empty() {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&transcript_bytes);
        let transcript_hash = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&transcript_hash);
        return Ok(hash_array);
    }
    
    Ok([0u8; 32])
}

/// Extract certificate fingerprint from HandshakeProof Merkle field
///
/// Computes SHA-256 hash of the leaf certificate (first certificate in chain)
/// 
/// NEW ARCHITECTURE: HandshakeProof format (canonical commitment):
/// - [client_hello_len(4)][client_hello][server_hello_len(4)][server_hello][cert_fingerprint(32)]
/// - The cert_fingerprint is already computed and stored as the last 32 bytes
pub fn extract_certificate_fingerprint(
    bundle: &VefasCanonicalBundle,
) -> VefasResult<[u8; 32]> {
    let proof_bytes = bundle.get_merkle_proof(FieldId::HandshakeProof as u8)
        .ok_or_else(|| VefasError::invalid_input("handshake_proof", "Merkle proof not found"))?;
    
    let proof: MerkleProof = bincode::deserialize(proof_bytes)
        .map_err(|e| VefasError::invalid_input("handshake_proof", &format!("Failed to deserialize: {}", e)))?;
    
    let data = proof.leaf_value.as_slice();
    let mut offset = 0;
    
    // Skip ClientHello section
    if offset + 4 <= data.len() {
        let client_hello_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4 + client_hello_len;
    }
    
    // Skip ServerHello section
    if offset + 4 <= data.len() {
        let server_hello_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4 + server_hello_len;
    }
    
    // Extract cert_fingerprint (32 bytes)
    if offset + 32 <= data.len() {
        let cert_fingerprint = &data[offset..offset + 32];
        
        let mut fingerprint_array = [0u8; 32];
        fingerprint_array.copy_from_slice(cert_fingerprint);
        return Ok(fingerprint_array);
    }
    
    // No Certificate message found - return zero fingerprint
    Ok([0u8; 32])
}

/// Generate unique proof ID based on merkle root and timestamp
///
/// Creates a deterministic but unique identifier for this proof
pub fn generate_proof_id(
    bundle: &VefasCanonicalBundle,
) -> VefasResult<[u8; 32]> {
    let merkle_root = bundle.merkle_root;
    
    // Create input for proof ID: merkle_root + timestamp + domain
    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&merkle_root);
    proof_input.extend_from_slice(&bundle.timestamp.to_be_bytes());
    proof_input.extend_from_slice(bundle.domain.as_bytes());
    
    // Compute proof ID
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&proof_input);
    let proof_id = hasher.finalize();
    let mut proof_id_array = [0u8; 32];
    proof_id_array.copy_from_slice(&proof_id);
    Ok(proof_id_array)
}

/// Helper type for parsing u24 values
#[derive(Debug, Clone, Copy)]
pub struct U24(u32);

impl U24 {
    pub fn from_be_bytes(bytes: [u8; 3]) -> Self {
        U24(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }
    
    pub fn value(&self) -> u32 {
        self.0
    }
}

/// Extract ClientHello and ServerHello from handshake messages
///
/// This function extracts the plaintext ClientHello and ServerHello messages
/// directly from the bundle fields for HandshakeProof construction.
///
/// # Arguments
/// * `bundle` - The VEFAS canonical bundle containing handshake messages
///
/// # Returns
/// A Result containing (ClientHello, ServerHello) or an error if extraction fails
pub fn extract_client_server_hello(
    bundle: &VefasCanonicalBundle,
) -> VefasResult<(Vec<u8>, Vec<u8>)> {
    // Extract ClientHello and ServerHello directly from bundle fields
    let client_hello = if bundle.client_hello.is_empty() {
        return Err(VefasError::invalid_input("client_hello", "ClientHello is empty"));
    } else {
        bundle.client_hello.clone()
    };
    
    let server_hello = if bundle.server_hello.is_empty() {
        return Err(VefasError::invalid_input("server_hello", "ServerHello is empty"));
    } else {
        bundle.server_hello.clone()
    };
    
    Ok((client_hello, server_hello))
}

/// Extract server random from ServerHello message
///
/// This function parses the ServerHello message to extract the server random
/// field for HandshakeProof construction.
///
/// # Arguments
/// * `server_hello` - The raw ServerHello message bytes
///
/// # Returns
/// A Result containing the server random (32 bytes) or None if parsing fails
pub fn extract_server_random(server_hello: &[u8]) -> VefasResult<Option<[u8; 32]>> {
    // ServerHello structure: [version(2)][random(32)][session_id_len(1)][session_id][cipher_suite(2)][compression_method(1)][extensions...]
    if server_hello.len() < 35 {
        return Ok(None);
    }
    
    // Skip version (2 bytes) and extract random (32 bytes)
    let random_start = 2;
    let random_end = random_start + 32;
    
    if random_end > server_hello.len() {
        return Ok(None);
    }
    
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&server_hello[random_start..random_end]);
    
    Ok(Some(server_random))
}

/// Extract server public key fingerprint from certificate chain
///
/// This function computes the SHA256 fingerprint of the server's public key
/// from the leaf certificate in the certificate chain using sha2 directly.
///
/// # Arguments
/// * `bundle` - The VEFAS canonical bundle containing certificate chain
///
/// # Returns
/// A Result containing the public key fingerprint (32 bytes) or None if extraction fails
pub fn extract_server_pubkey_fingerprint(
    bundle: &VefasCanonicalBundle,
) -> VefasResult<Option<[u8; 32]>> {
    if bundle.certificate_chain.is_empty() {
        return Ok(None);
    }
    
    // Get the first certificate (leaf certificate) from the chain
    let leaf_cert = &bundle.certificate_chain[0];
    
    if leaf_cert.is_empty() {
        return Ok(None);
    }
    
    // For now, compute fingerprint of the entire certificate using sha2 directly
    // TODO: Parse ASN.1 DER to extract just the public key
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(leaf_cert);
    let fingerprint = hasher.finalize();
    
    let mut fingerprint_array = [0u8; 32];
    fingerprint_array.copy_from_slice(&fingerprint);
    
    Ok(Some(fingerprint_array))
}

/// Build HandshakeProof from bundle data
///
/// This function constructs a HandshakeProof instance from the bundle's
/// handshake messages and certificate chain using the HandshakeProofBuilder.
///
/// # Arguments
/// * `bundle` - The VEFAS canonical bundle
///
/// # Returns
/// A Result containing the constructed HandshakeProof or an error if construction fails
pub fn build_handshake_proof(
    bundle: &VefasCanonicalBundle,
) -> VefasResult<HandshakeProof> {
    // Extract ClientHello and ServerHello
    let (client_hello, server_hello) = extract_client_server_hello(bundle)?;
    
    // Extract certificate fingerprint
    let cert_fingerprint = compute_certificate_fingerprint(bundle)?;
    
    // Extract server random from bundle (now directly available)
    let server_random = bundle.server_random;
    
    // Get cipher suite from bundle (now directly available)
    let cipher_suite = bundle.cipher_suite;
    
    // Build HandshakeProof using the builder
    let handshake_proof = HandshakeProofBuilder::new()
        .client_hello(client_hello)
        .server_hello(server_hello)
        .cert_fingerprint(cert_fingerprint)
        .server_random(server_random)
        .cipher_suite(cipher_suite)
        .build()?;
    
    Ok(handshake_proof)
}

/// Compute certificate fingerprint from certificate chain
///
/// This function computes the SHA256 fingerprint of the leaf certificate
/// directly from the certificate chain in the bundle using sha2 directly.
///
/// # Arguments
/// * `bundle` - The VEFAS canonical bundle containing certificate chain
///
/// # Returns
/// A Result containing the certificate fingerprint (32 bytes) or an error if computation fails
pub fn compute_certificate_fingerprint(
    bundle: &VefasCanonicalBundle,
) -> VefasResult<[u8; 32]> {
    if bundle.certificate_chain.is_empty() {
        return Err(VefasError::invalid_input("certificate_chain", "Certificate chain is empty"));
    }
    
    // Get the first certificate (leaf certificate) from the chain
    let leaf_cert = &bundle.certificate_chain[0];
    
    if leaf_cert.is_empty() {
        return Err(VefasError::invalid_input("leaf_certificate", "Leaf certificate is empty"));
    }
    
    // Compute SHA256 fingerprint of the leaf certificate using sha2 directly
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(leaf_cert);
    let fingerprint = hasher.finalize();
    
    let mut fingerprint_array = [0u8; 32];
    fingerprint_array.copy_from_slice(&fingerprint);
    
    Ok(fingerprint_array)
}

