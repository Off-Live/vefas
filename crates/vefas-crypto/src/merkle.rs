//! Merkle tree verification traits and types for zkVM environments
//! 
//! Implementations provide concrete types that implement the `MerkleHasher` trait.
//! See individual implementation crates for usage examples.

use core::fmt;
use alloc::vec::Vec;

/// Domain separation constants for Merkle tree construction
pub const DOMAIN_SEP_LEAF: u8 = 0x01;
pub const DOMAIN_SEP_NODE: u8 = 0x02;

/// Field IDs for Selective Disclosure (6 proofs for privacy + performance)
/// 
/// This design balances performance (~25% cycle reduction) with user privacy,
/// allowing selective disclosure of individual HTTP components.
/// 
/// ## User-Verifiable Fields (Selective Disclosure)
/// Users can independently verify and share these fields without revealing others:
/// - HttpRequest: Prove the exact request sent
/// - HttpResponse: Prove the exact response received  
/// - Domain: Prove which domain was contacted
/// - Timestamp: Prove when the request occurred
/// 
/// ## Internal Fields (Performance Optimization)
/// These composite fields optimize zkVM performance while maintaining security:
/// - HandshakeProof: Proves TLS handshake validity
/// - CryptoWitness: Private cryptographic parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldId {
    // === USER-VERIFIABLE FIELDS (Selective Disclosure) ===
    
    /// HTTP Request (Canonical Format)
    /// 
    /// Users can selectively disclose just the request without revealing the response.
    /// 
    /// Format: METHOD\nPATH\nheader: value\n...\n\nbody
    HttpRequest = 1,
    
    /// HTTP Response (Canonical Format)
    /// 
    /// Users can selectively disclose just the response without revealing the request.
    /// 
    /// Format: STATUS_CODE\nheader: value\n...\n\nbody
    HttpResponse = 2,
    
    /// Domain Name
    /// 
    /// The server domain that was contacted (e.g., "example.com").
    /// Users can prove which domain without revealing request/response content.
    Domain = 3,
    
    /// Request Timestamp
    /// 
    /// Unix timestamp when the request was made.
    /// Users can prove when the request occurred.
    Timestamp = 4,
    
    // === INTERNAL FIELDS (Performance Optimization) ===
    
    /// Handshake Proof (Composite)
    /// 
    /// Proves TLS 1.3 handshake validity without exposing individual messages.
    /// 
    /// Contains: ClientHello + ServerHello + AllHandshakeTranscript + ServerFinished
    /// Format: [msg1_len(4)][msg1_data]...[transcript_len(4)][transcript][finished_len(4)][finished]
    HandshakeProof = 10,
    
    /// Crypto Witness (Composite)
    /// 
    /// Private cryptographic parameters for zkVM verification.
    /// 
    /// Contains: SharedSecret + CipherSuite
    /// Format: [shared_secret(32)][cipher_suite(2)]
    /// Total: 34 bytes fixed size
    CryptoWitness = 11,
}

/// Merkle inclusion proof
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_value: Vec<u8>,
    pub siblings: Vec<[u8; 32]>,
    pub directions: Vec<bool>, // true = right, false = left
}

/// Trait for low-level hash operations used in Merkle trees
/// 
/// Implementations must provide SHA256 hashing capability.
pub trait MerkleHasher {
    /// Hash arbitrary data and return a 32-byte digest
    fn hash_data(&self, data: &[u8]) -> Result<[u8; 32], MerkleError>;
    
    /// Get the hasher name for debugging
    fn hasher_name(&self) -> &'static str;
}

/// Trait for Merkle tree verification in guest environments
/// 
/// This trait provides high-level Merkle proof verification using domain-separated hashing.
/// It builds on top of `MerkleHasher` to provide TLS-specific Merkle operations.
pub trait MerkleVerifier: MerkleHasher {
    /// Verify an inclusion proof
    fn verify_inclusion_proof(
        &self,
        merkle_root: &[u8; 32],
        proof: &MerkleProof,
        field_id: FieldId,
        leaf_value: &[u8],
    ) -> Result<bool, MerkleError> {
        // Verify that the leaf value matches the proof
        if leaf_value != proof.leaf_value.as_slice() {
            return Ok(false);
        }

        // Recompute leaf hash
        let leaf_hash = self.hash_leaf(field_id, leaf_value)?;

        // Verify proof path
        let mut current_hash = leaf_hash;
        for (i, &sibling_hash) in proof.siblings.iter().enumerate() {
            let (left, right) = if proof.directions[i] {
                (current_hash, sibling_hash)
            } else {
                (sibling_hash, current_hash)
            };
            
            current_hash = self.hash_node(left, right)?;
        }

        Ok(current_hash == *merkle_root)
    }
    
    /// Hash a leaf with domain separation
    fn hash_leaf(&self, field_id: FieldId, value: &[u8]) -> Result<[u8; 32], MerkleError> {
        // Create input data with proper domain separation
        let mut input_data = Vec::new();
        
        // Add domain separator
        input_data.push(DOMAIN_SEP_LEAF);
        
        // Add field ID
        input_data.push(field_id as u8);
        
        // Add length (4 bytes, little-endian)
        let length_bytes = (value.len() as u32).to_le_bytes();
        input_data.extend_from_slice(&length_bytes);
        
        // Add the actual value data
        input_data.extend_from_slice(value);
        
        // Hash using the underlying hasher
        self.hash_data(&input_data)
    }
    
    /// Hash an internal node
    fn hash_node(&self, left: [u8; 32], right: [u8; 32]) -> Result<[u8; 32], MerkleError> {
        // Create input data with proper domain separation
        let mut input_data = Vec::new();
        
        // Add domain separator
        input_data.push(DOMAIN_SEP_NODE);
        
        // Add left hash
        input_data.extend_from_slice(&left);
        
        // Add right hash
        input_data.extend_from_slice(&right);
        
        // Hash using the underlying hasher
        self.hash_data(&input_data)
    }
}

/// Merkle tree errors
#[derive(Debug)]
pub enum MerkleError {
    EmptyTree,
    FieldNotFound,
    HashError,
    InvalidProof,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleError::EmptyTree => write!(f, "Empty tree"),
            MerkleError::FieldNotFound => write!(f, "Field not found"),
            MerkleError::HashError => write!(f, "Hash computation error"),
            MerkleError::InvalidProof => write!(f, "Invalid proof"),
        }
    }
}

#[cfg(feature = "std")]
impl core::error::Error for MerkleError {}
