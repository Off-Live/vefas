//! Merkle Tree Commitments for Large HTTP Payloads
//!
//! This module implements Merkle tree-based commitments for large HTTP response bodies,
//! enabling selective disclosure and efficient verification in zkTLS proofs.
//!
//! # Features
//!
//! - **Selective Disclosure**: Prove specific chunks without revealing entire payload
//! - **Memory Efficient**: Process large payloads in fixed-size chunks
//! - **zkVM Optimized**: Efficient hash operations using cryptographic precompiles
//! - **Proof Generation**: Generate inclusion proofs for arbitrary data chunks
//! - **Verification**: Verify proofs against Merkle root commitments
//!
//! # Architecture
//!
//! ```text
//!                     Root Hash
//!                    /          \
//!                H(AB)          H(CD)
//!               /    \         /    \
//!           H(A)    H(B)   H(C)    H(D)
//!            |       |      |       |
//!        Chunk A  Chunk B Chunk C Chunk D
//! ```
//!
//! Each leaf represents a fixed-size chunk of the original data.
//! Interior nodes contain SHA-256 hashes of their children.

use crate::errors::{ZkTlsError, ZkTlsResult};
use zktls_crypto::traits::Hash;
use zktls_crypto::native::NativeCryptoProvider;

use alloc::{vec::Vec, collections::BTreeMap, format};

/// Merkle Tree Commitment for Large Payloads
///
/// Provides efficient commitment scheme for large HTTP response bodies using
/// binary Merkle trees. Supports selective disclosure and proof generation.
pub struct MerkleTreeCommitment {
    /// Merkle tree root hash (32-byte SHA-256)
    root: [u8; 32],
    
    /// Original data chunks (fixed-size)
    chunks: Vec<Vec<u8>>,
    
    /// Chunk size in bytes
    chunk_size: usize,
    
    /// Pre-computed interior node hashes for efficient proof generation
    nodes: BTreeMap<usize, [u8; 32]>,
}

impl MerkleTreeCommitment {
    /// Generate Merkle tree commitment for data
    ///
    /// # Arguments
    /// * `data` - The data to commit to
    /// * `chunk_size` - Size of each chunk in bytes (must be > 0)
    ///
    /// # Returns
    /// Merkle tree commitment with root hash and chunk structure
    ///
    /// # Example
    /// ```rust,no_run
    /// use zktls_core::http::merkle::MerkleTreeCommitment;
    ///
    /// let data = b"Large response body that needs Merkle tree commitment";
    /// let commitment = MerkleTreeCommitment::generate(data, 16)?;
    /// 
    /// assert_eq!(commitment.root().len(), 32);
    /// assert!(commitment.leaf_count() > 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate(data: &[u8], chunk_size: usize) -> ZkTlsResult<Self> {
        if chunk_size == 0 {
            return Err(ZkTlsError::InvalidTlsMessage("Chunk size must be greater than 0".into()));
        }
        
        if data.is_empty() {
            return Err(ZkTlsError::InvalidTlsMessage("Cannot create Merkle tree for empty data".into()));
        }
        
        // Split data into chunks
        let mut chunks = Vec::new();
        for chunk in data.chunks(chunk_size) {
            chunks.push(chunk.to_vec());
        }
        
        // Build Merkle tree bottom-up
        let (root, nodes) = Self::build_tree(&chunks)?;
        
        Ok(MerkleTreeCommitment {
            root,
            chunks,
            chunk_size,
            nodes,
        })
    }
    
    /// Get Merkle root hash
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }
    
    /// Get number of leaf nodes (chunks)
    pub fn leaf_count(&self) -> usize {
        self.chunks.len()
    }
    
    /// Get chunk size in bytes
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }
    
    /// Generate inclusion proof for specific chunk
    ///
    /// # Arguments
    /// * `chunk_index` - Index of the chunk to prove (0-based)
    ///
    /// # Returns
    /// Merkle proof containing sibling hashes needed for verification
    pub fn get_proof(&self, chunk_index: usize) -> ZkTlsResult<MerkleProof> {
        if chunk_index >= self.chunks.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Chunk index {} out of bounds (max: {})", chunk_index, self.chunks.len() - 1)
            ));
        }
        
        let mut siblings = Vec::new();
        let mut current_index = chunk_index;
        let mut level_size = self.chunks.len();
        
        // Traverse up the tree collecting sibling hashes
        while level_size > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            
            // Get sibling hash if it exists, otherwise use current node hash (for odd-numbered nodes)
            if sibling_index < level_size {
                let node_key = Self::node_key(level_size, sibling_index);
                if let Some(&sibling_hash) = self.nodes.get(&node_key) {
                    siblings.push(sibling_hash);
                }
            } else {
                // No sibling exists (rightmost node in odd-sized level)
                // Use the current node's hash as its own sibling (this matches tree construction)
                let current_node_key = Self::node_key(level_size, current_index);
                if let Some(&current_hash) = self.nodes.get(&current_node_key) {
                    siblings.push(current_hash);
                }
            }
            
            current_index /= 2;
            level_size = (level_size + 1) / 2; // Ceiling division
        }
        
        Ok(MerkleProof {
            chunk_index,
            chunk_data: self.chunks[chunk_index].clone(),
            siblings,
        })
    }
    
    /// Generate selective proof for multiple chunks
    ///
    /// # Arguments
    /// * `chunk_indices` - Indices of chunks to include in proof
    ///
    /// # Returns
    /// Selective proof containing only specified chunks and necessary proofs
    pub fn get_selective_proof(&self, chunk_indices: &[usize]) -> ZkTlsResult<SelectiveProof> {
        let mut revealed_chunks = Vec::new();
        let mut proofs = Vec::new();
        
        for &index in chunk_indices {
            if index >= self.chunks.len() {
                return Err(ZkTlsError::InvalidTlsMessage(
                    format!("Chunk index {} out of bounds", index)
                ));
            }
            
            revealed_chunks.push((index, self.chunks[index].clone()));
            proofs.push(self.get_proof(index)?);
        }
        
        Ok(SelectiveProof {
            revealed_chunks,
            proofs,
            total_chunks: self.chunks.len(),
            chunk_size: self.chunk_size,
        })
    }
    
    /// Build Merkle tree from leaf chunks
    ///
    /// Returns tuple of (root_hash, node_map) where node_map contains
    /// all interior node hashes indexed by level and position.
    fn build_tree(chunks: &[Vec<u8>]) -> ZkTlsResult<([u8; 32], BTreeMap<usize, [u8; 32]>)> {
        if chunks.is_empty() {
            return Err(ZkTlsError::InvalidTlsMessage("Cannot build tree from empty chunks".into()));
        }
        
        let crypto = NativeCryptoProvider::new();
        let mut nodes = BTreeMap::new();
        let mut current_level: Vec<[u8; 32]> = Vec::new();
        
        // Hash all leaf chunks
        for chunk in chunks {
            let chunk_hash = crypto.sha256(chunk);
            current_level.push(chunk_hash);
        }
        
        // Store leaf level hashes
        let mut level_size = current_level.len();
        for (i, &hash) in current_level.iter().enumerate() {
            nodes.insert(Self::node_key(level_size, i), hash);
        }
        
        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    left // Duplicate last node if odd number of nodes
                };
                
                // Compute parent hash: H(left || right)
                let mut parent_data = Vec::new();
                parent_data.extend_from_slice(&left);
                parent_data.extend_from_slice(&right);
                let parent_hash = crypto.sha256(&parent_data);
                
                next_level.push(parent_hash);
            }
            
            // Store current level hashes
            level_size = next_level.len();
            for (i, &hash) in next_level.iter().enumerate() {
                nodes.insert(Self::node_key(level_size, i), hash);
            }
            
            current_level = next_level;
        }
        
        Ok((current_level[0], nodes))
    }
    
    /// Generate unique key for node at given level and position
    fn node_key(level_size: usize, position: usize) -> usize {
        level_size * 1000000 + position
    }
}

/// Merkle Inclusion Proof
///
/// Contains all information needed to verify that a specific chunk
/// is included in the Merkle tree commitment.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Index of the chunk being proved
    pub chunk_index: usize,
    
    /// Original chunk data
    pub chunk_data: Vec<u8>,
    
    /// Sibling hashes needed for verification (bottom to top)
    pub siblings: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// Verify proof against Merkle root
    ///
    /// # Arguments
    /// * `root` - Expected Merkle root hash
    ///
    /// # Returns
    /// `true` if proof is valid, `false` otherwise
    pub fn verify(&self, root: &[u8; 32]) -> ZkTlsResult<bool> {
        let crypto = NativeCryptoProvider::new();
        
        // Start with chunk hash
        let mut current_hash = crypto.sha256(&self.chunk_data);
        let mut current_index = self.chunk_index;
        
        // Compute path to root using sibling hashes
        for &sibling in &self.siblings {
            let mut parent_data = Vec::new();
            
            if current_index % 2 == 0 {
                // Current node is left child
                parent_data.extend_from_slice(&current_hash);
                parent_data.extend_from_slice(&sibling);
            } else {
                // Current node is right child
                parent_data.extend_from_slice(&sibling);
                parent_data.extend_from_slice(&current_hash);
            }
            
            current_hash = crypto.sha256(&parent_data);
            current_index /= 2;
        }
        
        Ok(current_hash == *root)
    }
}

/// Selective Disclosure Proof
///
/// Contains proofs for multiple chunks while keeping other chunks hidden.
/// Enables privacy-preserving verification of specific data portions.
#[derive(Debug, Clone)]
pub struct SelectiveProof {
    /// Revealed chunks with their indices
    pub revealed_chunks: Vec<(usize, Vec<u8>)>,
    
    /// Individual Merkle proofs for each revealed chunk
    pub proofs: Vec<MerkleProof>,
    
    /// Total number of chunks in original data
    pub total_chunks: usize,
    
    /// Size of each chunk in bytes
    pub chunk_size: usize,
}

impl SelectiveProof {
    /// Verify selective proof against Merkle root
    ///
    /// # Arguments
    /// * `root` - Expected Merkle root hash
    ///
    /// # Returns
    /// `true` if all revealed chunks are valid, `false` otherwise
    pub fn verify(&self, root: &[u8; 32]) -> ZkTlsResult<bool> {
        if self.revealed_chunks.len() != self.proofs.len() {
            return Ok(false);
        }
        
        // Verify each individual proof
        for (i, proof) in self.proofs.iter().enumerate() {
            let (expected_index, expected_data) = &self.revealed_chunks[i];
            
            // Check proof matches revealed chunk
            if proof.chunk_index != *expected_index || proof.chunk_data != *expected_data {
                return Ok(false);
            }
            
            // Verify proof against root
            if !proof.verify(root)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Get total size of original data
    pub fn original_data_size(&self) -> usize {
        if self.total_chunks == 0 {
            return 0;
        }
        
        // Last chunk might be smaller than chunk_size
        let full_chunks = self.total_chunks - 1;
        let last_chunk_size = self.revealed_chunks
            .iter()
            .find(|(index, _)| *index == self.total_chunks - 1)
            .map(|(_, data)| data.len())
            .unwrap_or(self.chunk_size);
        
        full_chunks * self.chunk_size + last_chunk_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_merkle_tree_creation() {
        let data = b"This is test data for Merkle tree creation and verification";
        let commitment = MerkleTreeCommitment::generate(data, 16).unwrap();
        
        assert_eq!(commitment.root().len(), 32);
        assert!(commitment.leaf_count() > 1);
    }
    
    #[test]
    fn test_merkle_proof_generation_and_verification() {
        let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // 26 bytes
        let commitment = MerkleTreeCommitment::generate(data, 8).unwrap(); // 4 chunks
        
        // Generate proof for first chunk
        let proof = commitment.get_proof(0).unwrap();
        assert_eq!(proof.chunk_index, 0);
        assert_eq!(proof.chunk_data, b"ABCDEFGH");
        
        // Verify proof
        assert!(proof.verify(commitment.root()).unwrap());
    }
    
    #[test]
    fn test_selective_proof() {
        let data = b"0123456789ABCDEF"; // 16 bytes
        let commitment = MerkleTreeCommitment::generate(data, 4).unwrap(); // 4 chunks
        
        // Create selective proof for chunks 0 and 2
        let selective_proof = commitment.get_selective_proof(&[0, 2]).unwrap();
        
        assert_eq!(selective_proof.revealed_chunks.len(), 2);
        assert_eq!(selective_proof.proofs.len(), 2);
        assert_eq!(selective_proof.total_chunks, 4);
        
        // Verify selective proof
        assert!(selective_proof.verify(commitment.root()).unwrap());
    }
    
    #[test]
    fn test_invalid_chunk_index() {
        let data = b"Test data";
        let commitment = MerkleTreeCommitment::generate(data, 4).unwrap();
        
        let result = commitment.get_proof(100); // Invalid index
        assert!(result.is_err());
    }
    
    #[test]
    fn test_empty_data_error() {
        let result = MerkleTreeCommitment::generate(b"", 4);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_zero_chunk_size_error() {
        let result = MerkleTreeCommitment::generate(b"test", 0);
        assert!(result.is_err());
    }
}