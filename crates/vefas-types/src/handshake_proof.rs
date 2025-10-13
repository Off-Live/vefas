//! HandshakeProof structure for VEFAS TLS verification
//!
//! This module defines the HandshakeProof struct that represents a canonical
//! commitment to TLS handshake components without exposing encrypted data.
//!
//! ## Format
//!
//! HandshakeProof = H(ClientHello || ServerHello || cert_fingerprint || server_random || server_pubkey_fingerprint)
//!
//! ## Serialization Format
//!
//! ```
//! [client_hello_len(4)][client_hello][server_hello_len(4)][server_hello][cert_fingerprint(32)][server_random(32)][server_pubkey_fingerprint(32)]
//! ```
//!
//! Where:
//! - All lengths are big-endian u32
//! - server_random and server_pubkey_fingerprint are optional (32 bytes each)
//! - cert_fingerprint is always present (32 bytes)

use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

use crate::errors::{VefasError, VefasResult};

/// HandshakeProof structure for canonical TLS handshake commitment
///
/// This struct represents a commitment to essential TLS handshake components
/// without exposing encrypted handshake data. It enables verifiable TLS
/// verification while maintaining performance and security.
///
/// ## New Format
///
/// HandshakeProof = H(ClientHello || ServerHello || cert_fingerprint || server_random || cipher_suite)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandshakeProof {
    /// Plaintext ClientHello message
    pub client_hello: Vec<u8>,
    
    /// Plaintext ServerHello message  
    pub server_hello: Vec<u8>,
    
    /// SHA256 fingerprint of the leaf certificate
    pub cert_fingerprint: [u8; 32],
    
    /// Server random from ServerHello (always present)
    pub server_random: [u8; 32],
    
    /// Negotiated cipher suite
    pub cipher_suite: u16,
}

impl HandshakeProof {
    /// Create a new HandshakeProof instance
    pub fn new(
        client_hello: Vec<u8>,
        server_hello: Vec<u8>,
        cert_fingerprint: [u8; 32],
        server_random: [u8; 32],
        cipher_suite: u16,
    ) -> Self {
        Self {
            client_hello,
            server_hello,
            cert_fingerprint,
            server_random,
            cipher_suite,
        }
    }

    /// Serialize HandshakeProof to bytes using the canonical format
    ///
    /// Format: [client_hello_len(4)][client_hello][server_hello_len(4)][server_hello][cert_fingerprint(32)][server_random(32)][cipher_suite(2)]
    pub fn to_bytes(&self) -> VefasResult<Vec<u8>> {
        let mut data = Vec::new();
        
        // Add ClientHello with length prefix
        let client_hello_len = self.client_hello.len() as u32;
        data.extend_from_slice(&client_hello_len.to_be_bytes());
        data.extend_from_slice(&self.client_hello);
        
        // Add ServerHello with length prefix
        let server_hello_len = self.server_hello.len() as u32;
        data.extend_from_slice(&server_hello_len.to_be_bytes());
        data.extend_from_slice(&self.server_hello);
        
        // Add certificate fingerprint (always present)
        data.extend_from_slice(&self.cert_fingerprint);
        
        // Add server random (always present)
        data.extend_from_slice(&self.server_random);
        
        // Add cipher suite (always present)
        data.extend_from_slice(&self.cipher_suite.to_be_bytes());
        
        Ok(data)
    }

    /// Deserialize HandshakeProof from bytes using the canonical format
    pub fn from_bytes(data: &[u8]) -> VefasResult<Self> {
        let mut offset = 0;
        
        // Parse ClientHello
        if offset + 4 > data.len() {
            return Err(VefasError::invalid_input("handshake_proof", "Insufficient data for ClientHello length"));
        }
        let client_hello_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        
        if offset + client_hello_len > data.len() {
            return Err(VefasError::invalid_input("handshake_proof", "Insufficient data for ClientHello"));
        }
        let client_hello = data[offset..offset + client_hello_len].to_vec();
        offset += client_hello_len;
        
        // Parse ServerHello
        if offset + 4 > data.len() {
            return Err(VefasError::invalid_input("handshake_proof", "Insufficient data for ServerHello length"));
        }
        let server_hello_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        
        if offset + server_hello_len > data.len() {
            return Err(VefasError::invalid_input("handshake_proof", "Insufficient data for ServerHello"));
        }
        let server_hello = data[offset..offset + server_hello_len].to_vec();
        offset += server_hello_len;
        
        // Parse certificate fingerprint
        if offset + 32 > data.len() {
            return Err(VefasError::invalid_input("handshake_proof", "Insufficient data for certificate fingerprint"));
        }
        let mut cert_fingerprint = [0u8; 32];
        cert_fingerprint.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        // Parse server random (always present)
        if offset + 32 > data.len() {
            return Err(VefasError::invalid_input("handshake_proof", "Insufficient data for server random"));
        }
        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        // Parse cipher suite (always present)
        if offset + 2 > data.len() {
            return Err(VefasError::invalid_input("handshake_proof", "Insufficient data for cipher suite"));
        }
        let cipher_suite = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap());
        offset += 2;
        
        Ok(Self {
            client_hello,
            server_hello,
            cert_fingerprint,
            server_random,
            cipher_suite,
        })
    }

    /// Compute the canonical commitment hash of this HandshakeProof
    ///
    /// This creates a deterministic hash that can be used to verify
    /// the integrity of the handshake proof without exposing the raw data.
    pub fn compute_commitment_hash<H>(&self, hasher: &H) -> VefasResult<[u8; 32]>
    where
        H: crate::traits::Hash,
    {
        let mut commitment_data = Vec::new();
        
        // Concatenate all components in canonical order
        commitment_data.extend_from_slice(&self.client_hello);
        commitment_data.extend_from_slice(&self.server_hello);
        commitment_data.extend_from_slice(&self.cert_fingerprint);
        
        // Add server random (always present)
        commitment_data.extend_from_slice(&self.server_random);
        
        // Add cipher suite
        commitment_data.extend_from_slice(&self.cipher_suite.to_be_bytes());
        
        // Compute SHA256 hash
        let hash = hasher.sha256(&commitment_data);
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash);
        
        Ok(hash_array)
    }

    /// Validate the HandshakeProof structure
    pub fn validate(&self) -> VefasResult<()> {
        // Validate ClientHello is not empty
        if self.client_hello.is_empty() {
            return Err(VefasError::invalid_input("client_hello", "ClientHello cannot be empty"));
        }
        
        // Validate ServerHello is not empty
        if self.server_hello.is_empty() {
            return Err(VefasError::invalid_input("server_hello", "ServerHello cannot be empty"));
        }
        
        // Validate certificate fingerprint is not all zeros
        if self.cert_fingerprint.iter().all(|&b| b == 0) {
            return Err(VefasError::invalid_input("cert_fingerprint", "Certificate fingerprint cannot be all zeros"));
        }
        
        Ok(())
    }
}

/// Builder for constructing HandshakeProof instances
///
/// This builder provides a fluent interface for constructing HandshakeProof
/// instances with proper validation and error handling.
#[derive(Debug)]
pub struct HandshakeProofBuilder {
    client_hello: Option<Vec<u8>>,
    server_hello: Option<Vec<u8>>,
    cert_fingerprint: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,
    cipher_suite: Option<u16>,
}

impl HandshakeProofBuilder {
    /// Create a new HandshakeProofBuilder
    pub fn new() -> Self {
        Self {
            client_hello: None,
            server_hello: None,
            cert_fingerprint: None,
            server_random: None,
            cipher_suite: None,
        }
    }

    /// Set the ClientHello message
    pub fn client_hello(mut self, client_hello: Vec<u8>) -> Self {
        self.client_hello = Some(client_hello);
        self
    }

    /// Set the ServerHello message
    pub fn server_hello(mut self, server_hello: Vec<u8>) -> Self {
        self.server_hello = Some(server_hello);
        self
    }

    /// Set the certificate fingerprint
    pub fn cert_fingerprint(mut self, cert_fingerprint: [u8; 32]) -> Self {
        self.cert_fingerprint = Some(cert_fingerprint);
        self
    }

    /// Set the server random
    pub fn server_random(mut self, server_random: [u8; 32]) -> Self {
        self.server_random = Some(server_random);
        self
    }

    /// Set the cipher suite
    pub fn cipher_suite(mut self, cipher_suite: u16) -> Self {
        self.cipher_suite = Some(cipher_suite);
        self
    }

    /// Build the HandshakeProof instance
    ///
    /// # Returns
    /// A Result containing the constructed HandshakeProof or an error if
    /// required fields are missing or invalid.
    pub fn build(self) -> VefasResult<HandshakeProof> {
        let client_hello = self.client_hello
            .ok_or_else(|| VefasError::invalid_input("client_hello", "ClientHello is required"))?;
        
        let server_hello = self.server_hello
            .ok_or_else(|| VefasError::invalid_input("server_hello", "ServerHello is required"))?;
        
        let cert_fingerprint = self.cert_fingerprint
            .ok_or_else(|| VefasError::invalid_input("cert_fingerprint", "Certificate fingerprint is required"))?;
        
        let server_random = self.server_random
            .ok_or_else(|| VefasError::invalid_input("server_random", "Server random is required"))?;
        
        let cipher_suite = self.cipher_suite
            .ok_or_else(|| VefasError::invalid_input("cipher_suite", "Cipher suite is required"))?;

        let proof = HandshakeProof {
            client_hello,
            server_hello,
            cert_fingerprint,
            server_random,
            cipher_suite,
        };

        // Validate the constructed proof
        proof.validate()?;

        Ok(proof)
    }
}

impl Default for HandshakeProofBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for HandshakeProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HandshakeProof(client_hello: {} bytes, server_hello: {} bytes, cert_fingerprint: {:02x?}, cipher_suite: 0x{:04x})",
            self.client_hello.len(),
            self.server_hello.len(),
            self.cert_fingerprint,
            self.cipher_suite
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_handshake_proof_serialization() {
        let client_hello = vec![1, 2, 3, 4];
        let server_hello = vec![5, 6, 7, 8];
        let cert_fingerprint = [0xAA; 32];
        let server_random = [0xBB; 32];
        let cipher_suite = 0x1301;
        
        let proof = HandshakeProof::new(
            client_hello.clone(), 
            server_hello.clone(), 
            cert_fingerprint,
            server_random,
            cipher_suite
        );
        
        // Test serialization
        let serialized = proof.to_bytes().unwrap();
        
        // Test deserialization
        let deserialized = HandshakeProof::from_bytes(&serialized).unwrap();
        
        assert_eq!(proof, deserialized);
        assert_eq!(deserialized.client_hello, client_hello);
        assert_eq!(deserialized.server_hello, server_hello);
        assert_eq!(deserialized.cert_fingerprint, cert_fingerprint);
        assert_eq!(deserialized.server_random, server_random);
        assert_eq!(deserialized.cipher_suite, cipher_suite);
    }

    #[test]
    fn test_handshake_proof_builder() {
        let client_hello = vec![1, 2, 3, 4];
        let server_hello = vec![5, 6, 7, 8];
        let cert_fingerprint = [0xAA; 32];
        let server_random = [0xBB; 32];
        let cipher_suite = 0x1301;
        
        let proof = HandshakeProofBuilder::new()
            .client_hello(client_hello.clone())
            .server_hello(server_hello.clone())
            .cert_fingerprint(cert_fingerprint)
            .server_random(server_random)
            .cipher_suite(cipher_suite)
            .build()
            .unwrap();
        
        // Test serialization
        let serialized = proof.to_bytes().unwrap();
        
        // Test deserialization
        let deserialized = HandshakeProof::from_bytes(&serialized).unwrap();
        
        assert_eq!(proof, deserialized);
        assert_eq!(deserialized.server_random, server_random);
        assert_eq!(deserialized.cipher_suite, cipher_suite);
    }

    #[test]
    fn test_handshake_proof_validation() {
        let client_hello = vec![1, 2, 3, 4];
        let server_hello = vec![5, 6, 7, 8];
        let cert_fingerprint = [0xAA; 32];
        
        let proof = HandshakeProof::new(client_hello, server_hello, cert_fingerprint);
        assert!(proof.validate().is_ok());
        
        // Test empty ClientHello
        let invalid_proof = HandshakeProof::new(vec![], vec![1, 2, 3], [0xAA; 32]);
        assert!(invalid_proof.validate().is_err());
        
        // Test empty ServerHello
        let invalid_proof = HandshakeProof::new(vec![1, 2, 3], vec![], [0xAA; 32]);
        assert!(invalid_proof.validate().is_err());
        
        // Test zero certificate fingerprint
        let invalid_proof = HandshakeProof::new(vec![1, 2, 3], vec![4, 5, 6], [0; 32]);
        assert!(invalid_proof.validate().is_err());
    }

    #[test]
    fn test_handshake_proof_builder() {
        let client_hello = vec![1, 2, 3, 4];
        let server_hello = vec![5, 6, 7, 8];
        let cert_fingerprint = [0xAA; 32];
        let server_random = Some([0xBB; 32]);
        let server_pubkey_fingerprint = Some([0xCC; 32]);
        
        // Test successful build
        let proof = HandshakeProofBuilder::new()
            .client_hello(client_hello.clone())
            .server_hello(server_hello.clone())
            .cert_fingerprint(cert_fingerprint)
            .server_random(server_random)
            .server_pubkey_fingerprint(server_pubkey_fingerprint)
            .build()
            .unwrap();
        
        assert_eq!(proof.client_hello, client_hello);
        assert_eq!(proof.server_hello, server_hello);
        assert_eq!(proof.cert_fingerprint, cert_fingerprint);
        assert_eq!(proof.server_random, server_random);
        assert_eq!(proof.server_pubkey_fingerprint, server_pubkey_fingerprint);
        
        // Test missing required field
        let result = HandshakeProofBuilder::new()
            .client_hello(client_hello.clone())
            .server_hello(server_hello.clone())
            // Missing cert_fingerprint
            .build();
        
        assert!(result.is_err());
    }
}
