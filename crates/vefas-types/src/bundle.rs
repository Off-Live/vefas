//! Canonical bundle format for host→guest communication
//!
//! This module defines the VefasCanonicalBundle format, which is the key innovation
//! that bridges host (rustls) and guest (minimal verifier) in the revolutionary
//! host-rustls + guest-verifier architecture.
//!
//! ## Design Principles
//!
//! - **Deterministic**: Exact byte representation for consistent verification
//! - **Minimal**: Only essential data needed for TLS verification
//! - **Direct**: Raw captured data without interpretation or transformation
//! - **Efficient**: Optimized for zkVM proof generation

use alloc::{
    format,
    string::String,
    vec::Vec,
};
use core::mem::size_of;
use serde::{Deserialize, Serialize};

use crate::{
    errors::{VefasError, VefasResult},
    utils::format_decimal,
    MAX_DOMAIN_LENGTH, VEFAS_PROTOCOL_VERSION,
};

/// Maximum size for individual handshake messages
pub const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 16 * 1024; // 16KB

/// Maximum size for encrypted TLS records
pub const MAX_TLS_RECORD_SIZE: usize = 16 * 1024 + 256; // 16KB + TLS overhead

/// Maximum size for certificate chain in bundle
pub const MAX_CERTIFICATE_CHAIN_SIZE: usize = 64 * 1024; // 64KB

/// Canonical bundle format for deterministic TLS verification
///
/// This structure contains all data captured by the host during a real TLS session
/// and is passed to the guest program for minimal verification and proof generation.
///
/// The bundle represents the core innovation of the host-rustls + guest-verifier
/// architecture, enabling orders of magnitude cheaper proofs through separation
/// of TLS implementation (host) from verification (guest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VefasCanonicalBundle {
    // === PROTOCOL METADATA ===
    /// VEFAS protocol version
    pub version: u8,
    /// Target domain name for certificate validation
    pub domain: String,
    /// Unix timestamp when session was captured
    pub timestamp: u64,
    /// Expected HTTP status code
    pub expected_status: u16,
    /// Random nonce for proof uniqueness
    pub verifier_nonce: [u8; 32],
    
    // === TLS SESSION DATA ===
    /// TLS protocol version (0x0303 for TLS 1.2, 0x0304 for TLS 1.3)
    pub tls_version: u16,
    /// Negotiated cipher suite
    pub cipher_suite: u16,
    /// Server random from ServerHello
    pub server_random: [u8; 32],
    /// TLS session ID (if present)
    pub session_id: Option<Vec<u8>>,
    /// TLS session ticket (if present)
    pub session_ticket: Option<Vec<u8>>,
    
    // === HANDSHAKE MESSAGES ===
    /// Plaintext ClientHello message
    pub client_hello: Vec<u8>,
    /// Plaintext ServerHello message
    pub server_hello: Vec<u8>,
    
    // === CERTIFICATE DATA ===
    /// DER-encoded certificate chain
    pub certificate_chain: Vec<Vec<u8>>,
    /// SHA256 of leaf certificate (computed)
    pub cert_fingerprint: [u8; 32],
    
    // === APPLICATION DATA ===
    /// Canonicalized HTTP request
    pub http_request: Vec<u8>,
    /// Canonicalized HTTP response
    pub http_response: Vec<u8>,
    
    // === MERKLE TREE DATA ===
    /// Root hash of Merkle tree
    pub merkle_root: [u8; 32],
    /// Inclusion proofs for disclosed fields
    pub merkle_proofs: Vec<(u8, Vec<u8>)>, // (FieldId as u8, serialized MerkleProof)
    
    // === VALIDATION METADATA ===
    /// Whether handshake completed successfully
    pub handshake_complete: bool,
    /// Whether application data was captured
    pub application_data_present: bool,
}


impl VefasCanonicalBundle {
    /// Get Merkle proof for a specific field ID
    pub fn get_merkle_proof(&self, field_id: u8) -> Option<&Vec<u8>> {
        self.merkle_proofs.iter()
            .find(|(id, _)| *id == field_id)
            .map(|(_, proof)| proof)
    }

    /// Create a new canonical bundle with validation
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_hello: Vec<u8>,
        server_hello: Vec<u8>,
        certificate_chain: Vec<Vec<u8>>,
        http_request: Vec<u8>,
        http_response: Vec<u8>,
        domain: String,
        timestamp: u64,
        expected_status: u16,
        verifier_nonce: [u8; 32],
        tls_version: u16,
        cipher_suite: u16,
        server_random: [u8; 32],
        cert_fingerprint: [u8; 32],
        session_id: Option<Vec<u8>>,
        session_ticket: Option<Vec<u8>>,
        handshake_complete: bool,
        application_data_present: bool,
    ) -> VefasResult<Self> {
        let bundle = Self {
            version: VEFAS_PROTOCOL_VERSION as u8,
            domain,
            timestamp,
            expected_status,
            verifier_nonce,
            tls_version,
            cipher_suite,
            server_random,
            session_id,
            session_ticket,
            client_hello,
            server_hello,
            certificate_chain,
            cert_fingerprint,
            http_request,
            http_response,
            merkle_root: [0u8; 32], // Will be set later
            merkle_proofs: Vec::new(),
            handshake_complete,
            application_data_present,
        };

        bundle.validate()?;
        Ok(bundle)
    }

    /// Set Merkle proofs and root
    pub fn set_merkle_proofs(&mut self, merkle_root: [u8; 32], merkle_proofs: Vec<(u8, Vec<u8>)>) {
        self.merkle_root = merkle_root;
        self.merkle_proofs = merkle_proofs;
    }

    /// Get HTTP request data
    pub fn http_request(&self) -> VefasResult<&[u8]> {
        if self.http_request.is_empty() {
            return Err(VefasError::invalid_input("http_request", "No HTTP request data"));
        }
        Ok(&self.http_request)
    }

    /// Get HTTP response data
    pub fn http_response(&self) -> VefasResult<&[u8]> {
        if self.http_response.is_empty() {
            return Err(VefasError::invalid_input("http_response", "No HTTP response data"));
        }
        Ok(&self.http_response)
    }

    /// Validate bundle structure and constraints
    pub fn validate(&self) -> VefasResult<()> {
        // Validate protocol version
        if self.version as u16 != VEFAS_PROTOCOL_VERSION {
            return Err(VefasError::invalid_input(
                "version",
                &format!("Unsupported protocol version: {}", self.version),
            ));
        }

        // Validate domain name
        if self.domain.is_empty() || self.domain.len() > MAX_DOMAIN_LENGTH {
            return Err(VefasError::invalid_input(
                "domain",
                &format!("Invalid domain length: {}", self.domain.len()),
            ));
        }

        // Validate timestamp (must be reasonable Unix timestamp)
        // Note: In no_std environment, we can't get current time, so we just check it's not zero
        if self.timestamp == 0 {
            return Err(VefasError::invalid_input(
                "timestamp",
                "Timestamp cannot be zero",
            ));
        }

        // Validate TLS version
        if self.tls_version != 0x0303 && self.tls_version != 0x0304 {
            return Err(VefasError::invalid_input(
                "tls_version",
                &format!("Unsupported TLS version: 0x{:04x}", self.tls_version),
            ));
        }

        // Validate handshake message sizes
        let handshake_messages = [
            &self.client_hello,
            &self.server_hello,
        ];

        for (i, msg) in handshake_messages.iter().enumerate() {
            if msg.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
                return Err(VefasError::invalid_input(
                    "handshake_message",
                    &format!("Handshake message {} exceeds maximum size: {} > {}", 
                        i, msg.len(), MAX_HANDSHAKE_MESSAGE_SIZE),
                ));
            }
        }

        // Validate certificate chain
        let total_cert_size: usize = self.certificate_chain.iter().map(|cert| cert.len()).sum();
        if total_cert_size > MAX_CERTIFICATE_CHAIN_SIZE {
            return Err(VefasError::invalid_input(
                "certificate_chain",
                &format!("Certificate chain exceeds maximum size: {} > {}", 
                    total_cert_size, MAX_CERTIFICATE_CHAIN_SIZE),
            ));
        }

        // Validate HTTP data sizes
        if self.http_request.len() > MAX_TLS_RECORD_SIZE {
            return Err(VefasError::invalid_input(
                "http_request",
                &format!("HTTP request exceeds maximum size: {} > {}", 
                    self.http_request.len(), MAX_TLS_RECORD_SIZE),
            ));
        }

        if self.http_response.len() > MAX_TLS_RECORD_SIZE {
            return Err(VefasError::invalid_input(
                "http_response",
                &format!("HTTP response exceeds maximum size: {} > {}", 
                    self.http_response.len(), MAX_TLS_RECORD_SIZE),
            ));
        }

        Ok(())
    }

    /// Get memory footprint of the bundle
    pub fn memory_footprint(&self) -> usize {
        size_of::<Self>()
            + self.domain.len()
            + self.client_hello.len()
            + self.server_hello.len()
            + self.certificate_chain.iter().map(|cert| cert.len()).sum::<usize>()
            + self.http_request.len()
            + self.http_response.len()
            + self.merkle_proofs.iter().map(|(_, proof)| proof.len()).sum::<usize>()
            + self.session_id.as_ref().map(|id| id.len()).unwrap_or(0)
            + self.session_ticket.as_ref().map(|ticket| ticket.len()).unwrap_or(0)
    }

    /// Get bundle metadata for analysis
    pub fn metadata(&self) -> BundleMetadata {
        BundleMetadata {
            version: self.version as u16,
            domain: self.domain.clone(),
            timestamp: self.timestamp,
            handshake_message_count: 2, // Only client_hello and server_hello
            certificate_count: self.certificate_chain.len(),
            has_merkle_proofs: !self.merkle_proofs.is_empty(),
            memory_footprint: self.memory_footprint(),
        }
    }
}

/// Bundle metadata for analysis and monitoring
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleMetadata {
    /// Protocol version
    pub version: u16,
    /// Target domain
    pub domain: String,
    /// Capture timestamp
    pub timestamp: u64,
    /// Number of handshake messages
    pub handshake_message_count: usize,
    /// Number of certificates in chain
    pub certificate_count: usize,
    /// Whether Merkle proofs are present
    pub has_merkle_proofs: bool,
    /// Memory footprint in bytes
    pub memory_footprint: usize,
}

impl BundleMetadata {
    /// Get human-readable summary
    pub fn summary(&self) -> String {
        format!(
            "Bundle v{} for {} ({} certificates, {} handshake messages, {} bytes)",
            self.version,
            self.domain,
            self.certificate_count,
            self.handshake_message_count,
            format_decimal(self.memory_footprint)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_creation_and_validation() {
        let bundle = VefasCanonicalBundle::new(
            vec![0x01, 0x00, 0x00, 0x01, 0xFF], // client_hello
            vec![0x02, 0x00, 0x00, 0x01, 0xFF], // server_hello
            Vec::new(), // certificate_chain
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(), // http_request
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(), // http_response
            "example.com".to_string(),
            1234567890, // timestamp
            200, // expected_status
            [0u8; 32], // verifier_nonce
            0x0303, // tls_version (TLS 1.2)
            0x1301, // cipher_suite (TLS_AES_128_GCM_SHA256)
            [1u8; 32], // server_random
            [2u8; 32], // cert_fingerprint
            None, // session_id
            None, // session_ticket
            true, // handshake_complete
            true, // application_data_present
        );

        assert!(bundle.is_ok());
        let bundle = bundle.unwrap();
        assert_eq!(bundle.version as u16, VEFAS_PROTOCOL_VERSION);
        assert_eq!(bundle.domain, "example.com");
        assert_eq!(bundle.timestamp, 1234567890);
        assert_eq!(bundle.tls_version, 0x0303);
        assert_eq!(bundle.cipher_suite, 0x1301);
        assert_eq!(bundle.server_random, [1u8; 32]);
        assert_eq!(bundle.cert_fingerprint, [2u8; 32]);
        assert!(bundle.handshake_complete);
        assert!(bundle.application_data_present);
    }

    #[test]
    fn test_bundle_validation_errors() {
        // Test invalid domain
        let result = VefasCanonicalBundle::new(
            vec![0x01], // client_hello
            vec![0x02], // server_hello
            Vec::new(), // certificate_chain
            Vec::new(), // http_request
            Vec::new(), // http_response
            String::new(), // Invalid empty domain
            1234567890, // timestamp
            200, // expected_status
            [0u8; 32], // verifier_nonce
            0x0303, // tls_version
            0x1301, // cipher_suite
            [0u8; 32], // server_random
            [0u8; 32], // cert_fingerprint
            None, // session_id
            None, // session_ticket
            true, // handshake_complete
            true, // application_data_present
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_proof_management() {
        let mut bundle = VefasCanonicalBundle::new(
            vec![0x01], // client_hello
            vec![0x02], // server_hello
            Vec::new(), // certificate_chain
            Vec::new(), // http_request
            Vec::new(), // http_response
            "example.com".to_string(),
            1234567890, // timestamp
            200, // expected_status
            [0u8; 32], // verifier_nonce
            0x0303, // tls_version
            0x1301, // cipher_suite
            [0u8; 32], // server_random
            [0u8; 32], // cert_fingerprint
            None, // session_id
            None, // session_ticket
            true, // handshake_complete
            true, // application_data_present
        ).unwrap();

        // Initially no Merkle proofs
        assert!(bundle.get_merkle_proof(1).is_none());

        // Set Merkle proofs
        let merkle_root = [1u8; 32];
        let merkle_proofs = vec![(1u8, vec![0xFF, 0xFE])];
        bundle.set_merkle_proofs(merkle_root, merkle_proofs);

        // Now should have Merkle proofs
        assert!(bundle.get_merkle_proof(1).is_some());
        assert_eq!(bundle.merkle_root, merkle_root);
    }

    #[test]
    fn test_bundle_metadata() {
        let bundle = VefasCanonicalBundle::new(
            vec![0x01], // client_hello
            vec![0x02], // server_hello
            vec![vec![0x30, 0x82]], // certificate_chain with one cert
            Vec::new(), // http_request
            Vec::new(), // http_response
            "example.com".to_string(),
            1234567890, // timestamp
            200, // expected_status
            [0u8; 32], // verifier_nonce
            0x0303, // tls_version
            0x1301, // cipher_suite
            [0u8; 32], // server_random
            [0u8; 32], // cert_fingerprint
            None, // session_id
            None, // session_ticket
            true, // handshake_complete
            true, // application_data_present
        ).unwrap();

        let metadata = bundle.metadata();
        assert_eq!(metadata.version, VEFAS_PROTOCOL_VERSION);
        assert_eq!(metadata.domain, "example.com");
        assert_eq!(metadata.certificate_count, 1);
        assert_eq!(metadata.handshake_message_count, 2); // Only client_hello and server_hello
        assert!(!metadata.has_merkle_proofs);
        assert!(metadata.memory_footprint > 0);
    }
}