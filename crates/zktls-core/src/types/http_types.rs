//! HTTP and proof-related types
//!
//! This module contains all HTTP and zero-knowledge proof related types
//! including certificate chain data and proof claims.

use serde::{Deserialize, Serialize};

/// Certificate chain data for X.509 validation
#[derive(Debug, Clone)]
pub struct CertificateChainData {
    /// Test case name
    pub name: &'static str,
    /// Certificate chain (DER encoded)
    pub chain: &'static [&'static [u8]],
    /// Root CA certificates (DER encoded)
    pub trusted_roots: &'static [&'static [u8]],
    /// Domain name to validate
    pub domain: &'static str,
    /// Expected validation result
    pub valid: bool,
    /// Validation timestamp (Unix seconds)
    pub timestamp: u64,
}

/// zkProof claim structure for zkVM verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofClaim {
    /// Target domain
    pub domain: &'static str,
    /// HTTP request hash (SHA-256)
    pub request_hash: [u8; 32],
    /// HTTP response hash (SHA-256) 
    pub response_hash: [u8; 32],
    /// Response status code
    pub status_code: u16,
    /// Response body commitment
    pub body_commitment: [u8; 32],
    /// Timestamp of the request
    pub timestamp: u64,
}
