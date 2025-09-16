//! X.509 certificate parsing and validation
//!
//! This module provides X.509 certificate parsing following RFC 5280.
//! It builds on the ASN.1 DER parser foundation to extract certificate 
//! components needed for TLS 1.3 validation.
//!
//! # Supported Features
//! - Certificate structure parsing (version, serial, signature algorithm)
//! - Subject/Issuer Distinguished Name extraction
//! - Public key information (RSA, ECDSA P-256, Ed25519)
//! - Critical extensions (Key Usage, Extended Key Usage, SAN)
//! - Certificate validation and constraints
//! - Domain name validation (RFC 6125 server identity verification)
//!
//! # Security Considerations
//! - Strict ASN.1 DER validation using the existing parser
//! - No heap allocations in zkVM mode
//! - Comprehensive input validation for malformed certificates
//! - Cryptographically secure parsing suitable for zero-knowledge proofs

pub mod certificate;
pub mod extensions;
pub mod distinguished_name;
pub mod public_key;
pub mod validity;
pub mod error;
pub mod validation;
pub mod domain;
pub mod root_ca_store;

pub use certificate::*;
pub use extensions::*;
pub use distinguished_name::*;
pub use public_key::*;
pub use validity::*;
pub use error::*;
pub use validation::*;
pub use root_ca_store::*;

/// Domain validation functionality
pub mod domain_validation {
    pub use super::domain::*;
}