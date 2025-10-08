//! # VEFAS Crypto
//!
//! Cryptographic traits, types, and shared utilities for VEFAS (Verifiable Execution Framework for Agents).
//! This crate provides platform-agnostic interfaces and utilities that work seamlessly in both
//! std (host) and no_std (guest) environments.
//!
//! ## Design Principles
//!
//! - **Strictly no_std**: Built for constrained environments, works everywhere
//! - **Platform Agnostic**: Traits work across all zkVM platforms
//! - **Trait-Only**: Contains only interfaces, types, and utilities - no implementations
//! - **Shared Logic**: Common validation and parsing logic for consistency
//! - **Security First**: Constant-time operations where possible
//!
//! ## Architecture
//!
//! ```text
//! VefasCrypto (no_std + alloc)
//! ├── Traits (platform-agnostic interfaces)
//! ├── Types (cryptographic data structures)
//! ├── Validation (shared parsing and validation)
//! ├── Input Parsing (safe bounds-checked parsing)
//! └── Constants (cryptographic parameters)
//! ```
//!
//! ## Usage
//!
//! This crate is designed to be imported by both host (std) and guest (no_std) environments:
//! - Host applications use vefas-crypto-native for implementations
//! - Guest programs in SP1/RISC0 zkVMs use vefas-crypto-sp1/risc0 for implementations
//! - Shared validation and parsing logic ensures consistency across platforms

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![warn(missing_debug_implementations)]

extern crate alloc;

// Note: alloc types are available through submodules as needed
use vefas_types::VefasResult;

pub mod constants;
pub mod error;
pub mod http_utils;
pub mod input_validation;
pub mod merkle;
pub mod tls_parser;
pub mod traits;
pub mod types;
pub mod validation;

// Re-export new trait structure for convenience
pub use constants::*;
pub use error::{CryptoError, CryptoResult};
pub use traits::{
    Aead, Hash, Kdf, KeyExchange, PrecompileDetection, PrecompileSummary, Signature, VefasCrypto,
};
pub use types::{
    AeadKey, AeadNonce, CertificateChain, EcdsaSignature, HashOutput, HkdfInfo, HkdfSalt,
    PrivateKey, PublicKey,
};

// Re-export Merkle verification types and traits
pub use merkle::{
    FieldId, MerkleProof, MerkleHasher, MerkleVerifier, MerkleError,
    DOMAIN_SEP_LEAF, DOMAIN_SEP_NODE,
};

// Re-export utility modules for convenience
pub use http_utils::{hex_lower, parse_http_data, HttpData};
pub use input_validation::{validate_handshake_header, validate_tls_record_header, SafeParser};
pub use tls_parser::{
    compute_transcript_hash, decrypt_application_record, decrypt_application_record_mixed, hkdf_expand_label, hkdf_expand_label_for_cipher,
    parse_handshake_header, parse_server_cipher_suite, parse_server_hello_key_share, parse_tls_records,
};
pub use validation::{
    domain_matches, validate_certificate_chain_structure, validate_certificate_message,
    validate_x509_certificate, verify_certificate_chain_signatures, verify_certificate_signature,
};

// Note: Implementation functions have been moved to vefas-crypto-native
// This crate now only contains traits, types, and shared utilities

// Certificate chain validation is handled by the production-grade functions in validation.rs:
// - validate_certificate_chain_structure() for structural validation
// - validate_certificate_domain_binding() for domain binding validation
// - validate_x509_certificate() for individual certificate validation
//
// Full certificate chain validation (including CA trust, OCSP, etc.) would require
// integrating a dedicated X.509 library and is marked as future work.
