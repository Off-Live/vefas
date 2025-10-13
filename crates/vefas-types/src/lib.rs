//! # VEFAS Types
//!
//! Core data structures and types for VEFAS (Verifiable Execution Framework for Agents).
//! This crate provides platform-agnostic, no_std compatible types for zkTLS verification.
//!
//! ## Design Principles
//!
//! - **no_std compatible**: All types work in zkVM guest environments
//! - **Deterministic serialization**: Consistent encoding across platforms
//! - **Zero-copy where possible**: Minimal allocations for performance
//! - **Comprehensive validation**: All inputs validated for security
//!
//! ## Architecture
//!
//! ```text
//! VefasInput (Host → Guest)
//! ├── TLS session data (handshake, certificates, keys)
//! ├── HTTP request/response data
//! └── Metadata (timestamp, domain, etc.)
//!
//! VefasProofClaim (Guest → Host)
//! ├── Cryptographic commitments
//! ├── Verification results
//! └── Execution metadata
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![warn(missing_debug_implementations)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

// No imports needed at lib level

pub mod bundle;
pub mod crypto_provider;
pub mod errors;
pub mod handshake_proof;
pub mod http;
pub mod input;
pub mod output;
pub mod tls;
pub mod traits;
pub mod utils;

// Re-export core types for convenience
pub use bundle::{VefasCanonicalBundle, BundleMetadata};
pub use errors::{VefasError, VefasResult};
pub use handshake_proof::{HandshakeProof, HandshakeProofBuilder};
pub use http::{HttpMethod, HttpRequest, HttpResponse, HttpStatusCode, HttpHeaders};
pub use input::{VefasInput, TlsSessionData, VefasMetadata};
pub use output::{VefasProof, VefasProofClaim, VefasExecutionMetadata, VefasPerformanceMetrics};
pub use tls::{TlsVersion, CipherSuite, SessionKeys, HandshakeData, CertificateChain};
pub use traits::{Hash, Kdf, KeyExchange};

/// Protocol version for VEFAS data structures
pub const VEFAS_PROTOCOL_VERSION: u16 = 1;

/// Maximum size for domain names (RFC 1035)
pub const MAX_DOMAIN_LENGTH: usize = 253;

/// Maximum size for HTTP headers (reasonable limit)
pub const MAX_HTTP_HEADER_SIZE: usize = 8192;

/// Maximum size for HTTP body in zkVM context (memory constraint)
pub const MAX_HTTP_BODY_SIZE: usize = 1024 * 1024; // 1MB

/// Maximum number of certificates in a chain
pub const MAX_CERTIFICATE_CHAIN_LENGTH: usize = 10;

/// Maximum size for TLS handshake transcript
pub const MAX_HANDSHAKE_TRANSCRIPT_SIZE: usize = 64 * 1024; // 64KB