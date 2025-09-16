//! ASN.1 DER parsing for X.509 certificates
//!
//! This module provides a minimal, security-focused ASN.1 DER parser optimized
//! for X.509 certificate parsing in zero-knowledge environments. It implements
//! strict DER validation according to ITU-T X.690 specification.
//!
//! # Security Considerations
//! - Strict bounds checking on all operations
//! - No heap allocations in zkVM mode  
//! - Rejects BER indefinite length encoding
//! - Limited recursion depth to prevent stack overflow
//! - Comprehensive input validation

pub mod types;
pub mod parser;
pub mod error;

pub use types::*;
pub use parser::*;
pub use error::*;