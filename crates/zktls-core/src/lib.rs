#![no_std]
#![forbid(unsafe_code)]

//! # zkTLS Core - Zero-Knowledge TLS Verification Library
//! 
//! This crate provides the fundamental types, traits, and business logic for 
//! zkTLS implementation across different zkVM platforms (SP1 and RISC0).
//! All types are no_std compatible and optimized for zero-knowledge environments.
//!
//! ## Overview
//!
//! zkTLS enables zero-knowledge proofs of TLS handshakes and HTTP communications,
//! allowing verifiers to cryptographically verify that specific HTTPS requests
//! were made and responses received without revealing the actual data.
//!
//! ## Architecture
//!
//! The library is organized into several key modules:
//!
//! ### Core Modules
//! - [`config`] - Platform and client configuration
//! - [`types`] - Core data structures organized by domain
//! - [`errors`] - Comprehensive error handling
//! - [`utils`] - Utility functions and helpers
//!
//! ### Protocol Implementation
//! - [`tls`] - TLS 1.3 handshake and session management
//! - [`http`] - HTTP/1.1 protocol implementation
//! - [`x509`] - X.509 certificate parsing and validation
//! - [`asn1`] - ASN.1 DER parsing for certificates
//!
//! ### Client and Network
//! - [`client`] - Complete HTTPS client with zkTLS integration
//! - [`network`] - Network communication for zkVM environments
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use zktls_core::client::{HttpsClient, HttpsClientConfig};
//! use zktls_core::http::HttpRequest;
//!
//! // Create client with default configuration
//! let mut client = HttpsClient::new(HttpsClientConfig::default())?;
//!
//! // Make a simple GET request
//! let response = client.get("https://api.example.com/data")?;
//! println!("Status: {}", response.status());
//! 
//! // Access commitments for zkTLS proof generation
//! let request_commitment = response.request_commitment();
//! let response_commitment = response.response_commitment();
//! # Ok::<(), zktls_core::ZkTlsError>(())
//! ```
//!
//! ## Features
//!
//! - **TLS 1.3 Compliance**: Full implementation of RFC 8446
//! - **X.509 Certificate Validation**: Production-grade certificate chain validation
//! - **Zero-Knowledge Optimized**: Designed for efficient zkVM proof generation
//! - **no_std Compatible**: Works in constrained environments
//! - **Comprehensive Testing**: Extensive test suite with real-world scenarios
//!
//! ## Platform Support
//!
//! - **SP1**: Optimized for SP1 zkVM
//! - **RISC0**: Compatible with RISC0 zkVM
//! - **Generic**: Works in any no_std environment

// Enforce mutual exclusion of zkVM platform features at compile time
#[cfg(all(feature = "sp1", feature = "risc0"))]
compile_error!("Cannot enable both 'sp1' and 'risc0' features simultaneously. Please choose only one zkVM platform.");

extern crate alloc;

use core::fmt;
use heapless::Vec as HeaplessVec;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

// Type aliases for better readability and zkVM compatibility  
pub type FixedVec<T, const N: usize> = HeaplessVec<T, N>;

// Common sizes for zkTLS operations
pub const MAX_CERT_SIZE: usize = 4096;
pub const MAX_MESSAGE_SIZE: usize = 2048;
pub const MAX_HANDSHAKE_SIZE: usize = 8192;
pub const MAX_RESPONSE_SIZE: usize = 16384;
pub const MAX_DOMAIN_LEN: usize = 255;

// Core modules
pub mod config;
pub mod types;
pub mod errors;
pub mod utils;

// Protocol implementation modules
pub mod asn1;
pub mod x509;
pub mod tls;
pub mod http;

// Client and network modules
pub mod client;
pub mod network;

// Re-export core types for convenience
pub use types::*;
pub use errors::*;
pub use config::*;