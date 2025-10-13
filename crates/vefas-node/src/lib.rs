//! # VEFAS Node - Unified HTTP Execution and Proof Verification Service
//!
//! This crate provides a unified VEFAS node that combines HTTP request execution
//! and proof verification capabilities in a single service.
//!
//! ## Architecture Overview
//!
//! The VEFAS Node provides two main endpoints:
//!
//! 1. **POST /requests** - Execute HTTP requests and generate ZK proofs
//! 2. **POST /verify** - Verify ZK proofs with selective disclosure
//!
//! ## Key Components
//!
//! - **Request Handler**: Executes HTTP requests and generates ZK proofs
//! - **Verification Handler**: Verifies ZK proofs with selective disclosure
//! - **ZK Proof Validator**: Validates RISC0 and SP1 proofs
//! - **Certificate Validator**: Validates certificate chains
//! - **Attestation System**: Generates and verifies attestations
//!
//! ## Usage
//!
//! ```rust
//! use vefas_node::{VefasNode, VefasNodeConfig};
//!
//! let config = VefasNodeConfig::default();
//! let node = VefasNode::new(config).await?;
//! node.start().await?;
//! ```

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(clippy::all)]

pub mod error;
pub mod handlers;
pub mod types;
pub mod zktls;

// Re-export main types
pub use error::{VefasNodeError, VefasNodeResult};
pub use handlers::*;
pub use types::*;
pub use zktls::*;

/// VEFAS Node version
pub const VEFAS_NODE_VERSION: &str = env!("CARGO_PKG_VERSION");
