//! Core types and data structures for zkTLS operations
//! 
//! This module contains all the fundamental types used across zkTLS implementations,
//! organized by domain for better maintainability and clarity.

// Sub-modules
pub mod tls_types;
pub mod crypto_types;
pub mod http_types;

// Re-export all types for backward compatibility
pub use tls_types::*;
pub use crypto_types::*;
pub use http_types::*;
