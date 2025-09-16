//! zktls-crypto: Platform-agnostic cryptographic foundation
//!
//! This crate provides common traits and native implementations
//! for cryptographic operations used in TLS 1.3.
//!
//! # Design Principles
//!
//! 1. **Platform Agnostic**: Works in both std and no_std environments
//! 2. **Foundation Layer**: Provides traits and native implementations only
//! 3. **TLS 1.3 Focus**: Optimized for X25519 + AES-GCM + SHA-256 + ECDSA(P-256)
//! 4. **Production Quality**: Zero unsafe code, comprehensive error handling
//! 5. **RFC 8446 Compliance**: Full TLS 1.3 cryptographic requirements

#![cfg_attr(feature = "no_std", no_std)]

#[cfg(feature = "no_std")]
extern crate alloc;

pub mod hash;
pub mod traits;
pub mod error;
pub mod native;

pub const TLS13_LABEL: &str = "tls13";

// Re-export commonly used types
pub use traits::*;
pub use error::*;