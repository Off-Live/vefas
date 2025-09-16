//! VEFAS: Verifiable Execution Framework for Agents
//! 
//! A production-grade zkTLS client inside SP1 zkVM with strict TDD development.
//! 
//! This root package coordinates workspace feature flags for SP1 and RISC0 backends.
//! The actual implementation is in the workspace crates.

#![doc = include_str!("../REQUIREMENTS.md")]

// Re-export the main crates for convenience
#[cfg(feature = "sp1")]
pub use zktls_crypto as crypto;
#[cfg(feature = "sp1")]
pub use zktls_core as core;

#[cfg(feature = "risc0")]
pub use zktls_crypto as crypto;
#[cfg(feature = "risc0")]
pub use zktls_core as core;

// Default case (for compilation without features)
#[cfg(not(any(feature = "sp1", feature = "risc0")))]
pub use zktls_core as core;