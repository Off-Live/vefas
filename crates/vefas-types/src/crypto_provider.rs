//! # Crypto Provider Trait
//!
//! This module defines the CryptoProvider trait for cryptographic operations
//! in VEFAS validation systems.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::errors::VefasResult;

/// Result type for crypto operations
pub type CryptoResult<T> = VefasResult<T>;

/// Cryptographic provider trait for different crypto implementations
pub trait CryptoProvider {
    /// Verify HMAC for a Finished message
    fn verify_finished_hmac(
        &self,
        finished_msg: &[u8],
        traffic_secret: &[u8],
        transcript_hash: &[u8],
        cipher_suite: &str,
    ) -> CryptoResult<bool>;

    /// Derive traffic secrets using HKDF
    fn derive_traffic_secrets(
        &self,
        master_secret: &[u8],
        transcript_hash: &[u8],
        cipher_suite: &str,
    ) -> CryptoResult<(Vec<u8>, Vec<u8>)>; // (client_secret, server_secret)

    /// Decrypt application data
    fn decrypt_application_data(
        &self,
        encrypted_data: &[u8],
        traffic_secret: &[u8],
        sequence_number: u64,
        cipher_suite: &str,
    ) -> CryptoResult<Vec<u8>>;

    /// Compute hash of data
    fn compute_hash(&self, data: &[u8]) -> CryptoResult<Vec<u8>>;
}
