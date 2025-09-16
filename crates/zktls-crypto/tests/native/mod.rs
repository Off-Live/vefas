//! Native implementation tests
//!
//! This module contains comprehensive tests for all native cryptographic
//! implementations using official test vectors from NIST, RFC specifications,
//! and other authoritative sources.

mod hash_tests;
mod aead_tests;
mod ecdh_tests;
mod ecdsa_tests;
mod kdf_tests;