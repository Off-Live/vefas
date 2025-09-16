//! Native Key Derivation Function (KDF) implementations for zkTLS
//!
//! This module provides production-grade HKDF (HMAC-based Key Derivation Function)
//! implementations following RFC 5869. These are essential for TLS 1.3 key schedule
//! operations as defined in RFC 8446 Section 7.1.
//!
//! # Supported Algorithms
//!
//! - **HKDF-SHA256**: Extract-then-Expand paradigm with SHA-256
//! - **HKDF-SHA384**: Extract-then-Expand paradigm with SHA-384  
//! - **TLS 1.3 HKDF-Expand-Label**: TLS-specific key derivation
//!
//! # Security
//!
//! All implementations follow RFC 5869 strictly and use constant-time operations
//! from well-audited HMAC implementations.

use crate::error::{CryptoResult, CryptoError};
use sha2::{Sha256, Sha384};
use hmac::{Hmac, Mac};

#[cfg(feature = "no_std")]
use alloc::{vec, vec::Vec};

// Type aliases for HMAC with different hash functions
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;

/// Generic HKDF trait for different hash functions
pub trait HkdfHash {
    /// Hash output length in bytes
    const OUTPUT_SIZE: usize;
    
    /// HKDF-Extract operation
    fn extract(salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>>;
    
    /// HKDF-Expand operation
    fn expand(prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>>;
    
    /// Complete HKDF operation (extract + expand)
    fn derive(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        let prk = Self::extract(salt, ikm)?;
        Self::expand(&prk, info, length)
    }
}

/// HKDF implementation for SHA-256
pub struct HkdfSha256;

impl HkdfHash for HkdfSha256 {
    const OUTPUT_SIZE: usize = 32;
    
    fn extract(salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
        hkdf_extract_sha256(salt, ikm)
    }
    
    fn expand(prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        hkdf_expand_sha256(prk, info, length)
    }
}

/// HKDF implementation for SHA-384
pub struct HkdfSha384;

impl HkdfHash for HkdfSha384 {
    const OUTPUT_SIZE: usize = 48;
    
    fn extract(salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
        hkdf_extract_sha384(salt, ikm)
    }
    
    fn expand(prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        hkdf_expand_sha384(prk, info, length)
    }
}

/// HKDF-Extract using SHA-256
/// 
/// Extracts a pseudorandom key (PRK) from input keying material (IKM) using an optional salt.
/// This is the first phase of HKDF as defined in RFC 5869 Section 2.2.
/// 
/// # Arguments
/// * `salt` - Optional salt value (use empty slice if no salt)
/// * `ikm` - Input keying material
/// 
/// # Returns
/// 32-byte pseudorandom key (PRK)
pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
    // RFC 5869 Section 2.2: HKDF-Extract(salt, IKM) -> PRK
    // PRK = HMAC(salt, IKM)
    // If salt is not provided, it is set to a string of HashLen zeros
    
    let actual_salt = if salt.is_empty() {
        vec![0u8; 32] // SHA-256 produces 32-byte output
    } else {
        salt.to_vec()
    };
    
    let mut mac = HmacSha256::new_from_slice(&actual_salt)
        .map_err(|_| CryptoError::InvalidKeySize(actual_salt.len()))?;
    
    mac.update(ikm);
    let result = mac.finalize();
    
    Ok(result.into_bytes().to_vec())
}

/// HKDF-Expand using SHA-256
/// 
/// Expands a pseudorandom key (PRK) into output keying material (OKM) of specified length.
/// This is the second phase of HKDF as defined in RFC 5869 Section 2.3.
/// 
/// # Arguments
/// * `prk` - Pseudorandom key from HKDF-Extract (must be 32 bytes for SHA-256)
/// * `info` - Optional context and application specific information
/// * `length` - Length of output keying material (max 255 * 32 = 8160 bytes for SHA-256)
/// 
/// # Returns
/// Output keying material of requested length
pub fn hkdf_expand_sha256(prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    const HASH_LEN: usize = 32; // SHA-256 output length
    
    // Validate length according to RFC 5869: L <= 255 * HashLen
    let max_length = 255 * HASH_LEN;
    if length > max_length {
        return Err(CryptoError::invalid_hkdf_output_length(length, max_length));
    }
    
    // Handle zero length case
    if length == 0 {
        return Ok(Vec::new());
    }
    
    // Validate PRK length (should be HashLen)
    if prk.len() < HASH_LEN {
        return Err(CryptoError::invalid_hkdf_prk(HASH_LEN, prk.len()));
    }
    
    // RFC 5869 Section 2.3: HKDF-Expand(PRK, info, L) -> OKM
    // N = ceil(L / HashLen)
    // T = T(1) | T(2) | T(3) | ... | T(N)
    // OKM = first L octets of T
    
    let n = (length + HASH_LEN - 1) / HASH_LEN; // Ceiling division
    let mut t = Vec::new();
    let mut t_prev = Vec::new();
    
    for counter in 1..=n {
        let mut mac = HmacSha256::new_from_slice(prk)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        
        // T(i) = HMAC(PRK, T(i-1) | info | i)
        mac.update(&t_prev);
        mac.update(info);
        mac.update(&[counter as u8]);
        
        let t_i = mac.finalize().into_bytes();
        t.extend_from_slice(&t_i);
        t_prev = t_i.to_vec();
    }
    
    // Return first L octets of T
    t.truncate(length);
    Ok(t)
}

/// Complete HKDF using SHA-256
/// 
/// Combines HKDF-Extract and HKDF-Expand into a single operation.
/// 
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt value
/// * `info` - Optional context information
/// * `length` - Length of output keying material
/// 
/// # Returns
/// Output keying material of requested length
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    let prk = hkdf_extract_sha256(salt, ikm)?;
    hkdf_expand_sha256(&prk, info, length)
}

/// HKDF-Extract using SHA-384
pub fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
    // RFC 5869 Section 2.2: HKDF-Extract(salt, IKM) -> PRK
    let actual_salt = if salt.is_empty() {
        vec![0u8; 48] // SHA-384 produces 48-byte output
    } else {
        salt.to_vec()
    };
    
    let mut mac = HmacSha384::new_from_slice(&actual_salt)
        .map_err(|_| CryptoError::InvalidKeySize(actual_salt.len()))?;
    
    mac.update(ikm);
    let result = mac.finalize();
    
    Ok(result.into_bytes().to_vec())
}

/// HKDF-Expand using SHA-384
pub fn hkdf_expand_sha384(prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    const HASH_LEN: usize = 48; // SHA-384 output length
    
    // Validate length according to RFC 5869: L <= 255 * HashLen
    let max_length = 255 * HASH_LEN;
    if length > max_length {
        return Err(CryptoError::invalid_hkdf_output_length(length, max_length));
    }
    
    if length == 0 {
        return Ok(Vec::new());
    }
    
    // Validate PRK length
    if prk.len() < HASH_LEN {
        return Err(CryptoError::invalid_hkdf_prk(HASH_LEN, prk.len()));
    }
    
    let n = (length + HASH_LEN - 1) / HASH_LEN;
    let mut t = Vec::new();
    let mut t_prev = Vec::new();
    
    for counter in 1..=n {
        let mut mac = HmacSha384::new_from_slice(prk)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        
        mac.update(&t_prev);
        mac.update(info);
        mac.update(&[counter as u8]);
        
        let t_i = mac.finalize().into_bytes();
        t.extend_from_slice(&t_i);
        t_prev = t_i.to_vec();
    }
    
    t.truncate(length);
    Ok(t)
}

/// Complete HKDF using SHA-384
pub fn hkdf_sha384(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    let prk = hkdf_extract_sha384(salt, ikm)?;
    hkdf_expand_sha384(&prk, info, length)
}

/// TLS 1.3 HKDF-Expand-Label using SHA-256
/// 
/// Implements the HKDF-Expand-Label function as defined in RFC 8446 Section 7.1.
/// This is a TLS 1.3 specific variant of HKDF-Expand that includes structured
/// context information.
/// 
/// # Arguments
/// * `secret` - Input secret (PRK from HKDF-Extract)
/// * `label` - ASCII string label (will be prefixed with "tls13 ")
/// * `context` - Context value (typically a hash)
/// * `length` - Length of output key material
/// 
/// # Returns
/// Derived key material for TLS 1.3 use
pub fn hkdf_expand_label_sha256(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    // Construct HkdfLabel as per RFC 8446:
    // struct {
    //     uint16 length;
    //     opaque label<7..255>; 
    //     opaque context<0..255>;
    // } HkdfLabel;
    
    let mut hkdf_label = Vec::new();
    
    // Length (2 bytes, big-endian)
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    
    // Label with "tls13 " prefix
    let prefixed_label = [b"tls13 ", label].concat();
    if prefixed_label.len() > 255 || prefixed_label.len() < 7 {
        return Err(CryptoError::InvalidKeySize(prefixed_label.len()));
    }
    hkdf_label.push(prefixed_label.len() as u8);
    hkdf_label.extend_from_slice(&prefixed_label);
    
    // Context
    if context.len() > 255 {
        return Err(CryptoError::InvalidKeySize(context.len()));
    }
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);
    
    // Use HKDF-Expand with the constructed label
    hkdf_expand_sha256(secret, &hkdf_label, length)
}

/// TLS 1.3 key schedule helper functions
pub mod tls13 {
    use super::*;
    
    /// Derive early secret from PSK using HKDF-Extract with empty salt
    /// 
    /// # Arguments
    /// * `psk` - Pre-shared key (empty for 0-RTT or external PSK)
    /// 
    /// # Returns
    /// Early secret (32 bytes for SHA-256)
    pub fn derive_early_secret_sha256(psk: &[u8]) -> CryptoResult<Vec<u8>> {
        // RFC 8446: Early Secret = HKDF-Extract(0, PSK or 0)
        let salt = vec![0u8; 32]; // Zero salt for SHA-256
        hkdf_extract_sha256(&salt, psk)
    }
    
    /// Derive handshake secret from shared secret using HKDF-Extract
    /// 
    /// # Arguments
    /// * `shared_secret` - ECDHE shared secret
    /// * `derived_secret` - Derived secret from early secret
    /// 
    /// # Returns  
    /// Handshake secret (32 bytes for SHA-256)
    pub fn derive_handshake_secret_sha256(shared_secret: &[u8], derived_secret: &[u8]) -> CryptoResult<Vec<u8>> {
        // RFC 8446: Handshake Secret = HKDF-Extract(Derive-Secret(...), (EC)DHE)
        hkdf_extract_sha256(derived_secret, shared_secret)
    }
    
    /// Derive master secret using HKDF-Extract with zero IKM
    /// 
    /// # Arguments
    /// * `derived_secret` - Derived secret from handshake secret
    /// 
    /// # Returns
    /// Master secret (32 bytes for SHA-256)
    pub fn derive_master_secret_sha256(derived_secret: &[u8]) -> CryptoResult<Vec<u8>> {
        // RFC 8446: Master Secret = HKDF-Extract(Derive-Secret(...), 0)
        let ikm = vec![0u8; 32]; // Zero IKM for SHA-256
        hkdf_extract_sha256(derived_secret, &ikm)
    }
    
    /// Convenience function to derive a TLS 1.3 secret using HKDF-Expand-Label
    /// 
    /// # Arguments
    /// * `secret` - Input secret
    /// * `label` - Label without "tls13 " prefix (will be added automatically)
    /// * `context` - Context (usually transcript hash)
    /// * `length` - Output length
    /// 
    /// # Returns
    /// Derived secret
    pub fn derive_secret_sha256(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        hkdf_expand_label_sha256(secret, label, context, length)
    }
    
    /// Derive client/server handshake traffic keys
    /// 
    /// # Arguments
    /// * `handshake_secret` - Handshake secret from key schedule
    /// * `hello_hash` - Hash of ClientHello...ServerHello messages
    /// * `is_server` - true for server keys, false for client keys
    /// 
    /// # Returns
    /// Traffic secret (32 bytes for SHA-256)
    pub fn derive_handshake_traffic_secret_sha256(
        handshake_secret: &[u8], 
        hello_hash: &[u8], 
        is_server: bool
    ) -> CryptoResult<Vec<u8>> {
        let label = if is_server { b"s hs traffic" } else { b"c hs traffic" };
        derive_secret_sha256(handshake_secret, label, hello_hash, 32)
    }
    
    /// Derive client/server application traffic keys
    /// 
    /// # Arguments
    /// * `master_secret` - Master secret from key schedule
    /// * `finished_hash` - Hash of all handshake messages
    /// * `is_server` - true for server keys, false for client keys
    /// 
    /// # Returns
    /// Application traffic secret (32 bytes for SHA-256)
    pub fn derive_application_traffic_secret_sha256(
        master_secret: &[u8], 
        finished_hash: &[u8], 
        is_server: bool
    ) -> CryptoResult<Vec<u8>> {
        let label = if is_server { b"s ap traffic" } else { b"c ap traffic" };
        derive_secret_sha256(master_secret, label, finished_hash, 32)
    }
    
    /// Derive traffic keys (encryption key and IV) from traffic secret
    /// 
    /// # Arguments
    /// * `traffic_secret` - Client or server traffic secret
    /// * `key_length` - Key length (16 for AES-128, 32 for AES-256)
    /// * `iv_length` - IV length (typically 12 for GCM)
    /// 
    /// # Returns
    /// Tuple of (key, iv)
    pub fn derive_traffic_keys_sha256(
        traffic_secret: &[u8], 
        key_length: usize, 
        iv_length: usize
    ) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let key = derive_secret_sha256(traffic_secret, b"key", &[], key_length)?;
        let iv = derive_secret_sha256(traffic_secret, b"iv", &[], iv_length)?;
        Ok((key, iv))
    }
}