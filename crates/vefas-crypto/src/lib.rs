//! # VEFAS Crypto
//!
//! Cryptographic implementations and trait definitions for VEFAS (Verifiable Execution Framework for Agents).
//! This crate provides platform-agnostic traits and shared utilities that work seamlessly in both
//! std (host) and no_std (guest) environments.
//!
//! ## Design Principles
//!
//! - **Strictly no_std**: Built for constrained environments, works everywhere
//! - **Platform Agnostic**: Traits work across all zkVM platforms
//! - **Production Ready**: Battle-tested crypto implementations from RustCrypto
//! - **Performance Focused**: Optimized for zkVM precompiles when available
//! - **Security First**: Constant-time operations where possible
//!
//! ## Architecture
//!
//! ```text
//! VefasCrypto (no_std + alloc)
//! ├── Traits (platform-agnostic interfaces)
//! ├── Types (cryptographic data structures)
//! ├── Validation (shared parsing and validation)
//! ├── Input Parsing (safe bounds-checked parsing)
//! └── Constants (cryptographic parameters)
//! ```
//!
//! ## Usage
//!
//! This crate is designed to be imported by both host (std) and guest (no_std) environments:
//! - Host applications can use all functionality seamlessly
//! - Guest programs in SP1/RISC0 zkVMs can use the same interfaces
//! - Shared validation and parsing logic ensures consistency

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![warn(missing_debug_implementations)]

extern crate alloc;

// Note: alloc types are available through submodules as needed
use vefas_types::{
    tls::{CipherSuite, SessionKeys},
    VefasResult,
};

pub mod constants;
pub mod error;
pub mod http_utils;
pub mod input_validation;
pub mod tls_parser;
pub mod traits;
pub mod types;
pub mod validation;

// Re-export new trait structure for convenience
pub use constants::*;
pub use error::{CryptoError, CryptoResult};
pub use traits::{
    Aead, Hash, Kdf, KeyExchange, PrecompileDetection, PrecompileSummary, Signature, VefasCrypto,
};
pub use types::{
    AeadKey, AeadNonce, CertificateChain, EcdsaSignature, HashOutput, HkdfInfo, HkdfSalt,
    PrivateKey, PublicKey,
};

// Re-export utility modules for convenience
pub use http_utils::{hex_lower, parse_http_data, HttpData};
pub use input_validation::{validate_handshake_header, validate_tls_record_header, SafeParser};
pub use tls_parser::{
    compute_transcript_hash, decrypt_application_record, hkdf_expand_label, parse_handshake_header,
    parse_server_cipher_suite, parse_server_hello_key_share,
};
pub use validation::{
    domain_matches, validate_certificate_chain_structure, validate_certificate_message,
    validate_x509_certificate, verify_certificate_chain_signatures, verify_certificate_signature,
};

/// Verify TLS 1.3 session keys derivation
pub fn verify_session_keys(
    provider: &impl VefasCrypto,
    handshake_transcript: &[u8],
    shared_secret: &[u8],
    cipher_suite: CipherSuite,
) -> VefasResult<SessionKeys> {
    // Minimal support for TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384
    match cipher_suite {
        CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 => {}
        _ => {
            return Err(vefas_types::VefasError::crypto_error(
                vefas_types::errors::CryptoErrorType::UnsupportedAlgorithm,
                "Unsupported cipher suite in verify_session_keys",
            ));
        }
    }

    let key_len: usize = match cipher_suite {
        CipherSuite::Aes128GcmSha256 => 16,
        CipherSuite::Aes256GcmSha384 => 32,
        _ => 16,
    }; // AES-128/256
    let iv_len: usize = 12; // 96-bit IV
    let handshake_hash_vec = match cipher_suite {
        CipherSuite::Aes128GcmSha256 => provider.sha256(handshake_transcript).to_vec(),
        CipherSuite::Aes256GcmSha384 => provider.sha384(handshake_transcript).to_vec(),
        _ => provider.sha256(handshake_transcript).to_vec(),
    };

    let early_secret = provider.hkdf_extract(&[], &[]);
    let empty_hash_vec = match cipher_suite {
        CipherSuite::Aes128GcmSha256 => provider.sha256(&[]).to_vec(),
        CipherSuite::Aes256GcmSha384 => provider.sha384(&[]).to_vec(),
        _ => provider.sha256(&[]).to_vec(),
    };
    let hash_len: u8 = match cipher_suite {
        CipherSuite::Aes128GcmSha256 => 32,
        CipherSuite::Aes256GcmSha384 => 48,
        _ => 32,
    };
    let derived =
        provider.hkdf_expand_label(&early_secret, b"derived", &empty_hash_vec, hash_len)?;
    let mut derived_arr = [0u8; 32];
    // Truncate/fit if SHA-384 path
    let take = core::cmp::min(32, derived.len());
    derived_arr[..take].copy_from_slice(&derived[..take]);

    let handshake_secret = provider.hkdf_extract(&derived_arr, shared_secret);

    let _c_hs = provider.hkdf_expand_label(
        &handshake_secret,
        b"c hs traffic",
        &handshake_hash_vec,
        hash_len,
    )?;
    let _s_hs = provider.hkdf_expand_label(
        &handshake_secret,
        b"s hs traffic",
        &handshake_hash_vec,
        hash_len,
    )?;

    let derived2 =
        provider.hkdf_expand_label(&handshake_secret, b"derived", &empty_hash_vec, hash_len)?;
    let mut derived2_arr = [0u8; 32];
    let take2 = core::cmp::min(32, derived2.len());
    derived2_arr[..take2].copy_from_slice(&derived2[..take2]);
    let master_secret = provider.hkdf_extract(&derived2_arr, &[]);

    let c_ap = provider.hkdf_expand_label(
        &master_secret,
        b"c ap traffic",
        &handshake_hash_vec,
        hash_len,
    )?;
    let s_ap = provider.hkdf_expand_label(
        &master_secret,
        b"s ap traffic",
        &handshake_hash_vec,
        hash_len,
    )?;

    let c_key = provider.hkdf_expand_label(&c_ap, b"key", &[], key_len as u8)?;
    let s_key = provider.hkdf_expand_label(&s_ap, b"key", &[], key_len as u8)?;
    let c_iv = provider.hkdf_expand_label(&c_ap, b"iv", &[], iv_len as u8)?;
    let s_iv = provider.hkdf_expand_label(&s_ap, b"iv", &[], iv_len as u8)?;

    let res_master =
        provider.hkdf_expand_label(&master_secret, b"res master", &handshake_hash_vec, hash_len)?;

    let mut out = SessionKeys::new(cipher_suite);
    out.client_application_secret = c_ap;
    out.server_application_secret = s_ap;
    out.client_application_key = c_key;
    out.server_application_key = s_key;
    out.client_application_iv = c_iv;
    out.server_application_iv = s_iv;
    out.handshake_secret = handshake_secret.to_vec();
    out.master_secret = master_secret.to_vec();
    out.resumption_master_secret = res_master;
    out.validate(cipher_suite)?;
    Ok(out)
}

/// Derive TLS 1.3 per-record AEAD nonce (RFC 8446 §5.3) by XOR'ing the static IV with the big-endian sequence number.
pub fn derive_aead_nonce(static_iv: &[u8], sequence_number: u64) -> VefasResult<[u8; 12]> {
    if static_iv.len() != 12 {
        return Err(vefas_types::VefasError::crypto_error(
            vefas_types::errors::CryptoErrorType::InvalidNonceLength,
            "TLS 1.3 IV must be 12 bytes",
        ));
    }

    // Create 12-byte nonce with seq in the last 8 bytes (big-endian), first 4 bytes zero
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&sequence_number.to_be_bytes());

    // XOR with static IV
    let mut out = [0u8; 12];
    for i in 0..12 {
        out[i] = static_iv[i] ^ nonce[i];
    }
    Ok(out)
}

// Certificate chain validation is handled by the production-grade functions in validation.rs:
// - validate_certificate_chain_structure() for structural validation
// - validate_certificate_domain_binding() for domain binding validation
// - validate_x509_certificate() for individual certificate validation
//
// Full certificate chain validation (including CA trust, OCSP, etc.) would require
// integrating a dedicated X.509 library and is marked as future work.
