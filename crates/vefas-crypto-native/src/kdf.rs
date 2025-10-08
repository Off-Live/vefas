//! Key Derivation Function (KDF) implementations
//!
//! This module provides production-grade implementations of key derivation functions
//! including HKDF (RFC 5869) and TLS 1.3 key derivation (RFC 8446).

#[cfg(not(feature = "std"))]
use std::{vec, vec::Vec};

use hkdf::Hkdf;
use sha2::{Sha256, Sha384};
use vefas_types::{errors::CryptoErrorType, VefasError, VefasResult};

/// HKDF-Extract: extract a pseudorandom key from input keying material
///
/// # Arguments
/// * `salt` - Optional salt value (empty slice for no salt)
/// * `ikm` - Input keying material
///
/// # Returns
/// 32-byte pseudorandom key (PRK)
///
/// # Example
/// ```rust
/// use vefas_crypto_native::kdf::hkdf_extract;
///
/// let prk = hkdf_extract(b"salt", b"input key material");
/// assert_eq!(prk.len(), 32);
/// ```
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _hkdf) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// HKDF-Expand: expand a pseudorandom key to desired length
///
/// # Arguments
/// * `prk` - 32-byte pseudorandom key from HKDF-Extract
/// * `info` - Context and application specific information
/// * `length` - Desired output length in bytes (max 8160 for SHA-256)
///
/// # Returns
/// Output keying material of requested length
///
/// # Errors
/// Returns error if length is too large (> 255 * HashLen)
///
/// # Example
/// ```rust
/// use vefas_crypto_native::kdf::{hkdf_extract, hkdf_expand};
///
/// let prk = hkdf_extract(b"salt", b"ikm");
/// let okm = hkdf_expand(&prk, b"info", 42).unwrap();
/// assert_eq!(okm.len(), 42);
/// ```
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> VefasResult<Vec<u8>> {
    if length > 255 * 32 {
        return Err(VefasError::crypto_error(
            CryptoErrorType::InvalidKeyLength,
            "HKDF expand length too large",
        ));
    }

    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| {
        VefasError::crypto_error(CryptoErrorType::InvalidKeyLength, "invalid HKDF PRK")
    })?;

    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|_| VefasError::crypto_error(CryptoErrorType::HkdfFailed, "HKDF expand failed"))?;

    Ok(okm)
}

/// HKDF-Extract for SHA-384: extract a pseudorandom key from input keying material
///
/// # Arguments
/// * `salt` - Optional salt value (empty slice for no salt)
/// * `ikm` - Input keying material
///
/// # Returns
/// 48-byte pseudorandom key (PRK)
pub fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    let (prk, _hkdf) = Hkdf::<Sha384>::extract(Some(salt), ikm);
    prk.into()
}

/// HKDF-Expand for SHA-384: expand a pseudorandom key to desired length
///
/// # Arguments
/// * `prk` - 48-byte pseudorandom key from HKDF-Extract-SHA384
/// * `info` - Context and application specific information
/// * `length` - Desired output length in bytes (max 12240 for SHA-384)
///
/// # Returns
/// Output keying material of requested length
///
/// # Errors
/// Returns error if length is too large (> 255 * HashLen)
pub fn hkdf_expand_sha384(prk: &[u8; 48], info: &[u8], length: usize) -> VefasResult<Vec<u8>> {
    if length > 255 * 48 {
        return Err(VefasError::crypto_error(
            CryptoErrorType::InvalidKeyLength,
            "HKDF-SHA384 expand length too large",
        ));
    }

    let hk = Hkdf::<Sha384>::from_prk(prk).map_err(|_| {
        VefasError::crypto_error(CryptoErrorType::InvalidKeyLength, "invalid HKDF-SHA384 PRK")
    })?;

    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|_| VefasError::crypto_error(CryptoErrorType::HkdfFailed, "HKDF-SHA384 expand failed"))?;

    Ok(okm)
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1)
///
/// # Arguments
/// * `secret` - Input secret
/// * `label` - TLS 1.3 label (without "tls13 " prefix)
/// * `context` - Hash of handshake messages
/// * `length` - Desired output length (max 255 bytes)
///
/// # Returns
/// Derived traffic secret
///
/// # Errors
/// Returns error if length is too large or derivation fails
///
/// # Example
/// ```rust
/// use vefas_crypto_native::kdf::{hkdf_extract, hkdf_expand_label};
///
/// let prk = hkdf_extract(b"salt", b"ikm");
/// let secret = hkdf_expand_label(&prk, b"c hs traffic", &[0u8; 32], 32).unwrap();
/// assert_eq!(secret.len(), 32);
/// ```
pub fn hkdf_expand_label(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: u8,
) -> VefasResult<Vec<u8>> {
    // TLS 1.3 HKDF-Expand-Label format per RFC 8446
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    hkdf_label.push(6 + label.len() as u8); // "tls13 " + label length
    hkdf_label.extend_from_slice(b"tls13 ");
    hkdf_label.extend_from_slice(label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    // Use HKDF-Expand with the constructed label
    let prk = if secret.len() == 32 {
        let mut prk_array = [0u8; 32];
        prk_array.copy_from_slice(secret);
        prk_array
    } else {
        hkdf_extract(&[], secret)
    };

    hkdf_expand(&prk, &hkdf_label, length as usize)
}

/// Derive TLS 1.3 handshake traffic secrets
///
/// # Arguments
/// * `shared_secret` - ECDH shared secret
/// * `handshake_hash` - Hash of Client Hello ... Server Hello
///
/// # Returns
/// (client_handshake_traffic_secret, server_handshake_traffic_secret)
///
/// # Errors
/// Returns error if key derivation fails
///
/// # Example
/// ```rust
/// use vefas_crypto_native::kdf::derive_handshake_secrets;
///
/// let shared_secret = [1u8; 32];
/// let handshake_hash = [2u8; 32];
/// let (client_secret, server_secret) = derive_handshake_secrets(&shared_secret, &handshake_hash).unwrap();
/// assert_eq!(client_secret.len(), 32);
/// assert_eq!(server_secret.len(), 32);
/// ```
pub fn derive_handshake_secrets(
    shared_secret: &[u8],
    handshake_hash: &[u8; 32],
) -> VefasResult<([u8; 32], [u8; 32])> {
    // Derive-Secret(., "derived", "") = HKDF-Expand-Label(., "derived", Hash(""), L)
    let early_secret = hkdf_extract(&[], &[]);
    let empty_hash = crate::hash::sha256(b"");
    let derived_secret = hkdf_expand_label(&early_secret, b"derived", &empty_hash, 32)?;

    let mut derived_array = [0u8; 32];
    derived_array.copy_from_slice(&derived_secret);

    // Handshake Secret = HKDF-Extract(Derive-Secret(Early Secret, "derived", ""), ECDHE)
    let handshake_secret = hkdf_extract(&derived_array, shared_secret);

    // Client handshake traffic secret
    let client_secret = hkdf_expand_label(&handshake_secret, b"c hs traffic", handshake_hash, 32)?;

    // Server handshake traffic secret
    let server_secret = hkdf_expand_label(&handshake_secret, b"s hs traffic", handshake_hash, 32)?;

    let mut client_array = [0u8; 32];
    let mut server_array = [0u8; 32];
    client_array.copy_from_slice(&client_secret);
    server_array.copy_from_slice(&server_secret);

    Ok((client_array, server_array))
}

/// Derive TLS 1.3 application traffic secrets
///
/// # Arguments
/// * `handshake_secret` - Handshake secret from derive_handshake_secrets
/// * `handshake_hash` - Hash of Client Hello ... Server Finished
///
/// # Returns
/// (client_application_traffic_secret, server_application_traffic_secret)
///
/// # Errors
/// Returns error if key derivation fails
///
/// # Example
/// ```rust
/// use vefas_crypto_native::kdf::{derive_handshake_secrets, derive_application_secrets};
///
/// let shared_secret = [1u8; 32];
/// let handshake_hash = [2u8; 32];
/// let (client_hs, server_hs) = derive_handshake_secrets(&shared_secret, &handshake_hash).unwrap();
/// let (client_app, server_app) = derive_application_secrets(&client_hs, &handshake_hash).unwrap();
/// assert_eq!(client_app.len(), 32);
/// assert_eq!(server_app.len(), 32);
/// ```
pub fn derive_application_secrets(
    handshake_secret: &[u8; 32],
    handshake_hash: &[u8; 32],
) -> VefasResult<([u8; 32], [u8; 32])> {
    // Derive-Secret(Handshake Secret, "derived", "")
    let empty_hash = crate::hash::sha256(b"");
    let derived_secret = hkdf_expand_label(handshake_secret, b"derived", &empty_hash, 32)?;

    let mut derived_array = [0u8; 32];
    derived_array.copy_from_slice(&derived_secret);

    // Master Secret = HKDF-Extract(Derive-Secret(Handshake Secret, "derived", ""), 0)
    let master_secret = hkdf_extract(&derived_array, &[]);

    // Client application traffic secret
    let client_secret = hkdf_expand_label(&master_secret, b"c ap traffic", handshake_hash, 32)?;

    // Server application traffic secret
    let server_secret = hkdf_expand_label(&master_secret, b"s ap traffic", handshake_hash, 32)?;

    let mut client_array = [0u8; 32];
    let mut server_array = [0u8; 32];
    client_array.copy_from_slice(&client_secret);
    server_array.copy_from_slice(&server_secret);

    Ok((client_array, server_array))
}

/// Derive TLS 1.3 traffic keys and IVs from traffic secret
///
/// # Arguments
/// * `traffic_secret` - Traffic secret (handshake or application)
/// * `cipher_suite` - TLS cipher suite (for key/IV lengths)
///
/// # Returns
/// (key, iv) tuple
///
/// # Errors
/// Returns error if key derivation fails
pub fn derive_traffic_keys(traffic_secret: &[u8; 32]) -> VefasResult<([u8; 32], [u8; 12])> {
    // Derive key: HKDF-Expand-Label(Secret, "key", "", key_length)
    let key_material = hkdf_expand_label(traffic_secret, b"key", &[], 32)?;

    // Derive IV: HKDF-Expand-Label(Secret, "iv", "", iv_length)
    let iv_material = hkdf_expand_label(traffic_secret, b"iv", &[], 12)?;

    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];

    key.copy_from_slice(&key_material);
    iv.copy_from_slice(&iv_material);

    Ok((key, iv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_extract() {
        let salt = b"salt";
        let ikm = b"input key material";
        let prk = hkdf_extract(salt, ikm);
        assert_eq!(prk.len(), 32);

        // Test with empty salt
        let prk_no_salt = hkdf_extract(&[], ikm);
        assert_eq!(prk_no_salt.len(), 32);
        assert_ne!(prk, prk_no_salt);
    }

    #[test]
    fn test_hkdf_expand() {
        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"context info";

        let prk = hkdf_extract(salt, ikm);
        let okm = hkdf_expand(&prk, info, 42).unwrap();
        assert_eq!(okm.len(), 42);

        // Different info should produce different output
        let okm2 = hkdf_expand(&prk, b"different info", 42).unwrap();
        assert_ne!(okm, okm2);
    }

    #[test]
    fn test_hkdf_expand_max_length() {
        let prk = hkdf_extract(b"salt", b"ikm");

        // Valid maximum length
        let okm = hkdf_expand(&prk, b"info", 255 * 32);
        assert!(okm.is_ok());

        // Invalid length (too large)
        let result = hkdf_expand(&prk, b"info", 255 * 32 + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_rfc5869_test_case_1() {
        // RFC 5869 Test Case 1
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let prk = hkdf_extract(&salt, &ikm);
        let expected_prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        assert_eq!(prk, expected_prk);

        let okm = hkdf_expand(&prk, &info, 42).unwrap();
        let expected_okm = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_hkdf_expand_label() {
        let secret = [1u8; 32];
        let label = b"test label";
        let context = [2u8; 32];

        let result = hkdf_expand_label(&secret, label, &context, 32).unwrap();
        assert_eq!(result.len(), 32);

        // Different label should produce different output
        let result2 = hkdf_expand_label(&secret, b"different label", &context, 32).unwrap();
        assert_ne!(result, result2);

        // Different context should produce different output
        let context2 = [3u8; 32];
        let result3 = hkdf_expand_label(&secret, label, &context2, 32).unwrap();
        assert_ne!(result, result3);
    }

    #[test]
    fn test_derive_handshake_secrets() {
        let shared_secret = [1u8; 32];
        let handshake_hash = [2u8; 32];

        let (client_secret, server_secret) =
            derive_handshake_secrets(&shared_secret, &handshake_hash).unwrap();

        assert_eq!(client_secret.len(), 32);
        assert_eq!(server_secret.len(), 32);
        assert_ne!(client_secret, server_secret);

        // Different shared secret should produce different results
        let shared_secret2 = [3u8; 32];
        let (client_secret2, server_secret2) =
            derive_handshake_secrets(&shared_secret2, &handshake_hash).unwrap();
        assert_ne!(client_secret, client_secret2);
        assert_ne!(server_secret, server_secret2);
    }

    #[test]
    fn test_derive_application_secrets() {
        let handshake_secret = [1u8; 32];
        let handshake_hash = [2u8; 32];

        let (client_secret, server_secret) =
            derive_application_secrets(&handshake_secret, &handshake_hash).unwrap();

        assert_eq!(client_secret.len(), 32);
        assert_eq!(server_secret.len(), 32);
        assert_ne!(client_secret, server_secret);

        // Different handshake secret should produce different results
        let handshake_secret2 = [3u8; 32];
        let (client_secret2, server_secret2) =
            derive_application_secrets(&handshake_secret2, &handshake_hash).unwrap();
        assert_ne!(client_secret, client_secret2);
        assert_ne!(server_secret, server_secret2);
    }

    #[test]
    fn test_derive_traffic_keys() {
        let traffic_secret = [1u8; 32];
        let (key, iv) = derive_traffic_keys(&traffic_secret).unwrap();

        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 12);

        // Different traffic secret should produce different keys
        let traffic_secret2 = [2u8; 32];
        let (key2, iv2) = derive_traffic_keys(&traffic_secret2).unwrap();
        assert_ne!(key, key2);
        assert_ne!(iv, iv2);
    }

    #[test]
    fn test_tls13_key_derivation_chain() {
        // Test the complete TLS 1.3 key derivation chain
        let shared_secret = [1u8; 32];
        let handshake_hash = [2u8; 32];

        // Derive handshake secrets
        let (client_hs_secret, server_hs_secret) =
            derive_handshake_secrets(&shared_secret, &handshake_hash).unwrap();

        // Derive application secrets
        let (client_app_secret, server_app_secret) =
            derive_application_secrets(&client_hs_secret, &handshake_hash).unwrap();

        // Derive traffic keys
        let (client_key, client_iv) = derive_traffic_keys(&client_app_secret).unwrap();
        let (server_key, server_iv) = derive_traffic_keys(&server_app_secret).unwrap();

        // All outputs should be different
        assert_ne!(client_hs_secret, server_hs_secret);
        assert_ne!(client_app_secret, server_app_secret);
        assert_ne!(client_key, server_key);
        assert_ne!(client_iv, server_iv);

        // All outputs should have correct lengths
        assert_eq!(client_key.len(), 32);
        assert_eq!(server_key.len(), 32);
        assert_eq!(client_iv.len(), 12);
        assert_eq!(server_iv.len(), 12);
    }

    #[test]
    fn test_deterministic_behavior() {
        let salt = b"deterministic salt";
        let ikm = b"deterministic ikm";
        let info = b"deterministic info";

        // Multiple calls should produce identical results
        let prk1 = hkdf_extract(salt, ikm);
        let prk2 = hkdf_extract(salt, ikm);
        assert_eq!(prk1, prk2);

        let okm1 = hkdf_expand(&prk1, info, 32).unwrap();
        let okm2 = hkdf_expand(&prk2, info, 32).unwrap();
        assert_eq!(okm1, okm2);
    }
}
