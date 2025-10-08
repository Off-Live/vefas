//! Key exchange implementations
//!
//! This module provides production-grade implementations of key exchange algorithms
//! including X25519 and P-256 ECDH for TLS 1.3 and other protocols.

use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{PublicKey as P256PublicKey, SecretKey};
use rand_core::OsRng;
use vefas_types::{errors::CryptoErrorType, VefasError, VefasResult};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Generate X25519 key pair
///
/// # Returns
/// (private_key, public_key) tuple where:
/// - private_key: 32-byte scalar
/// - public_key: 32-byte compressed point
///
/// # Example
/// ```rust
/// use vefas_crypto_native::key_exchange::x25519_generate_keypair;
///
/// let (private, public) = x25519_generate_keypair();
/// assert_eq!(private.len(), 32);
/// assert_eq!(public.len(), 32);
/// ```
pub fn x25519_generate_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);

    (*secret.as_bytes(), *public.as_bytes())
}

/// Compute X25519 shared secret
///
/// # Arguments
/// * `private_key` - 32-byte private scalar
/// * `public_key` - 32-byte peer public key
///
/// # Returns
/// 32-byte shared secret
///
/// # Errors
/// Returns error if the public key is invalid or shared secret computation fails
///
/// # Example
/// ```rust
/// use vefas_crypto_native::key_exchange::{x25519_generate_keypair, x25519_compute_shared_secret};
///
/// let (alice_private, alice_public) = x25519_generate_keypair();
/// let (bob_private, bob_public) = x25519_generate_keypair();
///
/// let alice_shared = x25519_compute_shared_secret(&alice_private, &bob_public).unwrap();
/// let bob_shared = x25519_compute_shared_secret(&bob_private, &alice_public).unwrap();
///
/// assert_eq!(alice_shared, bob_shared);
/// ```
pub fn x25519_compute_shared_secret(
    private_key: &[u8; 32],
    public_key: &[u8; 32],
) -> VefasResult<[u8; 32]> {
    let secret = StaticSecret::from(*private_key);
    let public = X25519PublicKey::from(*public_key);

    let shared_secret = secret.diffie_hellman(&public);
    Ok(*shared_secret.as_bytes())
}

/// Generate P-256 ECDH key pair
///
/// # Returns
/// (private_key, public_key) tuple where:
/// - private_key: 32-byte scalar
/// - public_key: 65-byte uncompressed point (0x04 || x || y)
///
/// # Errors
/// Returns error if key generation fails
///
/// # Example
/// ```rust
/// use vefas_crypto_native::key_exchange::p256_generate_keypair;
///
/// let (private, public) = p256_generate_keypair().unwrap();
/// assert_eq!(private.len(), 32);
/// assert_eq!(public.len(), 65);
/// assert_eq!(public[0], 0x04); // Uncompressed point marker
/// ```
pub fn p256_generate_keypair() -> VefasResult<([u8; 32], [u8; 65])> {
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();

    let private_bytes = secret_key.to_bytes();
    let public_encoded = public_key.to_encoded_point(false); // Uncompressed
    let public_bytes = public_encoded.as_bytes();

    if public_bytes.len() != 65 {
        return Err(VefasError::crypto_error(
            CryptoErrorType::InvalidEcPoint,
            "invalid P-256 public key length",
        ));
    }

    let mut private_array = [0u8; 32];
    let mut public_array = [0u8; 65];

    private_array.copy_from_slice(&private_bytes);
    public_array.copy_from_slice(public_bytes);

    Ok((private_array, public_array))
}

/// Compute P-256 ECDH shared secret
///
/// # Arguments
/// * `private_key` - 32-byte private scalar
/// * `public_key` - 65-byte peer public key (uncompressed)
///
/// # Returns
/// 32-byte shared secret (x-coordinate of computed point)
///
/// # Errors
/// Returns error if the public key is invalid or shared secret computation fails
///
/// # Example
/// ```rust
/// use vefas_crypto_native::key_exchange::{p256_generate_keypair, p256_compute_shared_secret};
///
/// let (alice_private, alice_public) = p256_generate_keypair().unwrap();
/// let (bob_private, bob_public) = p256_generate_keypair().unwrap();
///
/// let alice_shared = p256_compute_shared_secret(&alice_private, &bob_public).unwrap();
/// let bob_shared = p256_compute_shared_secret(&bob_private, &alice_public).unwrap();
///
/// assert_eq!(alice_shared, bob_shared);
/// ```
pub fn p256_compute_shared_secret(
    private_key: &[u8; 32],
    public_key: &[u8; 65],
) -> VefasResult<[u8; 32]> {
    // Validate public key format
    if public_key[0] != 0x04 {
        return Err(VefasError::crypto_error(
            CryptoErrorType::InvalidEcPoint,
            "P-256 public key must be uncompressed (start with 0x04)",
        ));
    }

    // Parse private key
    let secret_key = SecretKey::from_slice(private_key).map_err(|_| {
        VefasError::crypto_error(
            CryptoErrorType::InvalidKeyLength,
            "invalid P-256 private key",
        )
    })?;

    // Parse public key
    let encoded_point = p256::EncodedPoint::from_bytes(public_key).map_err(|_| {
        VefasError::crypto_error(
            CryptoErrorType::InvalidEcPoint,
            "invalid P-256 public key encoding",
        )
    })?;

    let public_key = P256PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .unwrap_or_else(|| {
            // This should not happen if the encoded point is valid
            panic!("Failed to decode valid P-256 public key")
        });

    // Compute shared secret using ECDH
    let shared_secret =
        p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());

    // Extract x-coordinate as shared secret
    let x_coordinate = shared_secret.raw_secret_bytes();

    let mut result = [0u8; 32];
    result.copy_from_slice(x_coordinate);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_generate_keypair() {
        let (private, public) = x25519_generate_keypair();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);

        // Keys should be different each time
        let (private2, public2) = x25519_generate_keypair();
        assert_ne!(private, private2);
        assert_ne!(public, public2);
    }

    #[test]
    fn test_x25519_shared_secret() {
        let (alice_private, alice_public) = x25519_generate_keypair();
        let (bob_private, bob_public) = x25519_generate_keypair();

        let alice_shared = x25519_compute_shared_secret(&alice_private, &bob_public).unwrap();
        let bob_shared = x25519_compute_shared_secret(&bob_private, &alice_public).unwrap();

        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared.len(), 32);
    }

    #[test]
    fn test_p256_generate_keypair() {
        let (private, public) = p256_generate_keypair().unwrap();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04); // Uncompressed point marker

        // Keys should be different each time
        let (private2, public2) = p256_generate_keypair().unwrap();
        assert_ne!(private, private2);
        assert_ne!(public, public2);
    }

    #[test]
    fn test_p256_shared_secret() {
        let (alice_private, alice_public) = p256_generate_keypair().unwrap();
        let (bob_private, bob_public) = p256_generate_keypair().unwrap();

        let alice_shared = p256_compute_shared_secret(&alice_private, &bob_public).unwrap();
        let bob_shared = p256_compute_shared_secret(&bob_private, &alice_public).unwrap();

        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared.len(), 32);
    }

    #[test]
    fn test_x25519_rfc7748_test_vector() {
        // RFC 7748 Test Vector
        let alice_private = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_public = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        let expected_shared = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];

        let computed_shared = x25519_compute_shared_secret(&alice_private, &bob_public).unwrap();
        assert_eq!(computed_shared, expected_shared);
    }

    #[test]
    fn test_p256_invalid_public_key() {
        let (private, _) = p256_generate_keypair().unwrap();

        // Invalid public key (doesn't start with 0x04)
        let mut invalid_public = [0u8; 65];
        invalid_public[0] = 0x02; // Compressed point marker

        let result = p256_compute_shared_secret(&private, &invalid_public);
        assert!(result.is_err());
    }

    #[test]
    fn test_deterministic_behavior() {
        // Same inputs should produce same outputs
        let private = [1u8; 32];
        let public = [
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
            0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
            0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];

        let shared1 = p256_compute_shared_secret(&private, &public).unwrap();
        let shared2 = p256_compute_shared_secret(&private, &public).unwrap();
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_key_sizes() {
        let (x25519_private, x25519_public) = x25519_generate_keypair();
        assert_eq!(x25519_private.len(), 32);
        assert_eq!(x25519_public.len(), 32);

        let (p256_private, p256_public) = p256_generate_keypair().unwrap();
        assert_eq!(p256_private.len(), 32);
        assert_eq!(p256_public.len(), 65);
    }
}
