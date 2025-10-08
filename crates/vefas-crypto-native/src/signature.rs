//! Digital signature implementations
//!
//! This module provides production-grade implementations of digital signature algorithms
//! including P-256 ECDSA, secp256k1 ECDSA, Ed25519, and RSA signatures.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use ecdsa::signature::{SignatureEncoding, Verifier};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};

use k256::ecdsa::{
    Signature as K256Signature, SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey,
};
use k256::{PublicKey as K256PublicKey, SecretKey as K256SecretKey};

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};

use rsa::pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey,
};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::RandomizedSigner;
use rsa::{RsaPrivateKey, RsaPublicKey};

use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use vefas_types::{errors::CryptoErrorType, VefasError, VefasResult};

/// Generate P-256 ECDSA key pair
///
/// # Returns
/// (private_key, public_key) tuple where:
/// - private_key: 32-byte scalar
/// - public_key: 65-byte uncompressed point (0x04 || x || y)
///
/// # Errors
/// Returns error if key generation fails
pub fn p256_generate_keypair() -> VefasResult<([u8; 32], [u8; 65])> {
    let secret_key = P256SecretKey::random(&mut OsRng);
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

/// Sign message with P-256 ECDSA
///
/// # Arguments
/// * `private_key` - 32-byte private scalar
/// * `message` - Message to sign (typically a hash)
///
/// # Returns
/// DER-encoded ECDSA signature
///
/// # Errors
/// Returns error if signing fails or private key is invalid
pub fn p256_sign(private_key: &[u8; 32], message: &[u8]) -> VefasResult<Vec<u8>> {
    let secret_key = P256SecretKey::from_slice(private_key).map_err(|_| {
        VefasError::crypto_error(
            CryptoErrorType::InvalidKeyLength,
            "invalid P-256 private key",
        )
    })?;

    let signing_key = P256SigningKey::from(secret_key);
    let signature: P256Signature = signing_key.sign(message);

    Ok(signature.to_der().to_bytes().to_vec())
}

/// Verify P-256 ECDSA signature
///
/// # Arguments
/// * `public_key` - 65-byte uncompressed public key (0x04 || x || y)
/// * `message` - Message that was signed
/// * `signature` - DER-encoded signature
///
/// # Returns
/// `true` if signature is valid, `false` otherwise
pub fn p256_verify(public_key: &[u8; 65], message: &[u8], signature: &[u8]) -> bool {
    // Validate public key format
    if public_key[0] != 0x04 {
        return false;
    }

    // Parse public key
    let encoded_point = match p256::EncodedPoint::from_bytes(public_key) {
        Ok(point) => point,
        Err(_) => return false,
    };

    let public_key = match P256PublicKey::from_encoded_point(&encoded_point).into_option() {
        Some(key) => key,
        None => return false,
    };

    let verifying_key = P256VerifyingKey::from(public_key);

    // Parse signature
    let signature = match P256Signature::from_der(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Verify signature
    verifying_key.verify(message, &signature).is_ok()
}

/// Generate secp256k1 ECDSA key pair
///
/// # Returns
/// (private_key, public_key) tuple
///
/// # Errors
/// Returns error if key generation fails
pub fn secp256k1_generate_keypair() -> VefasResult<([u8; 32], [u8; 65])> {
    let secret_key = K256SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();

    let private_bytes = secret_key.to_bytes();
    let public_encoded = public_key.to_encoded_point(false); // Uncompressed
    let public_bytes = public_encoded.as_bytes();

    if public_bytes.len() != 65 {
        return Err(VefasError::crypto_error(
            CryptoErrorType::InvalidEcPoint,
            "invalid secp256k1 public key length",
        ));
    }

    let mut private_array = [0u8; 32];
    let mut public_array = [0u8; 65];

    private_array.copy_from_slice(&private_bytes);
    public_array.copy_from_slice(public_bytes);

    Ok((private_array, public_array))
}

/// Sign message with secp256k1 ECDSA
///
/// # Arguments
/// * `private_key` - 32-byte private scalar
/// * `message` - Message to sign
///
/// # Returns
/// DER-encoded ECDSA signature
///
/// # Errors
/// Returns error if signing fails or private key is invalid
pub fn secp256k1_sign(private_key: &[u8; 32], message: &[u8]) -> VefasResult<Vec<u8>> {
    let secret_key = K256SecretKey::from_slice(private_key).map_err(|_| {
        VefasError::crypto_error(
            CryptoErrorType::InvalidKeyLength,
            "invalid secp256k1 private key",
        )
    })?;

    let signing_key = K256SigningKey::from(secret_key);
    let signature: K256Signature = signing_key.sign(message);

    Ok(signature.to_der().to_bytes().to_vec())
}

/// Verify secp256k1 ECDSA signature
///
/// # Arguments
/// * `public_key` - 65-byte uncompressed public key
/// * `message` - Message that was signed
/// * `signature` - DER-encoded signature
///
/// # Returns
/// `true` if signature is valid, `false` otherwise
pub fn secp256k1_verify(public_key: &[u8; 65], message: &[u8], signature: &[u8]) -> bool {
    // Validate public key format
    if public_key[0] != 0x04 {
        return false;
    }

    // Parse public key
    let encoded_point = match k256::EncodedPoint::from_bytes(public_key) {
        Ok(point) => point,
        Err(_) => return false,
    };

    let public_key = match K256PublicKey::from_encoded_point(&encoded_point).into_option() {
        Some(key) => key,
        None => return false,
    };

    let verifying_key = K256VerifyingKey::from(public_key);

    // Parse signature
    let signature = match K256Signature::from_der(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Verify signature
    verifying_key.verify(message, &signature).is_ok()
}

/// Generate Ed25519 key pair
///
/// # Returns
/// (private_key, public_key) tuple where:
/// - private_key: 32-byte seed
/// - public_key: 32-byte compressed point
pub fn ed25519_generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let signing_key = Ed25519SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    (signing_key.to_bytes(), verifying_key.to_bytes())
}

/// Sign message with Ed25519
///
/// # Arguments
/// * `private_key` - 32-byte private key seed
/// * `message` - Message to sign
///
/// # Returns
/// 64-byte signature
pub fn ed25519_sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let signing_key = Ed25519SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(message);
    signature.to_bytes()
}

/// Verify Ed25519 signature
///
/// # Arguments
/// * `public_key` - 32-byte public key
/// * `message` - Message that was signed
/// * `signature` - 64-byte signature
///
/// # Returns
/// `true` if signature is valid, `false` otherwise
pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let verifying_key = match Ed25519VerifyingKey::from_bytes(public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let signature = Ed25519Signature::from_bytes(signature);

    verifying_key.verify(message, &signature).is_ok()
}

/// Generate RSA key pair (2048-bit)
///
/// # Returns
/// (private_key_der, public_key_der) tuple with DER-encoded keys
///
/// # Errors
/// Returns error if key generation fails
pub fn rsa_2048_generate_keypair() -> VefasResult<(Vec<u8>, Vec<u8>)> {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).map_err(|_| {
        VefasError::crypto_error(
            CryptoErrorType::KeyDerivationFailed,
            "RSA key generation failed",
        )
    })?;

    let public_key = RsaPublicKey::from(&private_key);

    let private_der = private_key.to_pkcs1_der().map_err(|_| {
        VefasError::crypto_error(
            CryptoErrorType::KeyDerivationFailed,
            "RSA private key DER encoding failed",
        )
    })?;

    let public_der = public_key.to_pkcs1_der().map_err(|_| {
        VefasError::crypto_error(
            CryptoErrorType::KeyDerivationFailed,
            "RSA public key DER encoding failed",
        )
    })?;

    Ok((
        private_der.as_bytes().to_vec(),
        public_der.as_bytes().to_vec(),
    ))
}

/// Sign message with RSA PKCS#1 v1.5 SHA-256
///
/// # Arguments
/// * `private_key_der` - DER-encoded RSA private key
/// * `message` - Message to sign
///
/// # Returns
/// RSA signature
///
/// # Errors
/// Returns error if signing fails or private key is invalid
pub fn rsa_pkcs1_sha256_sign(private_key_der: &[u8], message: &[u8]) -> VefasResult<Vec<u8>> {
    let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der).map_err(|_| {
        VefasError::crypto_error(
            CryptoErrorType::KeyDerivationFailed,
            "invalid RSA private key DER",
        )
    })?;

    // Use the RSA crate's SigningKey with SHA-256
    let signing_key = SigningKey::<Sha256>::new(private_key);

    let signature = signing_key.sign_with_rng(&mut OsRng, message);
    Ok(signature.to_vec())
}

/// Verify RSA PKCS#1 v1.5 SHA-256 signature
///
/// # Arguments
/// * `public_key_der` - DER-encoded RSA public key
/// * `message` - Message that was signed
/// * `signature` - RSA signature
///
/// # Returns
/// `true` if signature is valid, `false` otherwise
pub fn rsa_pkcs1_sha256_verify(public_key_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let public_key = match RsaPublicKey::from_pkcs1_der(public_key_der) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Use the RSA crate's VerifyingKey with SHA-256
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    match rsa::pkcs1v15::Signature::try_from(signature) {
        Ok(sig) => verifying_key.verify(message, &sig).is_ok(),
        Err(_) => false,
    }
}

/// Sign message with RSA PSS SHA-256
///
/// # Arguments
/// * `private_key_der` - DER-encoded RSA private key
/// * `message` - Message to sign
///
/// # Returns
/// RSA signature
///
/// # Errors
/// Returns error if signing fails or private key is invalid
pub fn rsa_pss_sha256_sign(private_key_der: &[u8], message: &[u8]) -> VefasResult<Vec<u8>> {
    let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der).map_err(|_| {
        VefasError::crypto_error(
            CryptoErrorType::KeyDerivationFailed,
            "invalid RSA private key DER",
        )
    })?;

    let signing_key = rsa::pss::SigningKey::<Sha256>::new(private_key);

    let signature = signing_key.sign_with_rng(&mut OsRng, message);
    Ok(signature.to_vec())
}

/// Verify RSA PSS SHA-256 signature
///
/// # Arguments
/// * `public_key_der` - DER-encoded RSA public key
/// * `message` - Message that was signed
/// * `signature` - RSA signature
///
/// # Returns
/// `true` if signature is valid, `false` otherwise
pub fn rsa_pss_sha256_verify(public_key_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let public_key = match RsaPublicKey::from_pkcs1_der(public_key_der) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let verifying_key = rsa::pss::VerifyingKey::<Sha256>::new(public_key);

    match rsa::pss::Signature::try_from(signature) {
        Ok(sig) => verifying_key.verify(message, &sig).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_generate_sign_verify() {
        let (private, public) = p256_generate_keypair().unwrap();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04);

        let message = b"test message";
        let signature = p256_sign(&private, message).unwrap();

        assert!(p256_verify(&public, message, &signature));
        assert!(!p256_verify(&public, b"different message", &signature));
    }

    #[test]
    fn test_secp256k1_generate_sign_verify() {
        let (private, public) = secp256k1_generate_keypair().unwrap();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04);

        let message = b"test message";
        let signature = secp256k1_sign(&private, message).unwrap();

        assert!(secp256k1_verify(&public, message, &signature));
        assert!(!secp256k1_verify(&public, b"different message", &signature));
    }

    #[test]
    fn test_ed25519_generate_sign_verify() {
        let (private, public) = ed25519_generate_keypair();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);

        let message = b"test message";
        let signature = ed25519_sign(&private, message);
        assert_eq!(signature.len(), 64);

        assert!(ed25519_verify(&public, message, &signature));
        assert!(!ed25519_verify(&public, b"different message", &signature));
    }

    #[test]
    fn test_rsa_generate_sign_verify_pkcs1() {
        let (private_der, public_der) = rsa_2048_generate_keypair().unwrap();

        let message = b"test message";
        let signature = rsa_pkcs1_sha256_sign(&private_der, message).unwrap();

        assert!(rsa_pkcs1_sha256_verify(&public_der, message, &signature));
        assert!(!rsa_pkcs1_sha256_verify(
            &public_der,
            b"different message",
            &signature
        ));
    }

    #[test]
    fn test_rsa_generate_sign_verify_pss() {
        let (private_der, public_der) = rsa_2048_generate_keypair().unwrap();

        let message = b"test message";
        let signature = rsa_pss_sha256_sign(&private_der, message).unwrap();

        assert!(rsa_pss_sha256_verify(&public_der, message, &signature));
        assert!(!rsa_pss_sha256_verify(
            &public_der,
            b"different message",
            &signature
        ));
    }

    #[test]
    fn test_ed25519_rfc8032_test_vector() {
        // RFC 8032 Test Vector
        let private_key = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let message = b"";
        let expected_signature = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let signature = ed25519_sign(&private_key, message);
        assert_eq!(signature, expected_signature);

        // Derive public key for verification
        let signing_key = Ed25519SigningKey::from_bytes(&private_key);
        let public_key = signing_key.verifying_key().to_bytes();

        assert!(ed25519_verify(&public_key, message, &signature));
    }

    #[test]
    fn test_signature_sizes() {
        let (p256_private, _) = p256_generate_keypair().unwrap();
        let (secp256k1_private, _) = secp256k1_generate_keypair().unwrap();
        let (ed25519_private, _) = ed25519_generate_keypair();

        let message = b"test message";

        let p256_sig = p256_sign(&p256_private, message).unwrap();
        let secp256k1_sig = secp256k1_sign(&secp256k1_private, message).unwrap();
        let ed25519_sig = ed25519_sign(&ed25519_private, message);

        // DER signatures have variable length
        assert!(p256_sig.len() >= 64 && p256_sig.len() <= 72);
        assert!(secp256k1_sig.len() >= 64 && secp256k1_sig.len() <= 72);

        // Ed25519 signatures are fixed length
        assert_eq!(ed25519_sig.len(), 64);
    }

    #[test]
    fn test_deterministic_ed25519() {
        let private = [1u8; 32];
        let message = b"deterministic test";

        let sig1 = ed25519_sign(&private, message);
        let sig2 = ed25519_sign(&private, message);

        // Ed25519 signatures should be deterministic
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_invalid_signature_verification() {
        let (_, public) = p256_generate_keypair().unwrap();

        // Invalid signature should fail verification
        let invalid_sig = vec![0u8; 64];
        assert!(!p256_verify(&public, b"message", &invalid_sig));

        // Malformed DER should fail
        let malformed_der = vec![0x30, 0x06, 0x02, 0x01, 0x01]; // Truncated
        assert!(!p256_verify(&public, b"message", &malformed_der));
    }
}
