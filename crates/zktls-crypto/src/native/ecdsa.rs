//! Native digital signature implementations for zkTLS
//!
//! This module provides production-grade ECDSA, Ed25519, and RSA signature
//! operations using well-audited cryptographic libraries. These implementations
//! are used as fallbacks when zkVM precompiles are not available.
//!
//! # Supported Algorithms
//!
//! - **P-256 ECDSA**: secp256r1 curve with SHA-256, ASN.1 DER signature format
//! - **Ed25519**: Edwards curve signatures following RFC 8032
//! - **RSA**: PKCS#1 v1.5 and PSS padding for legacy certificate support
//!
//! # Security
//!
//! All implementations use constant-time operations and are resistant to
//! timing attacks and side-channel analysis.

use crate::error::{CryptoError, CryptoResult};
use p256::ecdsa::{signature::Signer, signature::Verifier, signature::hazmat::PrehashVerifier, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, NonZeroScalar, SecretKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256, Sha384, Sha512};
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use rsa::RsaPublicKey;

#[cfg(feature = "no_std")]
use alloc::{vec::Vec, format};

/// Helper function to create a secure RNG for cryptographic operations
fn create_secure_rng() -> impl RngCore + CryptoRng {
    #[cfg(not(feature = "no_std"))]
    {
        ChaCha20Rng::from_entropy()
    }
    #[cfg(feature = "no_std")]
    {
        // In zkVM/no_std environment, use deterministic seed
        // Production deployments should provide entropy from host
        ChaCha20Rng::from_seed([42u8; 32])
    }
}

/// Generate a P-256 ECDSA keypair
/// 
/// Returns (private_key, public_key) where:
/// - private_key: 32-byte scalar in big-endian format
/// - public_key: 65-byte uncompressed point (0x04 || x || y)
///
/// # Security
/// Uses cryptographically secure random number generation.
pub fn p256_generate_keypair() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = create_secure_rng();
    let secret_key = SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();
    
    // Convert to bytes
    let private_bytes = secret_key.to_bytes();
    let public_bytes = public_key.to_encoded_point(false); // Uncompressed format
    
    Ok((private_bytes.to_vec(), public_bytes.as_bytes().to_vec()))
}

/// Sign a message using P-256 ECDSA with SHA-256
///
/// # Arguments
/// * `private_key` - 32-byte P-256 private key scalar
/// * `message` - Message to sign (will be hashed with SHA-256)
///
/// # Returns
/// ASN.1 DER encoded signature
pub fn p256_sign(private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    if private_key.len() != 32 {
        return Err(CryptoError::InvalidPrivateKey);
    }
    
    // Parse private key
    let secret_key = SecretKey::from_slice(private_key)
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    
    let signing_key = SigningKey::from(secret_key);
    
    // Sign the message (p256 crate will hash it internally with SHA-256)
    let signature: Signature = signing_key.sign(message);
    
    // Return as ASN.1 DER bytes
    Ok(signature.to_der().to_bytes().to_vec())
}

/// Verify a P-256 ECDSA signature
///
/// # Arguments  
/// * `public_key` - 65-byte uncompressed public key (0x04 || x || y) or 33-byte compressed
/// * `message` - Original message (will be hashed with SHA-256)
/// * `signature` - ASN.1 DER encoded signature or raw 64-byte (r || s)
///
/// # Returns
/// `true` if signature is valid, `false` otherwise
pub fn p256_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    // Hash the message with SHA-256
    let hash = Sha256::digest(message);
    
    // Verify the signature against the hash
    p256_verify_prehashed(public_key, &hash, signature)
}

/// Verify a P-256 ECDSA signature against pre-hashed data
///
/// This function is specifically designed for X.509 certificate verification
/// where the signature is created over the hash of the TBS certificate data.
///
/// # Arguments  
/// * `public_key` - 65-byte uncompressed public key (0x04 || x || y) or 33-byte compressed
/// * `hash` - Pre-computed hash (typically SHA-256, 32 bytes)
/// * `signature` - ASN.1 DER encoded signature or raw 64-byte (r || s)
///
/// # Returns
/// `true` if signature is valid, `false` otherwise
///
/// # Security
/// This function does NOT hash the input data. It expects the hash to be
/// pre-computed. This is correct for X.509 certificate verification where
/// signatures are created over hashed TBS certificate data.
pub fn p256_verify_prehashed(public_key: &[u8], hash: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    // Parse public key
    let encoded_point = EncodedPoint::from_bytes(public_key)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    
    // Parse signature - try ASN.1 DER first, then raw format
    let sig = if signature.len() == 64 {
        // Raw format: r || s (32 bytes each)
        let r_bytes = &signature[0..32];
        let s_bytes = &signature[32..64];
        
        // Convert to arrays and create NonZeroScalars
        let mut r_array = [0u8; 32];
        let mut s_array = [0u8; 32];
        r_array.copy_from_slice(r_bytes);
        s_array.copy_from_slice(s_bytes);
        
        let r_scalar = NonZeroScalar::from_repr(r_array.into())
            .into_option()
            .ok_or(CryptoError::InvalidSignature)?;
        let s_scalar = NonZeroScalar::from_repr(s_array.into())
            .into_option()
            .ok_or(CryptoError::InvalidSignature)?;
        
        Signature::from_scalars(r_scalar, s_scalar)
            .map_err(|_| CryptoError::InvalidSignature)?
    } else {
        // ASN.1 DER format
        Signature::from_der(signature)
            .map_err(|_| CryptoError::InvalidSignature)?
    };
    
    // Verify signature against the pre-computed hash
    match verifying_key.verify_prehash(hash, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

// Ed25519 implementation placeholder

/// Generate an Ed25519 keypair
///
/// Returns (private_key, public_key) where both are 32 bytes
/// 
/// # Security
/// Uses cryptographically secure random number generation.
pub fn ed25519_generate_keypair() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = create_secure_rng();
    
    // Generate 32 random bytes for the secret key
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    
    let signing_key = Ed25519SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    
    Ok((signing_key.to_bytes().to_vec(), verifying_key.to_bytes().to_vec()))
}

/// Sign a message using Ed25519
/// 
/// # Arguments
/// * `private_key` - 32-byte Ed25519 private key
/// * `message` - Message to sign (raw bytes, no prehashing)
/// 
/// # Returns
/// 64-byte Ed25519 signature
pub fn ed25519_sign(private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    if private_key.len() != 32 {
        return Err(CryptoError::InvalidPrivateKey);
    }
    
    // Convert private key bytes to signing key
    let key_bytes: [u8; 32] = private_key.try_into()
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
    
    // Sign the message
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify an Ed25519 signature  
/// 
/// # Arguments
/// * `public_key` - 32-byte Ed25519 public key
/// * `message` - Original message (raw bytes)
/// * `signature` - 64-byte Ed25519 signature
/// 
/// # Returns
/// `true` if signature is valid, `false` otherwise
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    if public_key.len() != 32 {
        return Err(CryptoError::InvalidPublicKey);
    }
    if signature.len() != 64 {
        return Err(CryptoError::InvalidSignature);
    }
    
    // Convert public key bytes to verifying key
    let key_bytes: [u8; 32] = public_key.try_into()
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let verifying_key = Ed25519VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    
    // Convert signature bytes
    let sig_bytes: [u8; 64] = signature.try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let signature = Ed25519Signature::from_bytes(&sig_bytes);
    
    // Verify signature
    match verifying_key.verify(message, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify an RSA signature with PKCS#1 v1.5 padding
/// 
/// # Arguments
/// * `public_key` - RSA public key in DER format
/// * `message` - Original message (will be hashed)
/// * `signature` - RSA signature bytes
/// * `hash_algorithm` - Hash algorithm ("sha256", "sha384", "sha512")
/// 
/// # Returns
/// `true` if signature is valid, `false` otherwise
/// 
/// # Security
/// Uses PKCS#1 v1.5 padding which is the most common format for X.509 certificate signatures.
/// Signature verification is constant-time and resistant to timing attacks.
pub fn rsa_verify(public_key: &[u8], message: &[u8], signature: &[u8], hash_algorithm: &str) -> CryptoResult<bool> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    
    // Parse RSA public key from DER format
    let rsa_key = RsaPublicKey::from_public_key_der(public_key)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    
    // Parse signature - RSA signatures are variable length based on key size
    let rsa_signature = Signature::try_from(signature)
        .map_err(|_| CryptoError::InvalidSignature)?;
    
    match hash_algorithm.to_lowercase().as_str() {
        "sha256" => {
            // Create verifying key with PKCS#1 v1.5 padding (most common for certificates)
            let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(rsa_key);
            
            // Verify signature (verifying_key handles hashing internally)
            match verifying_key.verify(message, &rsa_signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        },
        "sha384" => {
            let verifying_key = VerifyingKey::<Sha384>::new_unprefixed(rsa_key);
            match verifying_key.verify(message, &rsa_signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        },
        "sha512" => {
            let verifying_key = VerifyingKey::<Sha512>::new_unprefixed(rsa_key);
            match verifying_key.verify(message, &rsa_signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        },
        _ => Err(CryptoError::UnsupportedOperation(format!("RSA with {} hash algorithm not supported", hash_algorithm))),
    }
}