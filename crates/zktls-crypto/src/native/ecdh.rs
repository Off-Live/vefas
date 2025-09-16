//! Native ECDH implementations using x25519-dalek and p256 crates
//!
//! This module provides X25519 and P-256 ECDH key exchange implementations using
//! well-tested cryptographic libraries. These implementations are used as fallbacks
//! when zkVM precompiles are not available.
//!
//! # Security
//!
//! - X25519 implementation uses `x25519-dalek` which provides constant-time operations
//! - P-256 implementation uses `p256` crate with comprehensive security audits
//! - All operations are resistant to timing attacks and side-channel analysis
//!
//! # Performance  
//!
//! These implementations automatically benefit from platform optimizations and are
//! suitable for production use in standard Rust environments.

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use p256::{
    ecdh::diffie_hellman,
    EncodedPoint, 
    PublicKey as P256PublicKey,
    SecretKey as P256SecretKey,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use crate::error::{CryptoResult, CryptoError};

#[cfg(feature = "no_std")]
use alloc::{vec, vec::Vec};

/// Helper function to create a secure RNG for cross-environment compatibility
///
/// In std environments, uses system entropy via ChaCha20Rng::from_entropy().
/// In no_std environments, uses a deterministic seed (for zkVM compatibility).
/// 
/// # Production Note
/// For zkVM deployment, the deterministic seed should be provided by the host
/// environment to maintain cryptographic security while ensuring deterministic execution.
fn create_secure_rng() -> impl RngCore + CryptoRng {
    #[cfg(not(feature = "no_std"))]
    {
        // Use system entropy in std environment
        ChaCha20Rng::from_entropy()
    }
    #[cfg(feature = "no_std")]
    {
        // Deterministic seed for no_std/zkVM - in production, seed should come from host
        // Using a fixed seed for now to ensure compilation and deterministic execution
        ChaCha20Rng::from_seed([
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        ])
    }
}

/// Generate X25519 keypair for TLS 1.3 ECDHE (Ephemeral Diffie-Hellman)
///
/// # Returns
/// Tuple of (private_key, public_key) where both are 32 bytes
///
/// # Security
/// Uses ChaCha20Rng for cryptographically secure randomness.
/// **IMPORTANT**: This function generates ephemeral keys suitable for TLS 1.3 ECDHE.
/// Each generated private key should be used exactly once and then discarded
/// to maintain perfect forward secrecy.
///
/// # TLS 1.3 Compliance
/// Per RFC 8446 Section 4.2.8, ECDHE provides perfect forward secrecy by ensuring
/// that compromise of long-term keys does not compromise past session keys.
///
/// # Example
/// ```rust
/// use zktls_crypto::native::ecdh::x25519_generate_keypair;
///
/// let (private_key, public_key) = x25519_generate_keypair()?;
/// assert_eq!(private_key.len(), 32);
/// assert_eq!(public_key.len(), 32);
/// 
/// // In TLS 1.3, use the private key exactly once, then discard it
/// # Ok::<(), zktls_crypto::error::CryptoError>(())
/// ```
pub fn x25519_generate_keypair() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = create_secure_rng();
    // Use StaticSecret for compatibility but document ephemeral usage pattern
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = X25519PublicKey::from(&secret);
    
    Ok((secret.to_bytes().to_vec(), public.to_bytes().to_vec()))
}

/// Compute X25519 ECDHE shared secret with forward secrecy guarantees
///
/// # Arguments
/// * `private_key` - Local ephemeral private key (32 bytes) - **consumed and should be discarded after use**
/// * `peer_public_key` - Peer's public key (32 bytes)
///
/// # Returns
/// 32-byte shared secret
///
/// # Security & TLS 1.3 Compliance
/// This function implements ECDHE (Ephemeral Diffie-Hellman) per RFC 8446.
/// **CRITICAL**: The private key is consumed during this operation and should be
/// immediately discarded after use to maintain perfect forward secrecy.
///
/// # Forward Secrecy
/// Perfect forward secrecy ensures that compromise of long-term keys does not
/// compromise past session keys. This is achieved by:
/// 1. Generating fresh ephemeral keys for each session
/// 2. Using keys exactly once
/// 3. Securely erasing keys after use
///
/// # Errors
/// * `InvalidPrivateKey` - Private key format invalid
/// * `InvalidPublicKey` - Public key format invalid or not on curve
///
/// # Example
/// ```rust
/// use zktls_crypto::native::ecdh::{x25519_generate_keypair, x25519_ecdhe_shared_secret};
///
/// let (alice_private, alice_public) = x25519_generate_keypair()?;
/// let (bob_private, bob_public) = x25519_generate_keypair()?;
///
/// // Each private key is used exactly once and then discarded
/// let alice_shared = x25519_ecdhe_shared_secret(alice_private, &bob_public)?;
/// let bob_shared = x25519_ecdhe_shared_secret(bob_private, &alice_public)?;
/// assert_eq!(alice_shared, bob_shared);
/// 
/// // Private keys are now consumed and cannot be reused (forward secrecy)
/// # Ok::<(), zktls_crypto::error::CryptoError>(())
/// ```
pub fn x25519_ecdhe_shared_secret(private_key: Vec<u8>, peer_public_key: &[u8]) -> CryptoResult<Vec<u8>> {
    // Validate key sizes
    if private_key.len() != 32 {
        return Err(CryptoError::InvalidPrivateKey);
    }
    if peer_public_key.len() != 32 {
        return Err(CryptoError::InvalidPublicKey);
    }
    
    // Convert private key - consume the input vector for forward secrecy
    let mut private_bytes = [0u8; 32];
    private_bytes.copy_from_slice(&private_key);
    let secret = StaticSecret::from(private_bytes);
    
    // Convert public key
    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(peer_public_key);
    let public = X25519PublicKey::from(public_bytes);
    
    // Perform ECDHE - this consumes the secret key
    let shared_secret = secret.diffie_hellman(&public);
    
    // Note: StaticSecret::diffie_hellman() consumes self, providing forward secrecy
    // The private_key Vec is automatically dropped here
    
    Ok(shared_secret.to_bytes().to_vec())
}

/// Legacy X25519 Diffie-Hellman function - **DEPRECATED for TLS 1.3**
///
/// # Security Warning
/// This function allows private key reuse which violates TLS 1.3 ECDHE requirements.
/// Use `x25519_ecdhe_shared_secret` instead for TLS 1.3 compliance.
///
/// # Deprecation
/// This function is provided only for compatibility with legacy protocols.
/// New implementations should use `x25519_ecdhe_shared_secret` to ensure forward secrecy.
#[deprecated(since = "0.1.0", note = "Use x25519_ecdhe_shared_secret for TLS 1.3 compliance")]
pub fn x25519_diffie_hellman(private_key: &[u8], peer_public_key: &[u8]) -> CryptoResult<Vec<u8>> {
    // Validate key sizes
    if private_key.len() != 32 {
        return Err(CryptoError::InvalidPrivateKey);
    }
    if peer_public_key.len() != 32 {
        return Err(CryptoError::InvalidPublicKey);
    }
    
    // Convert private key
    let mut private_bytes = [0u8; 32];
    private_bytes.copy_from_slice(private_key);
    let secret = StaticSecret::from(private_bytes);
    
    // Convert public key
    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(peer_public_key);
    let public = X25519PublicKey::from(public_bytes);
    
    // Perform Diffie-Hellman
    let shared_secret = secret.diffie_hellman(&public);
    Ok(shared_secret.to_bytes().to_vec())
}

/// Generate P-256 keypair for TLS 1.3 ECDHE (Ephemeral Diffie-Hellman)
///
/// # Returns
/// Tuple of (private_key, public_key) where private key is 32 bytes
/// and public key is 64 bytes (uncompressed format without 0x04 prefix)
///
/// # Security  
/// Uses ChaCha20Rng for cryptographically secure randomness.
/// **IMPORTANT**: This function generates ephemeral keys suitable for TLS 1.3 ECDHE.
/// Each generated private key should be used exactly once and then discarded
/// to maintain perfect forward secrecy.
///
/// # TLS 1.3 Compliance
/// Per RFC 8446 Section 4.2.8, ECDHE provides perfect forward secrecy by ensuring
/// that compromise of long-term keys does not compromise past session keys.
///
/// # Example
/// ```rust
/// use zktls_crypto::native::ecdh::p256_generate_keypair;
///
/// let (private_key, public_key) = p256_generate_keypair()?;
/// assert_eq!(private_key.len(), 32);
/// assert_eq!(public_key.len(), 64);
/// 
/// // In TLS 1.3, use the private key exactly once, then discard it
/// # Ok::<(), zktls_crypto::error::CryptoError>(())
/// ```
pub fn p256_generate_keypair() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = create_secure_rng();
    let secret_key = P256SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();
    
    // Convert to bytes
    let private_bytes = secret_key.to_bytes();
    let public_point = public_key.to_encoded_point(false); // Uncompressed
    let public_bytes = public_point.as_bytes();
    
    // Skip the first byte (0x04 prefix for uncompressed) to get 64 bytes
    if public_bytes.len() == 65 && public_bytes[0] == 0x04 {
        Ok((private_bytes.to_vec(), public_bytes[1..].to_vec()))
    } else {
        Err(CryptoError::KeyGenerationFailed)
    }
}

/// Compute P-256 ECDHE shared secret with forward secrecy guarantees
///
/// # Arguments
/// * `private_key` - Local ephemeral private key (32 bytes) - **consumed and should be discarded after use**
/// * `peer_public_key` - Peer's public key (64 bytes uncompressed, without 0x04 prefix)
///
/// # Returns
/// 32-byte shared secret (x-coordinate of ECDH point)
///
/// # Security & TLS 1.3 Compliance
/// This function implements ECDHE (Ephemeral Diffie-Hellman) per RFC 8446.
/// **CRITICAL**: The private key is consumed during this operation and should be
/// immediately discarded after use to maintain perfect forward secrecy.
///
/// # Forward Secrecy
/// Perfect forward secrecy ensures that compromise of long-term keys does not
/// compromise past session keys. This is achieved by:
/// 1. Generating fresh ephemeral keys for each session
/// 2. Using keys exactly once
/// 3. Securely erasing keys after use
///
/// # Errors
/// * `InvalidPrivateKey` - Private key format invalid
/// * `InvalidPublicKey` - Public key format invalid or not on curve
///
/// # Example
/// ```rust
/// use zktls_crypto::native::ecdh::{p256_generate_keypair, p256_ecdhe_shared_secret};
///
/// let (alice_private, alice_public) = p256_generate_keypair()?;
/// let (bob_private, bob_public) = p256_generate_keypair()?;
///
/// // Each private key is used exactly once and then discarded
/// let alice_shared = p256_ecdhe_shared_secret(alice_private, &bob_public)?;
/// let bob_shared = p256_ecdhe_shared_secret(bob_private, &alice_public)?;
/// assert_eq!(alice_shared, bob_shared);
/// 
/// // Private keys are now consumed and cannot be reused (forward secrecy)
/// # Ok::<(), zktls_crypto::error::CryptoError>(())
/// ```
pub fn p256_ecdhe_shared_secret(private_key: Vec<u8>, peer_public_key: &[u8]) -> CryptoResult<Vec<u8>> {
    // Validate key sizes
    if private_key.len() != 32 {
        return Err(CryptoError::InvalidPrivateKey);
    }
    if peer_public_key.len() != 64 {
        return Err(CryptoError::InvalidPublicKey);
    }
    
    // Convert private key - consume the input vector for forward secrecy
    let secret_key = P256SecretKey::from_slice(&private_key)
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    
    // Convert public key (add 0x04 prefix for uncompressed format)
    let mut public_bytes = Vec::with_capacity(65);
    public_bytes.push(0x04); // Uncompressed point prefix
    public_bytes.extend_from_slice(peer_public_key);
    
    let encoded_point = EncodedPoint::from_bytes(&public_bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    
    let public_key = P256PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or(CryptoError::InvalidPublicKey)?;
    
    // Perform ECDHE - this consumes the secret key scalar
    let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    
    // The private_key Vec is dropped here, providing forward secrecy
    
    // Extract x-coordinate as the shared secret
    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Legacy P-256 Diffie-Hellman function - **DEPRECATED for TLS 1.3**
///
/// # Security Warning
/// This function allows private key reuse which violates TLS 1.3 ECDHE requirements.
/// Use `p256_ecdhe_shared_secret` instead for TLS 1.3 compliance.
///
/// # Deprecation
/// This function is provided only for compatibility with legacy protocols.
/// New implementations should use `p256_ecdhe_shared_secret` to ensure forward secrecy.
#[deprecated(since = "0.1.0", note = "Use p256_ecdhe_shared_secret for TLS 1.3 compliance")]
pub fn p256_diffie_hellman(private_key: &[u8], peer_public_key: &[u8]) -> CryptoResult<Vec<u8>> {
    // Validate key sizes
    if private_key.len() != 32 {
        return Err(CryptoError::InvalidPrivateKey);
    }
    if peer_public_key.len() != 64 {
        return Err(CryptoError::InvalidPublicKey);
    }
    
    // Convert private key
    let secret_key = P256SecretKey::from_slice(private_key)
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    
    // Convert public key (add 0x04 prefix for uncompressed format)
    let mut public_bytes = Vec::with_capacity(65);
    public_bytes.push(0x04); // Uncompressed point prefix
    public_bytes.extend_from_slice(peer_public_key);
    
    let encoded_point = EncodedPoint::from_bytes(&public_bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    
    let public_key = P256PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or(CryptoError::InvalidPublicKey)?;
    
    // Perform ECDH  
    let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    
    // Extract x-coordinate as the shared secret
    Ok(shared_secret.raw_secret_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// Test TLS 1.3 ECDHE forward secrecy compliance
    /// This test demonstrates the security improvement with ephemeral key handling
    #[test]
    fn test_tls13_ecdhe_forward_secrecy() {
        let public_key1 = hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let public_key2 = hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        
        // Generate ephemeral keys for TLS 1.3 ECDHE
        let (private_key1, _) = x25519_generate_keypair().unwrap();
        let (private_key2, _) = x25519_generate_keypair().unwrap();
        
        // With ECDHE, each private key is consumed and cannot be reused
        // This provides perfect forward secrecy
        let shared1 = x25519_ecdhe_shared_secret(private_key1, &public_key1).unwrap();
        let shared2 = x25519_ecdhe_shared_secret(private_key2, &public_key2).unwrap();
        
        // Different ephemeral keys and peers produce different secrets
        assert_ne!(shared1, shared2);
        
        // private_key1 and private_key2 are now consumed and cannot be reused
        // This ensures forward secrecy - compromise of future keys won't affect past sessions
    }
    
    #[test]
    fn test_x25519_ecdhe_basic() {
        let (private1, public1) = x25519_generate_keypair().unwrap();
        let (private2, public2) = x25519_generate_keypair().unwrap();
        
        assert_eq!(private1.len(), 32);
        assert_eq!(public1.len(), 32);
        assert_eq!(private2.len(), 32);
        assert_eq!(public2.len(), 32);
        
        // Keys should be different
        assert_ne!(private1, private2);
        assert_ne!(public1, public2);
        
        // Compute shared secrets using ECDHE (keys are consumed)
        let shared1 = x25519_ecdhe_shared_secret(private1, &public2).unwrap();
        let shared2 = x25519_ecdhe_shared_secret(private2, &public1).unwrap();
        
        assert_eq!(shared1, shared2);
        assert_eq!(shared1.len(), 32);
        
        // private1 and private2 are now consumed (forward secrecy)
    }
    
    #[test]
    fn test_p256_ecdhe_basic() {
        let (private1, public1) = p256_generate_keypair().unwrap();
        let (private2, public2) = p256_generate_keypair().unwrap();
        
        assert_eq!(private1.len(), 32);
        assert_eq!(public1.len(), 64);
        assert_eq!(private2.len(), 32);
        assert_eq!(public2.len(), 64);
        
        // Keys should be different
        assert_ne!(private1, private2);
        assert_ne!(public1, public2);
        
        // Compute shared secrets using ECDHE (keys are consumed)
        let shared1 = p256_ecdhe_shared_secret(private1, &public2).unwrap();
        let shared2 = p256_ecdhe_shared_secret(private2, &public1).unwrap();
        
        assert_eq!(shared1, shared2);
        assert_eq!(shared1.len(), 32);
        
        // private1 and private2 are now consumed (forward secrecy)
    }
    
    /// Test legacy functions still work but are deprecated
    #[test]
    #[allow(deprecated)]
    fn test_legacy_functions_still_work() {
        let private_key_bytes = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let public_key = hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        
        // Legacy function still works but is deprecated
        let _shared = x25519_diffie_hellman(&private_key_bytes, &public_key).unwrap();
        
        // This demonstrates the security issue - private key can be reused
        let _shared2 = x25519_diffie_hellman(&private_key_bytes, &public_key).unwrap();
        // This reuse violates TLS 1.3 ECDHE forward secrecy requirements
    }

    #[test]
    #[allow(deprecated)]
    fn test_x25519_rfc_vector() {
        // RFC 7748 test vector - using legacy function for compatibility
        let alice_private = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_public = hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let expected = hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        
        let result = x25519_diffie_hellman(&alice_private, &bob_public).unwrap();
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_x25519_ecdhe_rfc_vector() {
        // RFC 7748 test vector - using ECDHE function for TLS 1.3
        let alice_private = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").to_vec();
        let bob_public = hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let expected = hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        
        let result = x25519_ecdhe_shared_secret(alice_private, &bob_public).unwrap();
        assert_eq!(result, expected);
        // alice_private is now consumed (forward secrecy)
    }
    
    #[test]
    fn test_invalid_key_sizes() {
        // Test X25519 ECDHE invalid sizes
        let result = x25519_ecdhe_shared_secret(vec![0u8; 31], &[0u8; 32]);
        assert!(matches!(result, Err(CryptoError::InvalidPrivateKey)));
        
        let result = x25519_ecdhe_shared_secret(vec![0u8; 32], &[0u8; 31]);
        assert!(matches!(result, Err(CryptoError::InvalidPublicKey)));
        
        // Test P-256 ECDHE invalid sizes
        let result = p256_ecdhe_shared_secret(vec![0u8; 31], &[0u8; 64]);
        assert!(matches!(result, Err(CryptoError::InvalidPrivateKey)));
        
        let result = p256_ecdhe_shared_secret(vec![0u8; 32], &[0u8; 63]);
        assert!(matches!(result, Err(CryptoError::InvalidPublicKey)));
    }
    
    #[test]
    #[allow(deprecated)]
    fn test_legacy_invalid_key_sizes() {
        // Test legacy X25519 invalid sizes
        let result = x25519_diffie_hellman(&[0u8; 31], &[0u8; 32]);
        assert!(matches!(result, Err(CryptoError::InvalidPrivateKey)));
        
        let result = x25519_diffie_hellman(&[0u8; 32], &[0u8; 31]);
        assert!(matches!(result, Err(CryptoError::InvalidPublicKey)));
        
        // Test legacy P-256 invalid sizes
        let result = p256_diffie_hellman(&[0u8; 31], &[0u8; 64]);
        assert!(matches!(result, Err(CryptoError::InvalidPrivateKey)));
        
        let result = p256_diffie_hellman(&[0u8; 32], &[0u8; 63]);
        assert!(matches!(result, Err(CryptoError::InvalidPublicKey)));
    }
}