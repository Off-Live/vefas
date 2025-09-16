//! Comprehensive error handling system for zkTLS cryptographic operations
//! 
//! This module defines structured error types with proper error chains following
//! Rust best practices for production-grade error handling.

use thiserror::Error;

#[cfg(feature = "no_std")]
use alloc::string::String;

/// Comprehensive error type for all cryptographic operations in zkTLS
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CryptoError {
    /// Invalid key size provided to cryptographic operation
    #[error("Invalid key size: expected one of the supported sizes, got {0} bytes")]
    InvalidKeySize(usize),
    
    /// Invalid nonce/IV size provided to AEAD operation
    #[error("Invalid nonce size: expected {expected} bytes, got {actual} bytes")]
    InvalidNonceSize { expected: usize, actual: usize },
    
    /// Signature verification failed or signature format is invalid
    #[error("Invalid signature: signature verification failed or malformed signature data")]
    InvalidSignature,
    
    /// Error from zkVM precompile operation
    #[error("Precompile error: {0}")]
    PrecompileError(String),
    
    /// Cryptographic verification failed (generic verification failure)
    #[error("Verification failed: cryptographic verification did not succeed")]
    VerificationFailed,
    
    /// AEAD decryption failed (authentication tag mismatch)
    #[error("AEAD decryption failed: authentication tag verification failed")]
    DecryptionFailed,
    
    /// Invalid public key format or corrupted key data
    #[error("Invalid public key: key format is invalid or corrupted")]
    InvalidPublicKey,
    
    /// Invalid private key format or corrupted key data
    #[error("Invalid private key: key format is invalid or corrupted")]
    InvalidPrivateKey,
    
    /// Key generation failed
    #[error("Key generation failed: unable to generate cryptographically secure keys")]
    KeyGenerationFailed,
    
    /// Unsupported cryptographic algorithm or operation
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    
    /// zkVM platform not supported for this operation
    #[error("Platform not supported: operation not available on current zkVM platform")]
    PlatformNotSupported,
    
    /// HKDF output length is invalid (exceeds RFC 5869 limits)
    #[error("Invalid HKDF output length: requested {requested} bytes, maximum allowed is {max_allowed} bytes")]
    InvalidHkdfOutputLength { requested: usize, max_allowed: usize },
    
    /// HKDF pseudorandom key (PRK) is invalid
    #[error("Invalid HKDF PRK: PRK must be at least {min_length} bytes, got {actual_length} bytes")]
    InvalidHkdfPrk { min_length: usize, actual_length: usize },
}

impl CryptoError {
    /// Create an InvalidNonceSize error with expected and actual sizes
    pub fn invalid_nonce_size(expected: usize, actual: usize) -> Self {
        Self::InvalidNonceSize { expected, actual }
    }
    
    /// Create a PrecompileError with a custom message
    pub fn precompile_error<T: Into<String>>(msg: T) -> Self {
        Self::PrecompileError(msg.into())
    }
    
    /// Create an UnsupportedOperation error with a custom message
    pub fn unsupported_operation<T: Into<String>>(msg: T) -> Self {
        Self::UnsupportedOperation(msg.into())
    }
    
    /// Create an InvalidHkdfOutputLength error
    pub fn invalid_hkdf_output_length(requested: usize, max_allowed: usize) -> Self {
        Self::InvalidHkdfOutputLength { requested, max_allowed }
    }
    
    /// Create an InvalidHkdfPrk error
    pub fn invalid_hkdf_prk(min_length: usize, actual_length: usize) -> Self {
        Self::InvalidHkdfPrk { min_length, actual_length }
    }
}

/// Result type alias for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Helper trait for converting standard crypto library errors to CryptoError
pub trait IntoCryptoError<T> {
    fn into_crypto_error(self) -> CryptoResult<T>;
}

// Implement conversions for common crypto library errors
impl<T> IntoCryptoError<T> for Result<T, aes_gcm::Error> {
    fn into_crypto_error(self) -> CryptoResult<T> {
        self.map_err(|_| CryptoError::DecryptionFailed)
    }
}

impl<T> IntoCryptoError<T> for Result<T, p256::elliptic_curve::Error> {
    fn into_crypto_error(self) -> CryptoResult<T> {
        self.map_err(|_| CryptoError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(feature = "no_std")]
    use alloc::string::ToString;

    #[test]
    fn test_error_display_formatting() {
        let error = CryptoError::InvalidKeySize(15);
        assert!(error.to_string().contains("15"));
        
        let error = CryptoError::invalid_nonce_size(12, 8);
        let display = error.to_string();
        assert!(display.contains("12"));
        assert!(display.contains("8"));
    }
    
    #[test]
    fn test_error_debug_formatting() {
        let error = CryptoError::InvalidSignature;
        let display = error.to_string();
        assert!(display.contains("Invalid signature")); // Check the actual display message
    }
    
    #[test]
    fn test_error_equality() {
        assert_eq!(
            CryptoError::InvalidKeySize(16),
            CryptoError::InvalidKeySize(16)
        );
        assert_ne!(
            CryptoError::InvalidKeySize(16),
            CryptoError::InvalidKeySize(32)
        );
    }
    
    #[test]
    fn test_helper_constructors() {
        let error1 = CryptoError::invalid_nonce_size(12, 8);
        let error2 = CryptoError::InvalidNonceSize { expected: 12, actual: 8 };
        assert_eq!(error1, error2);
        
        let error = CryptoError::precompile_error("test message");
        assert!(matches!(error, CryptoError::PrecompileError(_)));
        assert!(error.to_string().contains("test message"));
    }
}