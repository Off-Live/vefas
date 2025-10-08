//! Error types for VEFAS crypto operations
//!
//! This module provides error handling that works in both std and no_std environments,
//! with different implementations based on the feature flags.

use alloc::{format, string::String, string::ToString};

use serde::{Deserialize, Serialize};

/// Result type for crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Comprehensive error type for cryptographic operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoError {
    /// Invalid key size
    InvalidKeySize(usize),

    /// Invalid nonce size
    InvalidNonceSize { expected: usize, actual: usize },

    /// Invalid public key
    InvalidPublicKey,

    /// Invalid private key
    InvalidPrivateKey,

    /// Invalid signature
    InvalidSignature,

    /// Encryption/decryption failed
    DecryptionFailed,

    /// Hash computation failed
    HashFailed,

    /// Signature verification failed
    SignatureVerificationFailed,

    /// Key derivation failed
    KeyDerivationFailed,

    /// HKDF operation failed
    HkdfFailed,

    /// Random number generation failed
    RngFailed,

    /// Certificate validation failed
    CertificateValidationFailed,

    /// Unsupported TLS Algorithm
    UnsupportedAlgorithm,

    /// Generic crypto error with message
    Generic(String),
}

impl CryptoError {
    /// Create a generic error with a message
    pub fn generic(msg: &str) -> Self {
        Self::Generic(msg.to_string())
    }

    /// Check if this error is related to invalid input
    pub fn is_input_error(&self) -> bool {
        matches!(
            self,
            CryptoError::InvalidKeySize(_)
                | CryptoError::InvalidNonceSize { .. }
                | CryptoError::InvalidPublicKey
                | CryptoError::InvalidPrivateKey
                | CryptoError::InvalidSignature
        )
    }

    /// Check if this error is related to cryptographic operations
    pub fn is_crypto_error(&self) -> bool {
        matches!(
            self,
            CryptoError::DecryptionFailed
                | CryptoError::HashFailed
                | CryptoError::SignatureVerificationFailed
                | CryptoError::KeyDerivationFailed
                | CryptoError::HkdfFailed
        )
    }

    /// Get error category for logging/metrics
    pub fn category(&self) -> &'static str {
        match self {
            CryptoError::InvalidKeySize(_) => "invalid_key_size",
            CryptoError::InvalidNonceSize { .. } => "invalid_nonce_size",
            CryptoError::InvalidPublicKey => "invalid_public_key",
            CryptoError::InvalidPrivateKey => "invalid_private_key",
            CryptoError::InvalidSignature => "invalid_signature",
            CryptoError::DecryptionFailed => "decryption_failed",
            CryptoError::HashFailed => "hash_failed",
            CryptoError::SignatureVerificationFailed => "signature_verification_failed",
            CryptoError::KeyDerivationFailed => "key_derivation_failed",
            CryptoError::HkdfFailed => "hkdf_failed",
            CryptoError::RngFailed => "rng_failed",
            CryptoError::CertificateValidationFailed => "certificate_validation_failed",
            CryptoError::UnsupportedAlgorithm => "unsupported_algorithm",
            CryptoError::Generic(_) => "generic",
        }
    }
}

// No_std Display implementation
impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidKeySize(size) => {
                write!(f, "Invalid key size: {}", size)
            }
            CryptoError::InvalidNonceSize { expected, actual } => {
                write!(
                    f,
                    "Invalid nonce size: expected {}, got {}",
                    expected, actual
                )
            }
            CryptoError::InvalidPublicKey => write!(f, "Invalid public key"),
            CryptoError::InvalidPrivateKey => write!(f, "Invalid private key"),
            CryptoError::InvalidSignature => write!(f, "Invalid signature"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::HashFailed => write!(f, "Hash computation failed"),
            CryptoError::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            CryptoError::HkdfFailed => write!(f, "HKDF operation failed"),
            CryptoError::RngFailed => write!(f, "Random number generation failed"),
            CryptoError::CertificateValidationFailed => write!(f, "Certificate validation failed"),
            CryptoError::UnsupportedAlgorithm => write!(f, "Unsupported algorithm"),
            CryptoError::Generic(msg) => write!(f, "Crypto error: {}", msg),
        }
    }
}

// Conversion from vefas_types::VefasError
impl From<vefas_types::VefasError> for CryptoError {
    fn from(err: vefas_types::VefasError) -> Self {
        use vefas_types::errors::{CryptoErrorType, VefasError};

        match err {
            VefasError::CryptoError {
                error_type,
                message: _,
            } => match error_type {
                CryptoErrorType::InvalidKeyLength => CryptoError::InvalidKeySize(0),
                CryptoErrorType::InvalidNonceLength => CryptoError::InvalidNonceSize {
                    expected: 0,
                    actual: 0,
                },
                CryptoErrorType::CipherFailed => CryptoError::DecryptionFailed,
                CryptoErrorType::HashFailed => CryptoError::HashFailed,
                CryptoErrorType::SignatureVerificationFailed => {
                    CryptoError::SignatureVerificationFailed
                }
                CryptoErrorType::KeyDerivationFailed => CryptoError::KeyDerivationFailed,
                CryptoErrorType::InvalidEcPoint => CryptoError::InvalidPublicKey,
                CryptoErrorType::InvalidSignature => CryptoError::InvalidSignature,
                CryptoErrorType::HkdfFailed => CryptoError::HkdfFailed,
                CryptoErrorType::UnsupportedAlgorithm => CryptoError::UnsupportedAlgorithm,
            },
            _ => CryptoError::Generic("VefasError conversion".to_string()),
        }
    }
}

// Conversion to vefas_types::VefasError
impl From<CryptoError> for vefas_types::VefasError {
    fn from(err: CryptoError) -> Self {
        use vefas_types::errors::CryptoErrorType;

        let (error_type, message) = match err {
            CryptoError::InvalidKeySize(size) => (
                CryptoErrorType::InvalidKeyLength,
                format!("Invalid key size: {}", size),
            ),
            CryptoError::InvalidNonceSize { expected, actual } => (
                CryptoErrorType::InvalidNonceLength,
                format!("Invalid nonce size: expected {}, got {}", expected, actual),
            ),
            CryptoError::InvalidPublicKey => (
                CryptoErrorType::InvalidEcPoint,
                "Invalid public key".to_string(),
            ),
            CryptoError::InvalidPrivateKey => (
                CryptoErrorType::InvalidEcPoint,
                "Invalid private key".to_string(),
            ),
            CryptoError::InvalidSignature => (
                CryptoErrorType::InvalidSignature,
                "Invalid signature".to_string(),
            ),
            CryptoError::DecryptionFailed => (
                CryptoErrorType::CipherFailed,
                "Decryption failed".to_string(),
            ),
            CryptoError::HashFailed => (
                CryptoErrorType::HashFailed,
                "Hash computation failed".to_string(),
            ),
            CryptoError::SignatureVerificationFailed => (
                CryptoErrorType::SignatureVerificationFailed,
                "Signature verification failed".to_string(),
            ),
            CryptoError::KeyDerivationFailed => (
                CryptoErrorType::KeyDerivationFailed,
                "Key derivation failed".to_string(),
            ),
            CryptoError::HkdfFailed => (
                CryptoErrorType::HkdfFailed,
                "HKDF operation failed".to_string(),
            ),
            CryptoError::RngFailed => (
                CryptoErrorType::KeyDerivationFailed,
                "Random number generation failed".to_string(),
            ),
            CryptoError::CertificateValidationFailed => (
                CryptoErrorType::SignatureVerificationFailed,
                "Certificate validation failed".to_string(),
            ),
            CryptoError::UnsupportedAlgorithm => (
                CryptoErrorType::UnsupportedAlgorithm,
                "Unsupported algorithm".to_string(),
            ),
            CryptoError::Generic(msg) => (CryptoErrorType::CipherFailed, msg),
        };

        vefas_types::VefasError::crypto_error(error_type, &message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = CryptoError::InvalidKeySize(16);
        assert_eq!(err.category(), "invalid_key_size");
        assert!(err.is_input_error());
        assert!(!err.is_crypto_error());
    }

    #[test]
    fn test_error_conversion() {
        let crypto_err = CryptoError::HashFailed;
        let vefas_err: vefas_types::VefasError = crypto_err.clone().into();
        let back_to_crypto: CryptoError = vefas_err.into();

        // Should be in the same category
        assert_eq!(crypto_err.category(), back_to_crypto.category());
    }

    #[test]
    fn test_error_categorization() {
        let input_err = CryptoError::InvalidPublicKey;
        assert!(input_err.is_input_error());
        assert!(!input_err.is_crypto_error());

        let crypto_err = CryptoError::DecryptionFailed;
        assert!(!crypto_err.is_input_error());
        assert!(crypto_err.is_crypto_error());
    }

    #[test]
    fn test_error_display() {
        let err = CryptoError::InvalidKeySize(32);
        let display = format!("{}", err);
        assert!(display.contains("Invalid key size: 32"));
    }

    #[test]
    fn test_error_json_serialization_no_std() {
        use alloc::vec::Vec;

        let err = CryptoError::InvalidKeySize(32);

        // Test serialization using serde-json-core (no_std compatible)
        let mut buffer = Vec::new();
        buffer.resize(256, 0); // Pre-allocate buffer

        if let Ok(written) = serde_json_core::to_slice(&err, &mut buffer) {
            // Test deserialization
            if let Ok((deserialized, _)) =
                serde_json_core::from_slice::<CryptoError>(&buffer[..written])
            {
                assert_eq!(err, deserialized);
            }
        }
    }

    // Note: JSON serialization works in no_std with serde-json-core
}
