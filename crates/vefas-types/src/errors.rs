//! Error types for VEFAS operations
//!
//! This module provides comprehensive error handling for all VEFAS operations,
//! designed for both std and no_std environments.

use alloc::string::String;
use serde::{Deserialize, Serialize};

/// Result type alias for VEFAS operations
pub type VefasResult<T> = Result<T, VefasError>;

/// Comprehensive error type for VEFAS operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VefasError {
    /// Invalid input data
    InvalidInput {
        /// Field that contains invalid data
        field: String,
        /// Reason for invalidity
        reason: String,
    },

    /// TLS protocol error
    TlsError {
        /// TLS error type
        error_type: TlsErrorType,
        /// Detailed error message
        message: String,
    },

    /// HTTP protocol error
    HttpError {
        /// HTTP error type
        error_type: HttpErrorType,
        /// Detailed error message
        message: String,
    },

    /// Cryptographic operation error
    CryptoError {
        /// Cryptographic error type
        error_type: CryptoErrorType,
        /// Detailed error message
        message: String,
    },

    /// Certificate validation error
    CertificateError {
        /// Certificate error type
        error_type: CertificateErrorType,
        /// Detailed error message
        message: String,
    },

    /// Serialization/deserialization error
    SerializationError {
        /// Error message
        message: String,
    },

    /// zkVM execution error
    ZkvmError {
        /// zkVM platform
        platform: String,
        /// Error message
        message: String,
    },

    /// Memory constraint violation
    MemoryError {
        /// Requested size
        requested: usize,
        /// Maximum allowed size
        limit: usize,
        /// Context of the allocation
        context: String,
    },

    /// Protocol version mismatch
    VersionMismatch {
        /// Expected version
        expected: u16,
        /// Actual version
        actual: u16,
    },

    /// Internal error (should not occur in production)
    Internal {
        /// Error message
        message: String,
    },
}

/// TLS-specific error types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsErrorType {
    /// Invalid handshake message
    InvalidHandshake,
    /// Unsupported TLS version
    UnsupportedVersion,
    /// Unsupported cipher suite
    UnsupportedCipherSuite,
    /// Invalid key exchange
    InvalidKeyExchange,
    /// Handshake verification failed
    HandshakeVerificationFailed,
    /// Invalid transcript format
    InvalidTranscript,
    /// Missing required extension
    MissingExtension,
    /// Invalid extension data
    InvalidExtension,
}

/// HTTP-specific error types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpErrorType {
    /// Invalid HTTP method
    InvalidMethod,
    /// Invalid HTTP version
    InvalidVersion,
    /// Invalid status code
    InvalidStatusCode,
    /// Invalid header format
    InvalidHeader,
    /// Header too large
    HeaderTooLarge,
    /// Body too large
    BodyTooLarge,
    /// Invalid URL format
    InvalidUrl,
    /// Missing required header
    MissingHeader,
    /// Invalid request format
    InvalidRequest,
    /// Invalid response format
    InvalidResponse,
}

/// Cryptographic error types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoErrorType {
    /// Invalid key length
    InvalidKeyLength,
    /// Invalid nonce/IV length
    InvalidNonceLength,
    /// Encryption/decryption failed
    CipherFailed,
    /// Hash computation failed
    HashFailed,
    /// Signature verification failed
    SignatureVerificationFailed,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Invalid elliptic curve point
    InvalidEcPoint,
    /// Invalid signature format
    InvalidSignature,
    /// HKDF operation failed
    HkdfFailed,
    /// Unsupported TLS Algorithm
    UnsupportedAlgorithm,
}

/// Certificate-specific error types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateErrorType {
    /// Invalid certificate format
    InvalidFormat,
    /// Certificate parsing failed
    ParseFailed,
    /// Certificate chain validation failed
    ChainValidationFailed,
    /// Certificate expired
    Expired,
    /// Certificate not yet valid
    NotYetValid,
    /// Hostname mismatch
    HostnameMismatch,
    /// Invalid signature algorithm
    InvalidSignatureAlgorithm,
    /// Unknown certificate authority
    UnknownCA,
    /// Certificate revoked
    Revoked,
    /// Invalid key usage
    InvalidKeyUsage,
    /// Chain too long
    ChainTooLong,
}

impl VefasError {
    /// Create an invalid input error
    pub fn invalid_input(field: &str, reason: &str) -> Self {
        Self::InvalidInput {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// Create a TLS error
    pub fn tls_error(error_type: TlsErrorType, message: &str) -> Self {
        Self::TlsError {
            error_type,
            message: message.into(),
        }
    }

    /// Create an HTTP error
    pub fn http_error(error_type: HttpErrorType, message: &str) -> Self {
        Self::HttpError {
            error_type,
            message: message.into(),
        }
    }

    /// Create a cryptographic error
    pub fn crypto_error(error_type: CryptoErrorType, message: &str) -> Self {
        Self::CryptoError {
            error_type,
            message: message.into(),
        }
    }

    /// Create a certificate error
    pub fn certificate_error(error_type: CertificateErrorType, message: &str) -> Self {
        Self::CertificateError {
            error_type,
            message: message.into(),
        }
    }

    /// Create a serialization error
    pub fn serialization_error(message: &str) -> Self {
        Self::SerializationError {
            message: message.into(),
        }
    }

    /// Create a zkVM error
    pub fn zkvm_error(platform: &str, message: &str) -> Self {
        Self::ZkvmError {
            platform: platform.into(),
            message: message.into(),
        }
    }

    /// Create a memory error
    pub fn memory_error(requested: usize, limit: usize, context: &str) -> Self {
        Self::MemoryError {
            requested,
            limit,
            context: context.into(),
        }
    }

    /// Create a version mismatch error
    pub fn version_mismatch(expected: u16, actual: u16) -> Self {
        Self::VersionMismatch { expected, actual }
    }

    /// Create an internal error
    pub fn internal(message: &str) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            VefasError::InvalidInput { .. } => false,
            VefasError::TlsError { error_type, .. } => matches!(
                error_type,
                TlsErrorType::UnsupportedVersion | TlsErrorType::UnsupportedCipherSuite
            ),
            VefasError::HttpError { error_type, .. } => matches!(
                error_type,
                HttpErrorType::HeaderTooLarge | HttpErrorType::BodyTooLarge
            ),
            VefasError::CryptoError { .. } => false,
            VefasError::CertificateError { error_type, .. } => matches!(
                error_type,
                CertificateErrorType::Expired | CertificateErrorType::NotYetValid
            ),
            VefasError::SerializationError { .. } => false,
            VefasError::ZkvmError { .. } => false,
            VefasError::MemoryError { .. } => false,
            VefasError::VersionMismatch { .. } => false,
            VefasError::Internal { .. } => false,
        }
    }

    /// Get error category for metrics/logging
    pub fn category(&self) -> &'static str {
        match self {
            VefasError::InvalidInput { .. } => "input",
            VefasError::TlsError { .. } => "tls",
            VefasError::HttpError { .. } => "http",
            VefasError::CryptoError { .. } => "crypto",
            VefasError::CertificateError { .. } => "certificate",
            VefasError::SerializationError { .. } => "serialization",
            VefasError::ZkvmError { .. } => "zkvm",
            VefasError::MemoryError { .. } => "memory",
            VefasError::VersionMismatch { .. } => "version",
            VefasError::Internal { .. } => "internal",
        }
    }
}

#[cfg(feature = "std")]
use core::fmt;

#[cfg(feature = "std")]
impl fmt::Display for VefasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VefasError::InvalidInput { field, reason } => {
                write!(f, "Invalid input in field '{}': {}", field, reason)
            }
            VefasError::TlsError {
                error_type,
                message,
            } => {
                write!(f, "TLS error ({:?}): {}", error_type, message)
            }
            VefasError::HttpError {
                error_type,
                message,
            } => {
                write!(f, "HTTP error ({:?}): {}", error_type, message)
            }
            VefasError::CryptoError {
                error_type,
                message,
            } => {
                write!(f, "Crypto error ({:?}): {}", error_type, message)
            }
            VefasError::CertificateError {
                error_type,
                message,
            } => {
                write!(f, "Certificate error ({:?}): {}", error_type, message)
            }
            VefasError::SerializationError { message } => {
                write!(f, "Serialization error: {}", message)
            }
            VefasError::ZkvmError { platform, message } => {
                write!(f, "zkVM error ({}): {}", platform, message)
            }
            VefasError::MemoryError {
                requested,
                limit,
                context,
            } => {
                write!(
                    f,
                    "Memory error in {}: requested {} bytes, limit {} bytes",
                    context, requested, limit
                )
            }
            VefasError::VersionMismatch { expected, actual } => {
                write!(f, "Version mismatch: expected {}, got {}", expected, actual)
            }
            VefasError::Internal { message } => {
                write!(f, "Internal error: {}", message)
            }
        }
    }
}

// Error trait implementation removed for no_std compatibility
// #[cfg(feature = "std")]
// impl std::error::Error for VefasError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = VefasError::invalid_input("domain", "too long");
        assert_eq!(error.category(), "input");
        assert!(!error.is_recoverable());
    }

    #[test]
    fn test_recoverable_errors() {
        let recoverable =
            VefasError::tls_error(TlsErrorType::UnsupportedVersion, "TLS 1.2 not supported");
        assert!(recoverable.is_recoverable());

        let non_recoverable = VefasError::crypto_error(
            CryptoErrorType::SignatureVerificationFailed,
            "Invalid signature",
        );
        assert!(!non_recoverable.is_recoverable());
    }

    #[test]
    fn test_serialization() {
        let error = VefasError::memory_error(1024, 512, "handshake buffer");
        let serialized = serde_json::to_string(&error).unwrap();
        let deserialized: VefasError = serde_json::from_str(&serialized).unwrap();
        assert_eq!(error, deserialized);
    }
}
