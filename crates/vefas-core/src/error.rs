//! Error types for VEFAS Core

extern crate alloc;

use alloc::string::String;
use vefas_types::errors::{HttpErrorType, TlsErrorType, VefasError};

/// Result type for VEFAS Core operations
pub type Result<T> = core::result::Result<T, VefasCoreError>;

/// VEFAS Core error types
#[derive(Debug, Clone, PartialEq)]
pub enum VefasCoreError {
    /// Configuration error
    ConfigError(String),

    /// URL parsing error
    UrlError(String),

    /// Network error
    NetworkError(String),

    /// TLS error
    TlsError(String),

    /// HTTP parsing error
    HttpError(String),

    /// Verification error
    VerificationError(String),

    /// Serialization error
    SerializationError(String),

    /// Invalid input error
    InvalidInput(String),

    /// Internal error
    Internal(String),

    /// Data extraction error
    ExtractionError(String),

    /// Validation error
    ValidationError(String),
}

impl core::fmt::Display for VefasCoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VefasCoreError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            VefasCoreError::UrlError(msg) => write!(f, "URL error: {}", msg),
            VefasCoreError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            VefasCoreError::TlsError(msg) => write!(f, "TLS error: {}", msg),
            VefasCoreError::HttpError(msg) => write!(f, "HTTP parsing error: {}", msg),
            VefasCoreError::VerificationError(msg) => write!(f, "Verification error: {}", msg),
            VefasCoreError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            VefasCoreError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            VefasCoreError::Internal(msg) => write!(f, "Internal error: {}", msg),
            VefasCoreError::ExtractionError(msg) => write!(f, "Data extraction error: {}", msg),
            VefasCoreError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VefasCoreError {}

impl VefasCoreError {
    /// Create a new configuration error
    pub fn config_error(msg: impl Into<String>) -> Self {
        Self::ConfigError(msg.into())
    }

    /// Create a new URL error
    pub fn url_error(msg: impl Into<String>) -> Self {
        Self::UrlError(msg.into())
    }

    /// Create a new network error
    pub fn network_error(msg: impl Into<String>) -> Self {
        Self::NetworkError(msg.into())
    }

    /// Create a new TLS error
    pub fn tls_error(msg: impl Into<String>) -> Self {
        Self::TlsError(msg.into())
    }

    /// Create a new HTTP error
    pub fn http_error(msg: impl Into<String>) -> Self {
        Self::HttpError(msg.into())
    }

    /// Create a new verification error
    pub fn verification_error(msg: impl Into<String>) -> Self {
        Self::VerificationError(msg.into())
    }

    /// Create a new serialization error
    pub fn serialization_error(msg: impl Into<String>) -> Self {
        Self::SerializationError(msg.into())
    }

    /// Create a new invalid input error
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Create a new internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Create a new data extraction error
    pub fn extraction_error(msg: impl Into<String>) -> Self {
        Self::ExtractionError(msg.into())
    }

    /// Create a new validation error
    pub fn validation_error(msg: impl Into<String>) -> Self {
        Self::ValidationError(msg.into())
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for VefasCoreError {
    fn from(err: std::io::Error) -> Self {
        Self::NetworkError(err.to_string())
    }
}

impl From<serde_json::Error> for VefasCoreError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<url::ParseError> for VefasCoreError {
    fn from(err: url::ParseError) -> Self {
        Self::UrlError(err.to_string())
    }
}

impl From<rustls::Error> for VefasCoreError {
    fn from(err: rustls::Error) -> Self {
        Self::TlsError(err.to_string())
    }
}

impl From<VefasError> for VefasCoreError {
    fn from(err: VefasError) -> Self {
        match err {
            VefasError::InvalidInput { field, reason } => {
                Self::ValidationError(format!("Invalid input for {}: {}", field, reason))
            }
            VefasError::TlsError {
                error_type: _,
                message,
            } => Self::TlsError(message),
            VefasError::HttpError {
                error_type: _,
                message,
            } => Self::HttpError(message),
            VefasError::CryptoError {
                error_type: _,
                message,
            } => Self::VerificationError(message),
            VefasError::CertificateError {
                error_type: _,
                message,
            } => Self::VerificationError(message),
            VefasError::SerializationError { message } => Self::SerializationError(message),
            VefasError::ZkvmError {
                platform: _,
                message,
            } => Self::Internal(message),
            VefasError::MemoryError { .. } => Self::Internal("Memory error".to_string()),
            VefasError::VersionMismatch { .. } => {
                Self::ValidationError("Version mismatch".to_string())
            }
            VefasError::Internal { message } => Self::Internal(message),
        }
    }
}

impl From<VefasCoreError> for VefasError {
    fn from(e: VefasCoreError) -> Self {
        match e {
            VefasCoreError::ConfigError(msg) => VefasError::invalid_input("config", &msg),
            VefasCoreError::UrlError(msg) => {
                VefasError::http_error(HttpErrorType::InvalidUrl, &msg)
            }
            VefasCoreError::NetworkError(msg) => {
                VefasError::http_error(HttpErrorType::InvalidResponse, &msg)
            }
            VefasCoreError::TlsError(msg) => {
                VefasError::tls_error(TlsErrorType::InvalidHandshake, &msg)
            }
            VefasCoreError::HttpError(msg) => {
                VefasError::http_error(HttpErrorType::InvalidResponse, &msg)
            }
            VefasCoreError::VerificationError(msg) => {
                VefasError::tls_error(TlsErrorType::HandshakeVerificationFailed, &msg)
            }
            VefasCoreError::SerializationError(msg) => VefasError::serialization_error(&msg),
            VefasCoreError::InvalidInput(msg) => VefasError::invalid_input("input", &msg),
            VefasCoreError::Internal(msg) => VefasError::internal(&msg),
            VefasCoreError::ExtractionError(msg) => {
                VefasError::tls_error(TlsErrorType::InvalidTranscript, &msg)
            }
            VefasCoreError::ValidationError(msg) => {
                VefasError::tls_error(TlsErrorType::InvalidHandshake, &msg)
            }
        }
    }
}
