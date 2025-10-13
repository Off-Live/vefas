//! Error types for VEFAS Node

use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, warn};

use vefas_core::VefasCoreError;

/// VEFAS Node error types
#[derive(Debug, Error)]
pub enum VefasNodeError {
    #[error("Initialization error: {0}")]
    Initialization(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("VEFAS Core error: {0}")]
    VefasCore(#[from] VefasCoreError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

/// Standardized error response format
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: ErrorDetails,
    pub session_id: Option<String>,
}

/// Detailed error information
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetails {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl VefasNodeError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            VefasNodeError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            VefasNodeError::UnsupportedPlatform(_) => StatusCode::BAD_REQUEST,
            VefasNodeError::ProofVerificationFailed(_) => StatusCode::BAD_REQUEST,
            VefasNodeError::RateLimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
            VefasNodeError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
            VefasNodeError::Network(_) => StatusCode::BAD_GATEWAY,
            VefasNodeError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VefasNodeError::Initialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VefasNodeError::ProofGenerationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VefasNodeError::VefasCore(_) => StatusCode::BAD_REQUEST,
            VefasNodeError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VefasNodeError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the error code string
    pub fn error_code(&self) -> &'static str {
        match self {
            VefasNodeError::InvalidRequest(_) => "INVALID_REQUEST",
            VefasNodeError::UnsupportedPlatform(_) => "UNSUPPORTED_PLATFORM",
            VefasNodeError::ProofVerificationFailed(_) => "PROOF_VERIFICATION_FAILED",
            VefasNodeError::ProofGenerationFailed(_) => "PROOF_GENERATION_FAILED",
            VefasNodeError::RateLimitExceeded(_) => "RATE_LIMIT_EXCEEDED",
            VefasNodeError::Timeout(_) => "TIMEOUT",
            VefasNodeError::Network(_) => "NETWORK_ERROR",
            VefasNodeError::Configuration(_) => "CONFIGURATION_ERROR",
            VefasNodeError::Initialization(_) => "INITIALIZATION_ERROR",
            VefasNodeError::VefasCore(_) => "VEFAS_CORE_ERROR",
            VefasNodeError::Serialization(_) => "SERIALIZATION_ERROR",
            VefasNodeError::Internal(_) => "INTERNAL_ERROR",
        }
    }

    /// Convert to error response with optional session ID
    pub fn to_error_response(&self, session_id: Option<String>) -> ErrorResponse {
        // Log the error based on severity
        match self.status_code() {
            StatusCode::INTERNAL_SERVER_ERROR => {
                error!("Internal server error: {}", self);
            }
            StatusCode::BAD_GATEWAY => {
                warn!("Network error: {}", self);
            }
            _ => {
                // Client errors - log at debug level
                tracing::debug!("Client error: {}", self);
            }
        }

        ErrorResponse {
            success: false,
            error: ErrorDetails {
                code: self.error_code().to_string(),
                message: self.to_string(),
                details: None, // Can be extended for specific error types
            },
            session_id,
        }
    }
}

impl IntoResponse for VefasNodeError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_response = self.to_error_response(None);

        (status, Json(error_response)).into_response()
    }
}

/// Result type for VEFAS Node operations
pub type VefasNodeResult<T> = Result<T, VefasNodeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            VefasNodeError::InvalidRequest("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            VefasNodeError::Internal("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            VefasNodeError::RateLimitExceeded("test".to_string()).status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(
            VefasNodeError::InvalidRequest("test".to_string()).error_code(),
            "INVALID_REQUEST"
        );
        assert_eq!(
            VefasNodeError::ProofGenerationFailed("test".to_string()).error_code(),
            "PROOF_GENERATION_FAILED"
        );
    }

    #[test]
    fn test_error_response_conversion() {
        let error = VefasNodeError::InvalidRequest("Invalid URL".to_string());
        let response = error.to_error_response(Some("session-123".to_string()));

        assert!(!response.success);
        assert_eq!(response.error.code, "INVALID_REQUEST");
        assert_eq!(response.error.message, "Invalid request: Invalid URL");
        assert_eq!(response.session_id, Some("session-123".to_string()));
    }
}
