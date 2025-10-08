//! Error types for VEFAS Gateway

use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, warn};

use vefas_core::VefasCoreError;

/// VEFAS Gateway error types
#[derive(Debug, Error)]
pub enum VefasGatewayError {
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

impl VefasGatewayError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            VefasGatewayError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            VefasGatewayError::UnsupportedPlatform(_) => StatusCode::BAD_REQUEST,
            VefasGatewayError::ProofVerificationFailed(_) => StatusCode::BAD_REQUEST,
            VefasGatewayError::RateLimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
            VefasGatewayError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
            VefasGatewayError::Network(_) => StatusCode::BAD_GATEWAY,
            VefasGatewayError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VefasGatewayError::Initialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VefasGatewayError::ProofGenerationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VefasGatewayError::VefasCore(_) => StatusCode::BAD_REQUEST,
            VefasGatewayError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VefasGatewayError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the error code string
    pub fn error_code(&self) -> &'static str {
        match self {
            VefasGatewayError::InvalidRequest(_) => "INVALID_REQUEST",
            VefasGatewayError::UnsupportedPlatform(_) => "UNSUPPORTED_PLATFORM",
            VefasGatewayError::ProofVerificationFailed(_) => "PROOF_VERIFICATION_FAILED",
            VefasGatewayError::ProofGenerationFailed(_) => "PROOF_GENERATION_FAILED",
            VefasGatewayError::RateLimitExceeded(_) => "RATE_LIMIT_EXCEEDED",
            VefasGatewayError::Timeout(_) => "TIMEOUT",
            VefasGatewayError::Network(_) => "NETWORK_ERROR",
            VefasGatewayError::Configuration(_) => "CONFIGURATION_ERROR",
            VefasGatewayError::Initialization(_) => "INITIALIZATION_ERROR",
            VefasGatewayError::VefasCore(_) => "VEFAS_CORE_ERROR",
            VefasGatewayError::Serialization(_) => "SERIALIZATION_ERROR",
            VefasGatewayError::Internal(_) => "INTERNAL_ERROR",
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

impl IntoResponse for VefasGatewayError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_response = self.to_error_response(None);

        (status, Json(error_response)).into_response()
    }
}

/// Result type for VEFAS Gateway operations
pub type VefasGatewayResult<T> = Result<T, VefasGatewayError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            VefasGatewayError::InvalidRequest("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            VefasGatewayError::Internal("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            VefasGatewayError::RateLimitExceeded("test".to_string()).status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(
            VefasGatewayError::InvalidRequest("test".to_string()).error_code(),
            "INVALID_REQUEST"
        );
        assert_eq!(
            VefasGatewayError::ProofGenerationFailed("test".to_string()).error_code(),
            "PROOF_GENERATION_FAILED"
        );
    }

    #[test]
    fn test_error_response_conversion() {
        let error = VefasGatewayError::InvalidRequest("Invalid URL".to_string());
        let response = error.to_error_response(Some("session-123".to_string()));

        assert!(!response.success);
        assert_eq!(response.error.code, "INVALID_REQUEST");
        assert_eq!(response.error.message, "Invalid request: Invalid URL");
        assert_eq!(response.session_id, Some("session-123".to_string()));
    }
}
