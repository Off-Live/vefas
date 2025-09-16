//! Gateway error types and handling
//!
//! This module defines comprehensive error types for the zkTLS gateway,
//! providing detailed error information for both API and CLI operations.

use thiserror::Error;
use std::fmt;

/// Gateway error enumeration
#[derive(Error, Debug)]
pub enum GatewayError {
    /// Configuration-related errors
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Platform-specific errors
    #[error("Platform error ({platform}): {message}")]
    Platform { platform: String, message: String },
    
    /// Proof generation errors
    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),
    
    /// Proof verification errors
    #[error("Proof verification failed: {0}")]
    ProofVerification(String),
    
    /// Input validation errors
    #[error("Input validation failed: {0}")]
    InputValidation(String),
    
    /// File I/O errors
    #[error("File I/O error: {0}")]
    FileIO(#[from] std::io::Error),
    
    /// Serialization/deserialization errors
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    /// HTTP server errors
    #[error("HTTP server error: {0}")]
    HttpServer(String),
    
    /// Network errors
    #[error("Network error: {0}")]
    Network(String),
    
    /// Timeout errors
    #[error("Operation timeout: {operation} after {timeout_ms}ms")]
    Timeout { operation: String, timeout_ms: u64 },
    
    /// Resource limit errors
    #[error("Resource limit exceeded: {resource} (limit: {limit})")]
    ResourceLimit { resource: String, limit: String },
    
    /// Authentication/authorization errors
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    /// Rate limiting errors
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
    
    /// Internal server errors
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl GatewayError {
    /// Create a configuration error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }
    
    /// Create a platform error
    pub fn platform(platform: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Platform {
            platform: platform.into(),
            message: message.into(),
        }
    }
    
    /// Create a proof generation error
    pub fn proof_generation(message: impl Into<String>) -> Self {
        Self::ProofGeneration(message.into())
    }
    
    /// Create a proof verification error
    pub fn proof_verification(message: impl Into<String>) -> Self {
        Self::ProofVerification(message.into())
    }
    
    /// Create an input validation error
    pub fn input_validation(message: impl Into<String>) -> Self {
        Self::InputValidation(message.into())
    }
    
    /// Create a serialization error
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization(message.into())
    }
    
    /// Create an HTTP server error
    pub fn http_server(message: impl Into<String>) -> Self {
        Self::HttpServer(message.into())
    }
    
    /// Create a network error
    pub fn network(message: impl Into<String>) -> Self {
        Self::Network(message.into())
    }
    
    /// Create a timeout error
    pub fn timeout(operation: impl Into<String>, timeout_ms: u64) -> Self {
        Self::Timeout {
            operation: operation.into(),
            timeout_ms,
        }
    }
    
    /// Create a resource limit error
    pub fn resource_limit(resource: impl Into<String>, limit: impl Into<String>) -> Self {
        Self::ResourceLimit {
            resource: resource.into(),
            limit: limit.into(),
        }
    }
    
    /// Create an authentication error
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::Authentication(message.into())
    }
    
    /// Create a rate limit error
    pub fn rate_limit(message: impl Into<String>) -> Self {
        Self::RateLimit(message.into())
    }
    
    /// Create an internal server error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
    
    /// Get the HTTP status code for this error
    pub fn http_status_code(&self) -> u16 {
        match self {
            Self::Config(_) => 500,
            Self::Platform { .. } => 502,
            Self::ProofGeneration(_) => 500,
            Self::ProofVerification(_) => 400,
            Self::InputValidation(_) => 400,
            Self::FileIO(_) => 500,
            Self::Serialization(_) => 400,
            Self::HttpServer(_) => 500,
            Self::Network(_) => 502,
            Self::Timeout { .. } => 504,
            Self::ResourceLimit { .. } => 413,
            Self::Authentication(_) => 401,
            Self::RateLimit(_) => 429,
            Self::Internal(_) => 500,
        }
    }
    
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network(_) | Self::Timeout { .. } | Self::HttpServer(_) => true,
            _ => false,
        }
    }
}

/// Result type alias for gateway operations
pub type GatewayResult<T> = Result<T, GatewayError>;

/// Error response for API endpoints
#[derive(Debug, Clone, serde::Serialize)]
pub struct ErrorResponse {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Request ID (if available)
    pub request_id: Option<String>,
    /// Additional error details
    pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
    /// Create a new error response
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            request_id: None,
            details: None,
        }
    }
    
    /// Add request ID to error response
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
    
    /// Add additional details to error response
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl From<GatewayError> for ErrorResponse {
    fn from(error: GatewayError) -> Self {
        let code = match error {
            GatewayError::Config(_) => "CONFIG_ERROR",
            GatewayError::Platform { .. } => "PLATFORM_ERROR",
            GatewayError::ProofGeneration(_) => "PROOF_GENERATION_ERROR",
            GatewayError::ProofVerification(_) => "PROOF_VERIFICATION_ERROR",
            GatewayError::InputValidation(_) => "INPUT_VALIDATION_ERROR",
            GatewayError::FileIO(_) => "FILE_IO_ERROR",
            GatewayError::Serialization(_) => "SERIALIZATION_ERROR",
            GatewayError::HttpServer(_) => "HTTP_SERVER_ERROR",
            GatewayError::Network(_) => "NETWORK_ERROR",
            GatewayError::Timeout { .. } => "TIMEOUT_ERROR",
            GatewayError::ResourceLimit { .. } => "RESOURCE_LIMIT_ERROR",
            GatewayError::Authentication(_) => "AUTHENTICATION_ERROR",
            GatewayError::RateLimit(_) => "RATE_LIMIT_ERROR",
            GatewayError::Internal(_) => "INTERNAL_ERROR",
        };
        
        Self::new(code, error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = GatewayError::config("test config error");
        assert!(matches!(error, GatewayError::Config(_)));
        
        let error = GatewayError::platform("sp1", "test platform error");
        assert!(matches!(error, GatewayError::Platform { .. }));
        
        let error = GatewayError::timeout("test operation", 5000);
        assert!(matches!(error, GatewayError::Timeout { .. }));
    }

    #[test]
    fn test_http_status_codes() {
        assert_eq!(GatewayError::config("test").http_status_code(), 500);
        assert_eq!(GatewayError::input_validation("test").http_status_code(), 400);
        assert_eq!(GatewayError::timeout("test", 1000).http_status_code(), 504);
        assert_eq!(GatewayError::rate_limit("test").http_status_code(), 429);
    }

    #[test]
    fn test_retryable_errors() {
        assert!(GatewayError::network("test").is_retryable());
        assert!(GatewayError::timeout("test", 1000).is_retryable());
        assert!(!GatewayError::config("test").is_retryable());
        assert!(!GatewayError::input_validation("test").is_retryable());
    }

    #[test]
    fn test_error_response() {
        let response = ErrorResponse::new("TEST_ERROR", "test message");
        assert_eq!(response.code, "TEST_ERROR");
        assert_eq!(response.message, "test message");
        
        let response = response.with_request_id("req-123");
        assert_eq!(response.request_id, Some("req-123".to_string()));
    }

    #[test]
    fn test_error_response_from_gateway_error() {
        let error = GatewayError::config("test error");
        let response: ErrorResponse = error.into();
        assert_eq!(response.code, "CONFIG_ERROR");
        assert_eq!(response.message, "Configuration error: test error");
    }
}
