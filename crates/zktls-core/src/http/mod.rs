//! HTTP/1.1 Protocol Implementation for zkTLS
//!
//! This module provides a complete HTTP/1.1 implementation optimized for 
//! zero-knowledge TLS verification. It includes request building, response
//! parsing, header handling, and integration with TLS application data.
//!
//! # Features
//!
//! - **Memory Efficient**: Optimized for zkVM environments with minimal heap usage
//! - **Standards Compliant**: Full HTTP/1.1 support following RFC 7230-7235
//! - **Secure**: Proper validation and error handling for untrusted data
//! - **Zero-Knowledge Ready**: Deterministic parsing for proof generation
//!
//! # Architecture
//!
//! The module is organized into focused components:
//!
//! - [`headers`] - HTTP header container with case-insensitive access
//! - [`request`] - HTTP request building and parsing
//! - [`response`] - HTTP response parsing with chunked encoding support
//! - [`message`] - Legacy unified HTTP message interface (for compatibility)
//! - [`commitment`] - Cryptographic commitments for HTTP requests and responses
//! - [`merkle`] - Merkle tree commitments for large payload selective disclosure
//!
//! # Usage Examples
//!
//! ## Building HTTP Requests
//!
//! ```rust,no_run
//! use zktls_core::http::{HttpRequest, HttpMethod};
//! 
//! // Simple GET request
//! let request = HttpRequest::get("/api/data", "example.com")?;
//! 
//! // POST request with JSON body
//! let request = HttpRequest::post_json(
//!     "/api/submit",
//!     "api.example.com", 
//!     r#"{"key": "value"}"#
//! )?;
//! 
//! // Serialize for transmission
//! let wire_bytes = request.serialize();
//! # Ok::<(), zktls_core::ZkTlsError>(())
//! ```
//!
//! ## Parsing HTTP Responses
//!
//! ```rust,no_run
//! use zktls_core::http::HttpResponse;
//! 
//! let raw_response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"result\":\"success\"}";
//! let response = HttpResponse::parse(raw_response)?;
//! 
//! assert!(response.is_success());
//! assert_eq!(response.status(), 200);
//! assert_eq!(response.header("content-type"), Some(&"application/json".to_string()));
//! # Ok::<(), zktls_core::ZkTlsError>(())
//! ```
//!
//! ## Working with Headers
//!
//! ```rust,no_run
//! use zktls_core::http::HttpHeaders;
//! 
//! let mut headers = HttpHeaders::new();
//! headers.insert("Content-Type", "application/json");
//! headers.insert("Authorization", "Bearer token123");
//! 
//! // Case-insensitive access
//! assert_eq!(headers.get("content-type"), Some(&"application/json".to_string()));
//! assert_eq!(headers.get("CONTENT-TYPE"), Some(&"application/json".to_string()));
//! ```
//!
//! # Integration with TLS
//!
//! This HTTP implementation is designed to work seamlessly with the TLS
//! application data layer for HTTPS communication:
//!
//! ```rust,no_run
//! use zktls_core::{http::HttpRequest, tls::ApplicationDataHandler};
//! 
//! // Build HTTP request
//! let request = HttpRequest::get("/secure", "secure.example.com")?;
//! let http_bytes = request.serialize();
//! 
//! // Encrypt via TLS
//! let handler = ApplicationDataHandler::new()?;
//! let encrypted = handler.encrypt(&http_bytes, &traffic_key, sequence_num)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # zkVM Optimizations
//!
//! The implementation includes several optimizations for zero-knowledge environments:
//!
//! - **Deterministic Parsing**: Consistent behavior for proof generation
//! - **Memory Bounds**: Fixed-size collections where possible using `heapless`
//! - **Error Propagation**: Comprehensive error handling without panics
//! - **Proof-Friendly**: Structured data suitable for commitment schemes

pub mod headers;
pub mod request; 
pub mod response;
pub mod message;
pub mod commitment;
pub mod merkle;

// Re-export main types for convenience
pub use headers::{HttpHeaders, headers as header_names};
pub use request::{HttpRequest, HttpMethod, url};
pub use response::{HttpResponse, HttpStatusCode};
pub use message::HttpMessage;
pub use commitment::{HttpRequestCommitment, HttpResponseCommitment, CommitmentScheme};
pub use merkle::{MerkleTreeCommitment, MerkleProof, SelectiveProof};

/// HTTP version constants
pub mod version {
    pub const HTTP_1_0: &str = "HTTP/1.0";
    pub const HTTP_1_1: &str = "HTTP/1.1";
}

/// Common MIME types for Content-Type headers
pub mod mime_types {
    pub const TEXT_PLAIN: &str = "text/plain";
    pub const TEXT_HTML: &str = "text/html";
    pub const APPLICATION_JSON: &str = "application/json";
    pub const APPLICATION_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
    pub const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";
    pub const MULTIPART_FORM_DATA: &str = "multipart/form-data";
}

/// Utility functions for HTTP processing
pub mod utils {
    use crate::errors::ZkTlsError;

    /// Validate HTTP header name according to RFC 7230
    pub fn is_valid_header_name(name: &str) -> bool {
        !name.is_empty() 
            && name.chars().all(|c| {
                c.is_ascii() && !c.is_control() && !"()<>@,;:\\\"/[]?={} \t".contains(c)
            })
    }

    /// Validate HTTP header value according to RFC 7230
    pub fn is_valid_header_value(value: &str) -> bool {
        value.chars().all(|c| {
            c == '\t' || (c.is_ascii() && c != '\r' && c != '\n')
        })
    }

    /// Parse HTTP version string
    pub fn parse_http_version(version: &str) -> Result<(u8, u8), ZkTlsError> {
        if !version.starts_with("HTTP/") {
            return Err(ZkTlsError::InvalidTlsMessage("Invalid HTTP version prefix".into()));
        }

        let version_part = &version[5..];
        let mut parts = version_part.split('.');
        
        let major = parts.next()
            .and_then(|s| s.parse::<u8>().ok())
            .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Invalid HTTP major version".into()))?;
            
        let minor = parts.next()
            .and_then(|s| s.parse::<u8>().ok())
            .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Invalid HTTP minor version".into()))?;

        if parts.next().is_some() {
            return Err(ZkTlsError::InvalidTlsMessage("Invalid HTTP version format".into()));
        }

        Ok((major, minor))
    }

    /// Check if HTTP method typically allows a request body
    pub fn method_allows_body(method: &str) -> bool {
        matches!(method.to_uppercase().as_str(), "POST" | "PUT" | "PATCH")
    }

    /// Get recommended default headers for HTTP requests
    pub fn default_request_headers() -> crate::http::HttpHeaders {
        let mut headers = crate::http::HttpHeaders::new();
        headers.insert("user-agent", "zkTLS/1.0");
        headers.insert("accept", "*/*");
        headers.insert("connection", "close");
        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_validation() {
        assert!(utils::is_valid_header_name("Content-Type"));
        assert!(utils::is_valid_header_name("X-Custom-Header"));
        assert!(!utils::is_valid_header_name("Invalid Header")); // contains space
        assert!(!utils::is_valid_header_name("Invalid:Header")); // contains colon

        assert!(utils::is_valid_header_value("application/json"));
        assert!(utils::is_valid_header_value("Bearer token123"));
        assert!(!utils::is_valid_header_value("Invalid\nValue")); // contains newline
    }

    #[test]
    fn test_http_version_parsing() {
        assert_eq!(utils::parse_http_version("HTTP/1.1").unwrap(), (1, 1));
        assert_eq!(utils::parse_http_version("HTTP/1.0").unwrap(), (1, 0));
        assert!(utils::parse_http_version("HTTP/2.0").is_ok()); // Valid format
        assert!(utils::parse_http_version("HTTPS/1.1").is_err()); // Wrong prefix
        assert!(utils::parse_http_version("HTTP/1").is_err()); // Missing minor
    }

    #[test]
    fn test_method_body_allowance() {
        assert!(utils::method_allows_body("POST"));
        assert!(utils::method_allows_body("PUT"));
        assert!(utils::method_allows_body("PATCH"));
        assert!(!utils::method_allows_body("GET"));
        assert!(!utils::method_allows_body("DELETE"));
        assert!(!utils::method_allows_body("HEAD"));
    }

    #[test]
    fn test_default_headers() {
        let headers = utils::default_request_headers();
        assert!(headers.get("user-agent").is_some());
        assert!(headers.get("accept").is_some());
        assert!(headers.get("connection").is_some());
    }
}