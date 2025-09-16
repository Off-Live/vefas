//! # HTTPS Client for zkTLS Implementation
//!
//! This module provides a complete HTTPS client that integrates all zkTLS components
//! for zero-knowledge verification of TLS handshakes and HTTP communications.
//!
//! ## Architecture
//!
//! The client is organized into focused sub-modules:
//!
//! - [`url`] - URL parsing and form encoding utilities
//! - [`session`] - TLS session management and certificate validation
//! - [`tls_client`] - TLS handshake and cryptographic operations
//! - [`http_client`] - HTTP request/response handling and commitments
//!
//! ## Key Features
//!
//! - **TLS 1.3 Handshake**: Complete implementation of RFC 8446
//! - **X.509 Certificate Validation**: Production-grade certificate chain validation
//! - **HTTP/1.1 Support**: Full HTTP protocol implementation
//! - **Commitment Generation**: Cryptographic commitments for zkVM proofs
//! - **Zero-Knowledge Optimized**: Deterministic behavior for proof generation
//!
//! ## Usage Examples
//!
//! ### Basic GET Request
//! ```rust,no_run
//! use zktls_core::client::{HttpsClient, HttpsClientConfig};
//!
//! let mut client = HttpsClient::new(HttpsClientConfig::default())?;
//! let response = client.get("https://api.example.com/data")?;
//! println!("Status: {}", response.status());
//! # Ok::<(), zktls_core::ZkTlsError>(())
//! ```
//!
//! ### POST with JSON Data
//! ```rust,no_run
//! use zktls_core::client::{HttpsClient, HttpsClientConfig};
//!
//! let mut client = HttpsClient::new(HttpsClientConfig::default())?;
//! let json_data = r#"{"key": "value"}"#;
//! let response = client.post_json("https://api.example.com/submit", json_data)?;
//! # Ok::<(), zktls_core::ZkTlsError>(())
//! ```
//!
//! ### Accessing Commitments for zkVM Proofs
//! ```rust,no_run
//! use zktls_core::client::{HttpsClient, HttpsClientConfig};
//!
//! let mut client = HttpsClient::new(HttpsClientConfig::default())?;
//! let response = client.get("https://api.example.com/data")?;
//! 
//! // Get commitments for zero-knowledge proof generation
//! let request_commitment = response.request_commitment();
//! let response_commitment = response.response_commitment();
//! let tls_session_info = response.tls_session_info();
//! # Ok::<(), zktls_core::ZkTlsError>(())
//! ```

use crate::{
    config::HttpsClientConfig,
    errors::{ZkTlsError, ZkTlsResult},
    http::HttpRequest,
};
use alloc::{collections::BTreeMap, string::String};

// Sub-modules
pub mod url;
pub mod session;
pub mod tls_client;
pub mod http_client;

// Re-export key types and functions
pub use session::{SessionKeys, TlsSessionInfo};
pub use http_client::{HttpsResponse, HttpClient};
pub use tls_client::TlsClient;
pub use url::{parse_url, encode_form_data, url_encode};

/// Custom error type for HTTPS client operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpsClientError {
    /// Configuration error
    ConfigError(String),
    /// Network connection error
    ConnectionError(String),
    /// TLS handshake failed
    HandshakeError(String),
    /// Certificate validation failed
    CertificateError(String),
    /// HTTP protocol error
    HttpError(String),
    /// Response too large
    ResponseTooLarge,
    /// Operation timeout
    Timeout,
    /// Invalid URL format
    InvalidUrl(String),
    /// zkTLS operation error
    ZkTlsError(ZkTlsError),
}

impl From<ZkTlsError> for HttpsClientError {
    fn from(error: ZkTlsError) -> Self {
        HttpsClientError::ZkTlsError(error)
    }
}

/// HTTPS Client with integrated zkTLS functionality
pub struct HttpsClient {
    /// HTTP client for request/response handling
    http_client: HttpClient,
    /// TLS client for handshake and session management
    tls_client: TlsClient,
    /// Current TLS session state (if connected)
    current_session: Option<session::TlsSession>,
}

impl HttpsClient {
    /// Create new HTTPS client with configuration
    pub fn new(config: HttpsClientConfig) -> ZkTlsResult<Self> {
        let http_client = HttpClient::new(config);
        let tls_client = TlsClient::new()?;
        
        Ok(Self {
            http_client,
            tls_client,
            current_session: None,
        })
    }

    /// Create HTTPS client with default configuration
    pub fn default() -> ZkTlsResult<Self> {
        Self::new(HttpsClientConfig::default())
    }

    /// Make an HTTP GET request
    pub fn get(&mut self, url: &str) -> ZkTlsResult<HttpsResponse> {
        let (hostname, _path) = parse_url(url)?;
        self.ensure_connected(&hostname)?;
        
        let session_info = self.current_session.as_ref().unwrap().to_session_info();
        self.http_client.get(url, &session_info)
    }

    /// Make an HTTP POST request with JSON body
    pub fn post_json(&mut self, url: &str, json_body: &str) -> ZkTlsResult<HttpsResponse> {
        let (hostname, _path) = parse_url(url)?;
        self.ensure_connected(&hostname)?;
        
        let session_info = self.current_session.as_ref().unwrap().to_session_info();
        self.http_client.post_json(url, json_body, &session_info)
    }

    /// Make an HTTP POST request with form data
    pub fn post_form(&mut self, url: &str, form_data: &BTreeMap<String, String>) -> ZkTlsResult<HttpsResponse> {
        let (hostname, _path) = parse_url(url)?;
        self.ensure_connected(&hostname)?;
        
        let session_info = self.current_session.as_ref().unwrap().to_session_info();
        self.http_client.post_form(url, form_data, &session_info)
    }

    /// Make a custom HTTP request
    pub fn request(&mut self, request: HttpRequest, hostname: &str) -> ZkTlsResult<HttpsResponse> {
        self.ensure_connected(hostname)?;
        
        let session_info = self.current_session.as_ref().unwrap().to_session_info();
        self.http_client.request(request, hostname, &session_info)
    }

    /// Ensure TLS connection is established for hostname
    fn ensure_connected(&mut self, hostname: &str) -> ZkTlsResult<()> {
        // Check if already connected to this hostname
        if let Some(ref session) = self.current_session {
            if session.hostname == hostname {
                return Ok(()); // Already connected
            }
        }
        
        // Establish new TLS connection
        let session = self.tls_client.establish_tls_connection(hostname)?;
        self.current_session = Some(session);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_client_creation() {
        let client = HttpsClient::default();
        assert!(client.is_ok());
    }
}
