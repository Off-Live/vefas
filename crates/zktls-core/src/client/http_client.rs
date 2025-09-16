//! HTTP client implementation for HTTPS client
//!
//! This module provides HTTP request/response handling, form data processing,
//! and commitment generation for the HTTPS client implementation.

use crate::{
    config::HttpsClientConfig,
    errors::ZkTlsResult,
    http::{HttpRequest, HttpResponse, HttpRequestCommitment, HttpResponseCommitment},
    network::NetworkClient,
};
use alloc::{collections::BTreeMap, string::{String, ToString}, vec::Vec, format};
use super::session::TlsSessionInfo;

/// Complete HTTPS response with zkTLS proof data
#[derive(Debug, Clone)]
pub struct HttpsResponse {
    /// Parsed HTTP response
    pub response: HttpResponse,
    /// Commitment to the original HTTP request (32-byte SHA-256)
    pub request_commitment: [u8; 32],
    /// Commitment to the HTTP response (32-byte SHA-256)
    pub response_commitment: [u8; 32],
    /// TLS session information for proof generation
    pub tls_session_info: TlsSessionInfo,
}

impl HttpsResponse {
    /// Get HTTP status code
    pub fn status(&self) -> u16 {
        self.response.status()
    }
    
    /// Check if response indicates success (2xx status)
    pub fn is_success(&self) -> bool {
        self.response.is_success()
    }
    
    /// Get response body
    pub fn body(&self) -> &[u8] {
        self.response.body()
    }
    
    /// Get response header by name
    pub fn header(&self, name: &str) -> Option<&String> {
        self.response.header(name)
    }
    
    /// Get request commitment for zkTLS proof
    pub fn request_commitment(&self) -> &[u8; 32] {
        &self.request_commitment
    }
    
    /// Get response commitment for zkTLS proof
    pub fn response_commitment(&self) -> &[u8; 32] {
        &self.response_commitment
    }
    
    /// Get TLS session information
    pub fn tls_session_info(&self) -> &TlsSessionInfo {
        &self.tls_session_info
    }
}

/// HTTP client for handling requests and responses
pub struct HttpClient {
    /// Client configuration
    config: HttpsClientConfig,
    /// Network client for real communication
    network_client: Option<NetworkClient>,
}

impl HttpClient {
    /// Create a new HTTP client
    pub fn new(config: HttpsClientConfig) -> Self {
        Self {
            config,
            network_client: None,
        }
    }

    /// Make an HTTP GET request
    pub fn get(&mut self, url: &str, session: &TlsSessionInfo) -> ZkTlsResult<HttpsResponse> {
        let (hostname, path) = super::url::parse_url(url)?;
        let request = HttpRequest::get(&path, &hostname)?;
        self.request(request, &hostname, session)
    }

    /// Make an HTTP POST request with JSON body
    pub fn post_json(&mut self, url: &str, json_body: &str, session: &TlsSessionInfo) -> ZkTlsResult<HttpsResponse> {
        let (hostname, path) = super::url::parse_url(url)?;
        let request = HttpRequest::post_json(&path, &hostname, json_body)?;
        self.request(request, &hostname, session)
    }

    /// Make an HTTP POST request with form data
    pub fn post_form(
        &mut self, 
        url: &str, 
        form_data: &BTreeMap<String, String>, 
        session: &TlsSessionInfo
    ) -> ZkTlsResult<HttpsResponse> {
        let (hostname, path) = super::url::parse_url(url)?;
        
        // Encode form data and create POST request
        let encoded_body = super::url::encode_form_data(form_data);
        let mut headers = crate::http::HttpHeaders::new();
        headers.insert("host", &hostname);
        headers.insert("content-type", "application/x-www-form-urlencoded");
        headers.insert("content-length", &encoded_body.len().to_string());
        
        let request = HttpRequest::new(
            crate::http::HttpMethod::Post,
            &path,
            "HTTP/1.1",
            headers,
            encoded_body.into_bytes(),
        )?;
        
        self.request(request, &hostname, session)
    }

    /// Make a custom HTTP request
    pub fn request(
        &mut self, 
        request: HttpRequest, 
        hostname: &str, 
        session: &TlsSessionInfo
    ) -> ZkTlsResult<HttpsResponse> {
        // Use real network communication instead of simulation
        let response = self.send_real_request(&request, hostname)?;
        
        // Generate commitments if enabled
        let (request_commitment, response_commitment) = if self.config.generate_commitments {
            let req_commitment = HttpRequestCommitment::generate(&request)?;
            let resp_commitment = HttpResponseCommitment::generate(&response)?;
            (req_commitment, resp_commitment)
        } else {
            ([0u8; 32], [0u8; 32]) // Zero commitments when disabled
        };
        
        Ok(HttpsResponse {
            response,
            request_commitment,
            response_commitment,
            tls_session_info: session.clone(),
        })
    }
    
    /// Send a real HTTP request using network communication
    fn send_real_request(&mut self, request: &HttpRequest, hostname: &str) -> ZkTlsResult<HttpResponse> {
        // Create or get network client
        if self.network_client.is_none() {
            self.network_client = Some(NetworkClient::new_https(hostname));
        }
        
        let network_client = self.network_client.as_mut().unwrap();
        
        // Use real network communication
        // Note: This is currently a placeholder that returns an error
        // In a real implementation, this would perform actual network communication
        network_client.send_http_request(request)
    }
}
