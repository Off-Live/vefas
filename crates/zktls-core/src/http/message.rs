//! HTTP Message Compatibility Layer
//!
//! This module provides the legacy `HttpMessage` interface for backward compatibility
//! with existing code while leveraging the new modular HTTP implementation.
//!
//! The `HttpMessage` type wraps the new `HttpRequest` and `HttpResponse` types
//! to maintain API compatibility during the refactoring transition.

use super::{HttpRequest, HttpResponse, HttpHeaders, HttpMethod, HttpStatusCode};
use crate::errors::ZkTlsError;
use alloc::{collections::BTreeMap, string::String, vec::Vec};

/// Legacy HTTP Message interface for backward compatibility
/// 
/// This enum wraps the new `HttpRequest` and `HttpResponse` types while
/// maintaining the original API surface for existing tests and code.
#[derive(Debug, Clone)]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
}

impl HttpMessage {
    /// Parse an HTTP request from raw bytes (legacy interface)
    pub fn parse_request(data: &[u8]) -> Result<Self, ZkTlsError> {
        let request = HttpRequest::parse(data)?;
        Ok(HttpMessage::Request(request))
    }

    /// Parse an HTTP response from raw bytes (legacy interface)
    pub fn parse_response(data: &[u8]) -> Result<Self, ZkTlsError> {
        let response = HttpResponse::parse(data)?;
        Ok(HttpMessage::Response(response))
    }

    /// Create a new HTTP request (legacy interface)
    pub fn request(
        method: &str,
        path: &str,
        version: &str,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    ) -> Self {
        let http_method = HttpMethod::from_str(method);
        let http_headers = HttpHeaders::from_map(headers);
        
        // Create request with error handling - if it fails, create a minimal valid request
        let request = HttpRequest::new(http_method, path, version, http_headers, body)
            .unwrap_or_else(|_| {
                // Fallback: create minimal GET request
                let mut fallback_headers = HttpHeaders::new();
                fallback_headers.insert("host", "localhost");
                HttpRequest::new(
                    HttpMethod::Get,
                    "/",
                    "HTTP/1.1",
                    fallback_headers,
                    Vec::new(),
                ).expect("Fallback request creation failed")
            });
        
        HttpMessage::Request(request)
    }

    /// Create a new HTTP response (legacy interface)
    pub fn response(
        version: &str,
        status_code: u16,
        reason_phrase: &str,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    ) -> Self {
        let http_status = HttpStatusCode::new(status_code);
        let http_headers = HttpHeaders::from_map(headers);
        
        // Create response with error handling
        let response = HttpResponse::new(version, http_status, reason_phrase, http_headers, body)
            .unwrap_or_else(|_| {
                // Fallback: create minimal 200 OK response
                let mut fallback_headers = HttpHeaders::new();
                fallback_headers.insert("content-length", "0");
                HttpResponse::new(
                    "HTTP/1.1",
                    HttpStatusCode::OK,
                    "OK",
                    fallback_headers,
                    Vec::new(),
                ).expect("Fallback response creation failed")
            });
        
        HttpMessage::Response(response)
    }

    /// Serialize message to HTTP wire format (legacy interface)
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            HttpMessage::Request(req) => req.serialize(),
            HttpMessage::Response(resp) => resp.serialize(),
        }
    }

    /// Get HTTP method (requests only, legacy interface)
    pub fn method(&self) -> &str {
        match self {
            HttpMessage::Request(req) => req.method().as_str(),
            HttpMessage::Response(_) => "", // Not applicable for responses
        }
    }

    /// Get request path (requests only, legacy interface)
    pub fn path(&self) -> &str {
        match self {
            HttpMessage::Request(req) => req.path(),
            HttpMessage::Response(_) => "", // Not applicable for responses
        }
    }

    /// Get HTTP version (legacy interface)
    pub fn version(&self) -> &str {
        match self {
            HttpMessage::Request(req) => req.version(),
            HttpMessage::Response(resp) => resp.version(),
        }
    }

    /// Get status code (responses only, legacy interface)
    pub fn status_code(&self) -> u16 {
        match self {
            HttpMessage::Request(_) => 0, // Not applicable for requests
            HttpMessage::Response(resp) => resp.status(),
        }
    }

    /// Get reason phrase (responses only, legacy interface)
    pub fn reason_phrase(&self) -> &str {
        match self {
            HttpMessage::Request(_) => "", // Not applicable for requests
            HttpMessage::Response(resp) => resp.reason_phrase(),
        }
    }

    /// Get header value by name (legacy interface)
    pub fn header(&self, name: &str) -> Option<&str> {
        let header_value = match self {
            HttpMessage::Request(req) => req.header(name),
            HttpMessage::Response(resp) => resp.header(name),
        };
        header_value.map(|s| s.as_str())
    }

    /// Get message body (legacy interface)
    pub fn body(&self) -> &[u8] {
        match self {
            HttpMessage::Request(req) => req.body(),
            HttpMessage::Response(resp) => resp.body(),
        }
    }

    /// Check if this is a request message
    pub fn is_request(&self) -> bool {
        matches!(self, HttpMessage::Request(_))
    }

    /// Check if this is a response message
    pub fn is_response(&self) -> bool {
        matches!(self, HttpMessage::Response(_))
    }

    /// Get the underlying request (if this is a request)
    pub fn as_request(&self) -> Option<&HttpRequest> {
        match self {
            HttpMessage::Request(req) => Some(req),
            HttpMessage::Response(_) => None,
        }
    }

    /// Get the underlying response (if this is a response)
    pub fn as_response(&self) -> Option<&HttpResponse> {
        match self {
            HttpMessage::Request(_) => None,
            HttpMessage::Response(resp) => Some(resp),
        }
    }

    /// Get mutable reference to the underlying request (if this is a request)
    pub fn as_request_mut(&mut self) -> Option<&mut HttpRequest> {
        match self {
            HttpMessage::Request(req) => Some(req),
            HttpMessage::Response(_) => None,
        }
    }

    /// Get mutable reference to the underlying response (if this is a response)  
    pub fn as_response_mut(&mut self) -> Option<&mut HttpResponse> {
        match self {
            HttpMessage::Request(_) => None,
            HttpMessage::Response(resp) => Some(resp),
        }
    }

    /// Set a header value (legacy interface)
    pub fn set_header(&mut self, name: &str, value: &str) -> Result<(), ZkTlsError> {
        match self {
            HttpMessage::Request(req) => req.set_header(name, value),
            HttpMessage::Response(resp) => resp.set_header(name, value),
        }
    }

    /// Remove a header (legacy interface)
    pub fn remove_header(&mut self, name: &str) {
        match self {
            HttpMessage::Request(req) => req.remove_header(name),
            HttpMessage::Response(resp) => resp.remove_header(name),
        }
    }

    /// Set message body (legacy interface)
    pub fn set_body(&mut self, body: Vec<u8>) -> Result<(), ZkTlsError> {
        match self {
            HttpMessage::Request(req) => req.set_body(body),
            HttpMessage::Response(resp) => resp.set_body(body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, string::ToString};

    #[test]
    fn test_legacy_request_interface() {
        let mut headers = BTreeMap::new();
        headers.insert("Host".to_string(), "example.com".to_string());
        headers.insert("User-Agent".to_string(), "test".to_string());

        let message = HttpMessage::request("GET", "/test", "HTTP/1.1", headers, vec![]);
        
        assert!(message.is_request());
        assert_eq!(message.method(), "GET");
        assert_eq!(message.path(), "/test");
        assert_eq!(message.version(), "HTTP/1.1");
        assert_eq!(message.header("host"), Some("example.com"));
    }

    #[test]
    fn test_legacy_response_interface() {
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".to_string(), "text/plain".to_string());

        let message = HttpMessage::response("HTTP/1.1", 200, "OK", headers, b"Hello".to_vec());
        
        assert!(message.is_response());
        assert_eq!(message.status_code(), 200);
        assert_eq!(message.reason_phrase(), "OK");
        assert_eq!(message.version(), "HTTP/1.1");
        assert_eq!(message.body(), b"Hello");
    }

    #[test]
    fn test_legacy_parsing() {
        // Test request parsing
        let request_data = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let message = HttpMessage::parse_request(request_data).unwrap();
        assert!(message.is_request());
        assert_eq!(message.method(), "GET");
        assert_eq!(message.path(), "/test");

        // Test response parsing
        let response_data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
        let message = HttpMessage::parse_response(response_data).unwrap();
        assert!(message.is_response());
        assert_eq!(message.status_code(), 200);
        assert_eq!(message.body(), b"Hello");
    }

    #[test]
    fn test_serialization_compatibility() {
        // Test that serialization works with the legacy interface
        let mut headers = BTreeMap::new();
        headers.insert("Content-Length".to_string(), "4".to_string());
        
        let message = HttpMessage::response("HTTP/1.1", 200, "OK", headers, b"test".to_vec());
        let serialized = message.serialize();
        
        // Should be able to parse it back
        let parsed = HttpMessage::parse_response(&serialized).unwrap();
        assert_eq!(parsed.body(), b"test");
        assert_eq!(parsed.status_code(), 200);
    }
}