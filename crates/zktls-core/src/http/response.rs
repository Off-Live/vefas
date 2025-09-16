//! HTTP Response Parser
//!
//! This module provides functionality for parsing HTTP/1.1 responses
//! optimized for zkVM execution environments.
//!
//! Key features:
//! - HTTP/1.1 response parsing following RFC 7230
//! - Status code validation and standard codes
//! - Chunked transfer encoding support 
//! - Memory-efficient parsing suitable for zero-knowledge proofs
//! - Content-Length handling and validation

use super::headers::HttpHeaders;
use crate::errors::ZkTlsError;
use alloc::{collections::BTreeMap, format, string::{String, ToString}, vec::Vec};

/// HTTP Status Codes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpStatusCode(pub u16);

impl HttpStatusCode {
    /// Common HTTP status codes
    pub const OK: HttpStatusCode = HttpStatusCode(200);
    pub const CREATED: HttpStatusCode = HttpStatusCode(201);
    pub const NO_CONTENT: HttpStatusCode = HttpStatusCode(204);
    pub const MOVED_PERMANENTLY: HttpStatusCode = HttpStatusCode(301);
    pub const FOUND: HttpStatusCode = HttpStatusCode(302);
    pub const NOT_MODIFIED: HttpStatusCode = HttpStatusCode(304);
    pub const BAD_REQUEST: HttpStatusCode = HttpStatusCode(400);
    pub const UNAUTHORIZED: HttpStatusCode = HttpStatusCode(401);
    pub const FORBIDDEN: HttpStatusCode = HttpStatusCode(403);
    pub const NOT_FOUND: HttpStatusCode = HttpStatusCode(404);
    pub const METHOD_NOT_ALLOWED: HttpStatusCode = HttpStatusCode(405);
    pub const INTERNAL_SERVER_ERROR: HttpStatusCode = HttpStatusCode(500);
    pub const NOT_IMPLEMENTED: HttpStatusCode = HttpStatusCode(501);
    pub const BAD_GATEWAY: HttpStatusCode = HttpStatusCode(502);
    pub const SERVICE_UNAVAILABLE: HttpStatusCode = HttpStatusCode(503);

    /// Create status code from u16
    pub fn new(code: u16) -> Self {
        Self(code)
    }

    /// Get status code as u16
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// Check if status code indicates success (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0)
    }

    /// Check if status code indicates redirection (3xx)
    pub fn is_redirection(&self) -> bool {
        (300..400).contains(&self.0)
    }

    /// Check if status code indicates client error (4xx)
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.0)
    }

    /// Check if status code indicates server error (5xx)
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.0)
    }

    /// Check if status code indicates error (4xx or 5xx)
    pub fn is_error(&self) -> bool {
        self.is_client_error() || self.is_server_error()
    }

    /// Get default reason phrase for status code
    pub fn default_reason_phrase(&self) -> &'static str {
        match self.0 {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            _ => "Unknown",
        }
    }
}

/// HTTP Response representation optimized for zkVM
#[derive(Debug, Clone)]
pub struct HttpResponse {
    version: String,
    status_code: HttpStatusCode,
    reason_phrase: String,
    headers: HttpHeaders,
    body: Vec<u8>,
}

impl HttpResponse {
    /// Create a new HTTP response
    pub fn new(
        version: &str,
        status_code: HttpStatusCode,
        reason_phrase: &str,
        headers: HttpHeaders,
        body: Vec<u8>,
    ) -> Result<Self, ZkTlsError> {
        // Validate HTTP version
        if !version.starts_with("HTTP/1.") {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Unsupported HTTP version: {}", version)
            ));
        }

        let mut response = Self {
            version: version.to_string(),
            status_code,
            reason_phrase: reason_phrase.to_string(),
            headers,
            body,
        };

        // Auto-set Content-Length if body is present and not chunked
        if !response.body.is_empty() && !response.headers.is_chunked() {
            response.headers.insert("content-length", &response.body.len().to_string());
        }

        // Validate headers
        response.headers.validate()?;

        Ok(response)
    }

    /// Create a simple 200 OK response
    pub fn ok(body: &str, content_type: &str) -> Result<Self, ZkTlsError> {
        let mut headers = HttpHeaders::new();
        headers.insert("content-type", content_type);
        headers.insert("connection", "close");

        Self::new(
            "HTTP/1.1",
            HttpStatusCode::OK,
            "OK",
            headers,
            body.as_bytes().to_vec(),
        )
    }

    /// Create a JSON response
    pub fn json(status_code: HttpStatusCode, json_body: &str) -> Result<Self, ZkTlsError> {
        let mut headers = HttpHeaders::new();
        headers.insert("content-type", "application/json");
        headers.insert("connection", "close");

        let reason_phrase = status_code.default_reason_phrase();
        Self::new(
            "HTTP/1.1",
            status_code,
            reason_phrase,
            headers,
            json_body.as_bytes().to_vec(),
        )
    }

    /// Parse an HTTP response from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        let data_str = core::str::from_utf8(data)
            .map_err(|_| ZkTlsError::InvalidTlsMessage("Invalid UTF-8 in HTTP response".into()))?;
        
        // Split headers and body - must have the headers terminator
        if !data_str.contains("\r\n\r\n") {
            return Err(ZkTlsError::InvalidTlsMessage("Missing HTTP headers terminator".into()));
        }
        
        let mut parts = data_str.splitn(2, "\r\n\r\n");
        let headers_part = parts.next()
            .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Missing HTTP headers".into()))?;
        let body_part = parts.next().unwrap_or("").as_bytes();
        
        // Parse status line and headers
        let mut lines = headers_part.lines();
        let status_line = lines.next()
            .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Missing HTTP status line".into()))?;
        
        // Parse status line: VERSION STATUS_CODE REASON_PHRASE
        let mut status_parts = status_line.splitn(3, ' ');
        let version = status_parts.next()
            .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Missing HTTP version".into()))?;
        let status_code_str = status_parts.next()
            .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Missing HTTP status code".into()))?;
        let reason_phrase = status_parts.next().unwrap_or("");
        
        // Validate and parse status code
        let status_code_num = status_code_str.parse::<u16>()
            .map_err(|_| ZkTlsError::InvalidTlsMessage("Invalid HTTP status code".into()))?;
        let status_code = HttpStatusCode::new(status_code_num);
        
        // Parse headers
        let mut header_map = BTreeMap::new();
        for line in lines {
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                header_map.insert(key, value);
            }
        }
        
        let headers = HttpHeaders::from_map(header_map);
        
        // Handle body based on Content-Length or Transfer-Encoding
        let body = if headers.is_chunked() {
            Self::parse_chunked_body(body_part)?
        } else if let Some(content_length) = headers.content_length() {
            body_part.get(..content_length).unwrap_or(body_part).to_vec()
        } else {
            body_part.to_vec()
        };
        
        Self::new(version, status_code, reason_phrase, headers, body)
    }

    /// Serialize response to HTTP wire format
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = format!(
            "{} {} {}\r\n",
            self.version,
            self.status_code.as_u16(),
            self.reason_phrase
        );
        
        result.push_str(&self.headers.serialize());
        result.push_str("\r\n");
        
        let mut bytes = result.into_bytes();
        bytes.extend_from_slice(&self.body);
        
        bytes
    }

    /// Parse chunked transfer encoding body
    fn parse_chunked_body(data: &[u8]) -> Result<Vec<u8>, ZkTlsError> {
        let mut body = Vec::new();
        let mut pos = 0;
        
        while pos < data.len() {
            // Find the end of the chunk size line
            let newline_pos = data[pos..].iter().position(|&b| b == b'\r')
                .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Invalid chunked encoding".into()))?;
            
            // Parse chunk size (hex)
            let chunk_size_str = core::str::from_utf8(&data[pos..pos + newline_pos])
                .map_err(|_| ZkTlsError::InvalidTlsMessage("Invalid chunk size encoding".into()))?;
            
            let chunk_size = usize::from_str_radix(chunk_size_str.trim(), 16)
                .map_err(|_| ZkTlsError::InvalidTlsMessage("Invalid chunk size format".into()))?;
            
            pos += newline_pos + 2; // Skip \r\n
            
            if chunk_size == 0 {
                break; // End of chunks
            }
            
            // Read chunk data
            if pos + chunk_size > data.len() {
                return Err(ZkTlsError::InvalidTlsMessage("Incomplete chunk data".into()));
            }
            
            body.extend_from_slice(&data[pos..pos + chunk_size]);
            pos += chunk_size + 2; // Skip chunk data and \r\n
        }
        
        Ok(body)
    }

    /// Get HTTP version
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Get status code
    pub fn status_code(&self) -> &HttpStatusCode {
        &self.status_code
    }

    /// Get status code as u16
    pub fn status(&self) -> u16 {
        self.status_code.as_u16()
    }

    /// Get reason phrase
    pub fn reason_phrase(&self) -> &str {
        &self.reason_phrase
    }

    /// Get headers
    pub fn headers(&self) -> &HttpHeaders {
        &self.headers
    }

    /// Get mutable headers
    pub fn headers_mut(&mut self) -> &mut HttpHeaders {
        &mut self.headers
    }

    /// Get specific header value
    pub fn header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }

    /// Get response body
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Get response body as string (if valid UTF-8)
    pub fn body_str(&self) -> Result<&str, core::str::Utf8Error> {
        core::str::from_utf8(&self.body)
    }

    /// Set response body and update Content-Length
    pub fn set_body(&mut self, body: Vec<u8>) -> Result<(), ZkTlsError> {
        self.body = body;
        
        // Update Content-Length if not chunked
        if !self.headers.is_chunked() {
            self.headers.insert("content-length", &self.body.len().to_string());
        }
        
        self.headers.validate()
    }

    /// Add or update a header
    pub fn set_header(&mut self, name: &str, value: &str) -> Result<(), ZkTlsError> {
        self.headers.insert(name, value);
        self.headers.validate()
    }

    /// Remove a header
    pub fn remove_header(&mut self, name: &str) {
        self.headers.remove(name);
    }

    /// Get content length from headers or body size
    pub fn content_length(&self) -> usize {
        self.headers.content_length().unwrap_or(self.body.len())
    }

    /// Check if response uses chunked transfer encoding
    pub fn is_chunked(&self) -> bool {
        self.headers.is_chunked()
    }

    /// Check if response indicates successful request
    pub fn is_success(&self) -> bool {
        self.status_code.is_success()
    }

    /// Check if response indicates error
    pub fn is_error(&self) -> bool {
        self.status_code.is_error()
    }

    /// Check if response indicates redirection
    pub fn is_redirect(&self) -> bool {
        self.status_code.is_redirection()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code_categories() {
        assert!(HttpStatusCode::OK.is_success());
        assert!(HttpStatusCode::NOT_FOUND.is_client_error());
        assert!(HttpStatusCode::INTERNAL_SERVER_ERROR.is_server_error());
        assert!(HttpStatusCode::FOUND.is_redirection());
    }

    #[test]
    fn test_ok_response_creation() {
        let response = HttpResponse::ok("Hello World", "text/plain").unwrap();
        
        assert_eq!(response.status(), 200);
        assert_eq!(response.body_str().unwrap(), "Hello World");
        assert_eq!(response.header("content-type"), Some(&"text/plain".to_string()));
    }

    #[test]
    fn test_json_response_creation() {
        let response = HttpResponse::json(HttpStatusCode::OK, r#"{"status":"ok"}"#).unwrap();
        
        assert_eq!(response.status(), 200);
        assert_eq!(response.header("content-type"), Some(&"application/json".to_string()));
        assert_eq!(response.body_str().unwrap(), r#"{"status":"ok"}"#);
    }

    #[test]
    fn test_response_parsing() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!";
        let response = HttpResponse::parse(raw).unwrap();
        
        assert_eq!(response.status(), 200);
        assert_eq!(response.reason_phrase(), "OK");
        assert_eq!(response.body_str().unwrap(), "Hello, World!");
    }

    #[test]
    fn test_chunked_response_parsing() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n7\r\n World!\r\n0\r\n\r\n";
        let response = HttpResponse::parse(raw).unwrap();
        
        assert_eq!(response.body_str().unwrap(), "Hello World!");
    }

    #[test]
    fn test_response_serialization() {
        let response = HttpResponse::ok("test", "text/plain").unwrap();
        let serialized = response.serialize();
        let parsed = HttpResponse::parse(&serialized).unwrap();
        
        assert_eq!(parsed.status(), 200);
        assert_eq!(parsed.body_str().unwrap(), "test");
    }
}