//! HTTP Request Builder and Parser
//!
//! This module provides functionality for building and parsing HTTP/1.1 requests
//! optimized for zkVM execution environments.
//!
//! Key features:
//! - HTTP/1.1 request parsing following RFC 7230
//! - Request building with proper method and URI validation
//! - Memory-efficient parsing suitable for zero-knowledge proofs
//! - Support for common HTTP methods (GET, POST, PUT, DELETE, etc.)
//! - URL encoding and validation

use super::headers::HttpHeaders;
use crate::errors::ZkTlsError;
use alloc::{collections::BTreeMap, format, string::{String, ToString}, vec::Vec};

/// HTTP Methods supported in zkTLS
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Connect,
    Trace,
    Custom(String),
}

impl HttpMethod {
    /// Parse HTTP method from string
    pub fn from_str(method: &str) -> Self {
        match method.to_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "DELETE" => HttpMethod::Delete,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            "PATCH" => HttpMethod::Patch,
            "CONNECT" => HttpMethod::Connect,
            "TRACE" => HttpMethod::Trace,
            _ => HttpMethod::Custom(method.to_string()),
        }
    }

    /// Convert HTTP method to string
    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Connect => "CONNECT",
            HttpMethod::Trace => "TRACE",
            HttpMethod::Custom(method) => method,
        }
    }

    /// Check if method typically has a request body
    pub fn has_body(&self) -> bool {
        matches!(self, HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch | HttpMethod::Custom(_))
    }
}

/// HTTP Request representation optimized for zkVM
#[derive(Debug, Clone)]
pub struct HttpRequest {
    method: HttpMethod,
    path: String,
    version: String,
    headers: HttpHeaders,
    body: Vec<u8>,
}

impl HttpRequest {
    /// Create a new HTTP request
    pub fn new(
        method: HttpMethod,
        path: &str,
        version: &str,
        headers: HttpHeaders,
        body: Vec<u8>,
    ) -> Result<Self, ZkTlsError> {
        // Validate HTTP version
        if !version.starts_with("HTTP/1.") {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Unsupported HTTP version: {}", version)
            ));
        }

        // Validate path (basic URL validation)
        if path.is_empty() || !path.starts_with('/') {
            return Err(ZkTlsError::InvalidTlsMessage(
                "Invalid HTTP path: must start with '/'".into()
            ));
        }

        let mut request = Self {
            method,
            path: path.to_string(),
            version: version.to_string(),
            headers,
            body,
        };

        // Auto-set Content-Length if body is present and not chunked
        if !request.body.is_empty() && !request.headers.is_chunked() {
            request.headers.insert("content-length", &request.body.len().to_string());
        }

        // Validate headers
        request.headers.validate()?;

        Ok(request)
    }

    /// Create a simple GET request
    pub fn get(path: &str, host: &str) -> Result<Self, ZkTlsError> {
        let mut headers = HttpHeaders::new();
        headers.insert("host", host);
        headers.insert("connection", "close");

        Self::new(
            HttpMethod::Get,
            path,
            "HTTP/1.1",
            headers,
            Vec::new(),
        )
    }

    /// Create a POST request with JSON body
    pub fn post_json(path: &str, host: &str, json_body: &str) -> Result<Self, ZkTlsError> {
        let mut headers = HttpHeaders::new();
        headers.insert("host", host);
        headers.insert("content-type", "application/json");
        headers.insert("connection", "close");

        Self::new(
            HttpMethod::Post,
            path,
            "HTTP/1.1",
            headers,
            json_body.as_bytes().to_vec(),
        )
    }

    /// Parse an HTTP request from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        let data_str = core::str::from_utf8(data)
            .map_err(|_| ZkTlsError::InvalidTlsMessage("Invalid UTF-8 in HTTP request".into()))?;
        
        // Split headers and body - must have the headers terminator
        if !data_str.contains("\r\n\r\n") {
            return Err(ZkTlsError::InvalidTlsMessage("Missing HTTP headers terminator".into()));
        }
        
        let mut parts = data_str.splitn(2, "\r\n\r\n");
        let headers_part = parts.next()
            .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Missing HTTP headers".into()))?;
        let body_part = parts.next().unwrap_or("").as_bytes().to_vec();
        
        // Parse request line and headers
        let mut lines = headers_part.lines();
        let request_line = lines.next()
            .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Missing HTTP request line".into()))?;
        
        // Parse request line: METHOD PATH VERSION
        let mut request_parts = request_line.split_whitespace();
        let method_str = request_parts.next()
            .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Missing HTTP method".into()))?;
        let path = request_parts.next()
            .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Missing HTTP path".into()))?;
        let version = request_parts.next()
            .ok_or_else(|| ZkTlsError::InvalidTlsMessage("Missing HTTP version".into()))?;
        
        let method = HttpMethod::from_str(method_str);
        
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
        
        Self::new(method, path, version, headers, body_part)
    }

    /// Serialize request to HTTP wire format
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = format!(
            "{} {} {}\r\n",
            self.method.as_str(),
            self.path,
            self.version
        );
        
        result.push_str(&self.headers.serialize());
        result.push_str("\r\n");
        
        let mut bytes = result.into_bytes();
        bytes.extend_from_slice(&self.body);
        
        bytes
    }

    /// Get request method
    pub fn method(&self) -> &HttpMethod {
        &self.method
    }

    /// Get request path
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get HTTP version
    pub fn version(&self) -> &str {
        &self.version
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

    /// Get request body
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Set request body and update Content-Length
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

    /// Check if request uses chunked transfer encoding
    pub fn is_chunked(&self) -> bool {
        self.headers.is_chunked()
    }

    /// Check if request indicates keep-alive connection
    pub fn is_keep_alive(&self) -> bool {
        self.headers.is_keep_alive()
    }
}

/// URL encoding utilities
pub mod url {
    use alloc::{format, string::String, vec::Vec};

    /// URL-encode a string
    pub fn encode(input: &str) -> String {
        let mut result = String::new();
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                _ => {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
        result
    }

    /// URL-decode a string
    pub fn decode(input: &str) -> Result<String, &'static str> {
        let mut result = Vec::new();
        let mut chars = input.chars();
        
        while let Some(ch) = chars.next() {
            match ch {
                '%' => {
                    let hex_chars: String = chars.by_ref().take(2).collect();
                    if hex_chars.len() != 2 {
                        return Err("Invalid URL encoding: incomplete percent sequence");
                    }
                    let byte = u8::from_str_radix(&hex_chars, 16)
                        .map_err(|_| "Invalid URL encoding: invalid hex digits")?;
                    result.push(byte);
                }
                '+' => result.push(b' '),
                _ => result.push(ch as u8),
            }
        }
        
        String::from_utf8(result)
            .map_err(|_| "Invalid URL encoding: invalid UTF-8")
    }

    /// Parse query parameters from URL query string
    pub fn parse_query(query: &str) -> Vec<(String, String)> {
        let mut params = Vec::new();
        
        for pair in query.split('&') {
            if let Some(eq_pos) = pair.find('=') {
                let key = &pair[..eq_pos];
                let value = &pair[eq_pos + 1..];
                
                if let (Ok(decoded_key), Ok(decoded_value)) = (decode(key), decode(value)) {
                    params.push((decoded_key, decoded_value));
                }
            } else if let Ok(decoded_key) = decode(pair) {
                params.push((decoded_key, String::new()));
            }
        }
        
        params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_parsing() {
        assert_eq!(HttpMethod::from_str("GET"), HttpMethod::Get);
        assert_eq!(HttpMethod::from_str("post"), HttpMethod::Post);
        assert_eq!(HttpMethod::from_str("CUSTOM"), HttpMethod::Custom("CUSTOM".to_string()));
    }

    #[test]
    fn test_simple_get_request() {
        let request = HttpRequest::get("/", "example.com").unwrap();
        
        assert_eq!(request.method(), &HttpMethod::Get);
        assert_eq!(request.path(), "/");
        assert_eq!(request.header("host"), Some(&"example.com".to_string()));
    }

    #[test]
    fn test_post_json_request() {
        let request = HttpRequest::post_json("/api", "example.com", r#"{"key":"value"}"#).unwrap();
        
        assert_eq!(request.method(), &HttpMethod::Post);
        assert_eq!(request.header("content-type"), Some(&"application/json".to_string()));
        assert_eq!(request.body(), br#"{"key":"value"}"#);
    }

    #[test]
    fn test_request_parsing() {
        let raw = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let request = HttpRequest::parse(raw).unwrap();
        
        assert_eq!(request.method(), &HttpMethod::Get);
        assert_eq!(request.path(), "/path");
        assert_eq!(request.header("host"), Some(&"example.com".to_string()));
    }

    #[test]
    fn test_url_encoding() {
        assert_eq!(url::encode("hello world"), "hello%20world");
        assert_eq!(url::decode("hello%20world").unwrap(), "hello world");
    }

    #[test]
    fn test_query_parsing() {
        let params = url::parse_query("key1=value1&key2=value2&key3");
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], ("key1".to_string(), "value1".to_string()));
        assert_eq!(params[2], ("key3".to_string(), String::new()));
    }
}