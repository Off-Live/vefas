//! HTTP Header Handling
//!
//! This module provides functionality for parsing, storing, and manipulating
//! HTTP headers with case-insensitive key handling optimized for zkVM environments.
//!
//! Key features:
//! - Case-insensitive header keys following RFC 7230
//! - Memory-efficient storage using BTreeMap
//! - Standard header constants and utilities
//! - Validation for common headers like Content-Length, Transfer-Encoding

use alloc::{collections::BTreeMap, format, string::{String, ToString}, vec::Vec};
use crate::errors::ZkTlsError;

/// HTTP Headers container with case-insensitive key access
/// 
/// Uses BTreeMap for deterministic iteration order required in zkVM environments.
/// All header names are normalized to lowercase for consistent access.
#[derive(Debug, Clone, Default)]
pub struct HttpHeaders {
    headers: BTreeMap<String, String>,
}

impl HttpHeaders {
    /// Create a new empty headers container
    pub fn new() -> Self {
        Self {
            headers: BTreeMap::new(),
        }
    }

    /// Create headers from a BTreeMap
    pub fn from_map(headers: BTreeMap<String, String>) -> Self {
        let mut normalized = BTreeMap::new();
        for (key, value) in headers {
            normalized.insert(key.to_lowercase(), value);
        }
        Self { headers: normalized }
    }

    /// Insert a header with case-insensitive key
    pub fn insert(&mut self, name: &str, value: &str) {
        self.headers.insert(name.to_lowercase(), value.to_string());
    }

    /// Get a header value by case-insensitive key
    pub fn get(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }

    /// Check if a header exists
    pub fn contains_key(&self, name: &str) -> bool {
        self.headers.contains_key(&name.to_lowercase())
    }

    /// Remove a header by case-insensitive key
    pub fn remove(&mut self, name: &str) -> Option<String> {
        self.headers.remove(&name.to_lowercase())
    }

    /// Get iterator over all headers
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.headers.iter()
    }

    /// Get the number of headers
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Check if headers container is empty
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Clear all headers
    pub fn clear(&mut self) {
        self.headers.clear();
    }

    /// Get Content-Length as parsed integer
    pub fn content_length(&self) -> Option<usize> {
        self.get("content-length")?
            .parse()
            .ok()
    }

    /// Check if Transfer-Encoding is chunked
    pub fn is_chunked(&self) -> bool {
        self.get("transfer-encoding")
            .map(|v| v.to_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    /// Get Connection header value
    pub fn connection(&self) -> Option<&String> {
        self.get("connection")
    }

    /// Check if Connection header indicates keep-alive
    pub fn is_keep_alive(&self) -> bool {
        self.connection()
            .map(|v| v.to_lowercase().contains("keep-alive"))
            .unwrap_or(false)
    }

    /// Get Host header value
    pub fn host(&self) -> Option<&String> {
        self.get("host")
    }

    /// Get Content-Type header value
    pub fn content_type(&self) -> Option<&String> {
        self.get("content-type")
    }

    /// Get User-Agent header value
    pub fn user_agent(&self) -> Option<&String> {
        self.get("user-agent")
    }

    /// Validate common headers for correctness
    pub fn validate(&self) -> Result<(), ZkTlsError> {
        // Validate Content-Length if present
        if let Some(cl) = self.get("content-length") {
            cl.parse::<usize>()
                .map_err(|_| ZkTlsError::InvalidTlsMessage(
                    "Invalid Content-Length header value".into()
                ))?;
        }

        // Ensure Transfer-Encoding and Content-Length are not both present
        // (RFC 7230 Section 3.3.3)
        if self.is_chunked() && self.content_length().is_some() {
            return Err(ZkTlsError::InvalidTlsMessage(
                "Both Transfer-Encoding: chunked and Content-Length present".into()
            ));
        }

        Ok(())
    }

    /// Serialize headers to HTTP wire format
    pub fn serialize(&self) -> String {
        let mut result = String::new();
        for (name, value) in &self.headers {
            // Convert header names back to title case for wire format
            let title_case = title_case_header(name);
            result.push_str(&format!("{}: {}\r\n", title_case, value));
        }
        result
    }
}

/// Convert lowercase header name to title case for wire format
/// Examples: "content-type" -> "Content-Type", "user-agent" -> "User-Agent"
fn title_case_header(name: &str) -> String {
    name.split('-')
        .map(|word| {
            let mut chars: Vec<char> = word.chars().collect();
            if !chars.is_empty() {
                chars[0] = chars[0].to_uppercase().next().unwrap_or(chars[0]);
            }
            chars.into_iter().collect::<String>()
        })
        .collect::<Vec<String>>()
        .join("-")
}

// Standard HTTP header constants
pub mod headers {
    pub const ACCEPT: &str = "Accept";
    pub const ACCEPT_ENCODING: &str = "Accept-Encoding";
    pub const ACCEPT_LANGUAGE: &str = "Accept-Language";
    pub const AUTHORIZATION: &str = "Authorization";
    pub const CACHE_CONTROL: &str = "Cache-Control";
    pub const CONNECTION: &str = "Connection";
    pub const CONTENT_ENCODING: &str = "Content-Encoding";
    pub const CONTENT_LENGTH: &str = "Content-Length";
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const COOKIE: &str = "Cookie";
    pub const DATE: &str = "Date";
    pub const ETAG: &str = "ETag";
    pub const EXPIRES: &str = "Expires";
    pub const HOST: &str = "Host";
    pub const IF_MODIFIED_SINCE: &str = "If-Modified-Since";
    pub const IF_NONE_MATCH: &str = "If-None-Match";
    pub const LAST_MODIFIED: &str = "Last-Modified";
    pub const LOCATION: &str = "Location";
    pub const PRAGMA: &str = "Pragma";
    pub const REFERER: &str = "Referer";
    pub const SERVER: &str = "Server";
    pub const SET_COOKIE: &str = "Set-Cookie";
    pub const TRANSFER_ENCODING: &str = "Transfer-Encoding";
    pub const USER_AGENT: &str = "User-Agent";
    pub const X_FORWARDED_FOR: &str = "X-Forwarded-For";
    pub const X_REAL_IP: &str = "X-Real-IP";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_insensitive_access() {
        let mut headers = HttpHeaders::new();
        headers.insert("Content-Type", "application/json");
        
        assert_eq!(headers.get("content-type"), Some(&"application/json".to_string()));
        assert_eq!(headers.get("CONTENT-TYPE"), Some(&"application/json".to_string()));
        assert_eq!(headers.get("Content-Type"), Some(&"application/json".to_string()));
    }

    #[test]
    fn test_content_length_parsing() {
        let mut headers = HttpHeaders::new();
        headers.insert("Content-Length", "1234");
        
        assert_eq!(headers.content_length(), Some(1234));
    }

    #[test]
    fn test_chunked_detection() {
        let mut headers = HttpHeaders::new();
        headers.insert("Transfer-Encoding", "chunked");
        
        assert!(headers.is_chunked());
    }

    #[test]
    fn test_title_case_conversion() {
        assert_eq!(title_case_header("content-type"), "Content-Type");
        assert_eq!(title_case_header("user-agent"), "User-Agent");
        assert_eq!(title_case_header("x-forwarded-for"), "X-Forwarded-For");
    }

    #[test]
    fn test_validation() {
        let mut headers = HttpHeaders::new();
        headers.insert("Content-Length", "invalid");
        assert!(headers.validate().is_err());

        headers.clear();
        headers.insert("Content-Length", "100");
        headers.insert("Transfer-Encoding", "chunked");
        assert!(headers.validate().is_err());
    }
}