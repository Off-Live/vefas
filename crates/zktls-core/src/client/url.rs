//! URL parsing and form encoding utilities for HTTPS client
//!
//! This module provides URL parsing, form data encoding, and related utilities
//! for the HTTPS client implementation.

use crate::errors::{ZkTlsError, ZkTlsResult};
use alloc::{collections::BTreeMap, string::{String, ToString}, vec::Vec, format};

/// Parse URL into hostname and path components
pub fn parse_url(url: &str) -> ZkTlsResult<(String, String)> {
    if !url.starts_with("https://") {
        return Err(ZkTlsError::InvalidTlsMessage("URL must start with https://".to_string()));
    }
    
    let url_without_scheme = &url[8..]; // Remove "https://"
    let parts: Vec<&str> = url_without_scheme.splitn(2, '/').collect();
    
    let hostname = parts[0].to_string();
    let path = if parts.len() > 1 {
        format!("/{}", parts[1])
    } else {
        "/".to_string()
    };
    
    Ok((hostname, path))
}

/// Encode form data as application/x-www-form-urlencoded
pub fn encode_form_data(form_data: &BTreeMap<String, String>) -> String {
    form_data
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Simple URL encoding for form data
pub fn url_encode(s: &str) -> String {
    // Simplified URL encoding - in production would use proper encoding
    s.replace(' ', "%20")
     .replace('&', "%26")
     .replace('=', "%3D")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_parsing() {
        let (hostname, path) = parse_url("https://example.com/api/data").unwrap();
        assert_eq!(hostname, "example.com");
        assert_eq!(path, "/api/data");

        let (hostname, path) = parse_url("https://api.test.com").unwrap();
        assert_eq!(hostname, "api.test.com");
        assert_eq!(path, "/");
    }

    #[test]
    fn test_form_data_encoding() {
        let mut form_data = BTreeMap::new();
        form_data.insert("key1".to_string(), "value1".to_string());
        form_data.insert("key2".to_string(), "value with spaces".to_string());
        
        let encoded = encode_form_data(&form_data);
        assert!(encoded.contains("key1=value1"));
        assert!(encoded.contains("key2=value%20with%20spaces"));
    }

    #[test]
    fn test_invalid_url() {
        let result = parse_url("http://example.com");
        assert!(result.is_err());
    }
}
