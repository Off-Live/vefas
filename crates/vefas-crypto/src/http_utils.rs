//! HTTP processing utilities for VEFAS
//!
//! This module provides HTTP message parsing and validation capabilities
//! that can be shared across different zkVM platforms. All parsing operations
//! include comprehensive validation to ensure secure operation in
//! zero-knowledge contexts.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use vefas_types::{VefasError, VefasResult};

/// Parsed HTTP request data
#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Parsed HTTP response data
#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Combined HTTP request and response data
#[derive(Debug, Clone)]
pub struct HttpData {
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

impl HttpData {
    /// Create new HttpData
    pub fn new(request: Vec<u8>, response: Vec<u8>) -> Self {
        Self { request, response }
    }
}

/// Parse HTTP request and response data to extract key information
pub fn parse_http_data(http_data: &HttpData) -> VefasResult<(String, String, u16)> {
    // Parse HTTP request
    let request = parse_http_request(&http_data.request)?;

    // Parse HTTP response
    let response = parse_http_response(&http_data.response)?;

    Ok((request.method, request.path, response.status_code))
}

/// Parse HTTP request message
pub fn parse_http_request(data: &[u8]) -> VefasResult<HttpRequest> {
    let request_str = core::str::from_utf8(data)
        .map_err(|_| VefasError::invalid_input("http_request", "Invalid UTF-8"))?;

    let lines: Vec<&str> = request_str.lines().collect();
    if lines.is_empty() {
        return Err(VefasError::invalid_input("http_request", "Empty request"));
    }

    // Parse request line: "METHOD /path HTTP/1.1"
    let request_line = lines[0];
    let request_parts: Vec<&str> = request_line.split_whitespace().collect();
    if request_parts.len() < 3 {
        return Err(VefasError::invalid_input(
            "http_request",
            "Invalid request line format",
        ));
    }

    let method = validate_http_method(request_parts[0])?;
    let path = validate_http_path(request_parts[1])?;
    let version = validate_http_version(request_parts[2])?;

    // Parse headers
    let mut headers = Vec::new();
    let mut body_start = 1;

    for (i, line) in lines.iter().enumerate().skip(1) {
        if line.is_empty() {
            // Empty line separates headers from body
            body_start = i + 1;
            break;
        }

        let header = parse_http_header(line)?;
        headers.push(header);
    }

    // Extract body
    let body = if body_start < lines.len() {
        let body_lines = &lines[body_start..];
        let body_str = body_lines.join("\n");
        body_str.into_bytes()
    } else {
        Vec::new()
    };

    Ok(HttpRequest {
        method,
        path,
        version,
        headers,
        body,
    })
}

/// Parse HTTP response message
pub fn parse_http_response(data: &[u8]) -> VefasResult<HttpResponse> {
    let response_str = core::str::from_utf8(data)
        .map_err(|_| VefasError::invalid_input("http_response", "Invalid UTF-8"))?;

    let lines: Vec<&str> = response_str.lines().collect();
    if lines.is_empty() {
        return Err(VefasError::invalid_input("http_response", "Empty response"));
    }

    // Parse status line: "HTTP/1.1 200 OK"
    let status_line = lines[0];
    let status_parts: Vec<&str> = status_line.split_whitespace().collect();
    if status_parts.len() < 2 {
        return Err(VefasError::invalid_input(
            "http_response",
            "Invalid status line format",
        ));
    }

    let version = validate_http_version(status_parts[0])?;
    let status_code = parse_status_code(status_parts[1])?;
    let status_text = if status_parts.len() > 2 {
        status_parts[2..].join(" ")
    } else {
        String::new()
    };

    // Parse headers
    let mut headers = Vec::new();
    let mut body_start = 1;

    for (i, line) in lines.iter().enumerate().skip(1) {
        if line.is_empty() {
            // Empty line separates headers from body
            body_start = i + 1;
            break;
        }

        let header = parse_http_header(line)?;
        headers.push(header);
    }

    // Extract body
    let body = if body_start < lines.len() {
        let body_lines = &lines[body_start..];
        let body_str = body_lines.join("\n");
        body_str.into_bytes()
    } else {
        Vec::new()
    };

    Ok(HttpResponse {
        status_code,
        status_text,
        version,
        headers,
        body,
    })
}

/// Validate HTTP method
pub fn validate_http_method(method: &str) -> VefasResult<String> {
    // Reject empty methods
    if method.is_empty() {
        return Err(VefasError::invalid_input(
            "http_request",
            "HTTP method cannot be empty",
        ));
    }

    // Common HTTP methods
    match method.to_uppercase().as_str() {
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "TRACE" | "CONNECT" => {
            Ok(method.to_uppercase())
        }
        _ => {
            // Allow custom methods but validate they contain only valid characters
            if method
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '_')
            {
                Ok(method.to_string())
            } else {
                Err(VefasError::invalid_input(
                    "http_request",
                    "Invalid HTTP method",
                ))
            }
        }
    }
}

/// Validate HTTP path
pub fn validate_http_path(path: &str) -> VefasResult<String> {
    if path.is_empty() {
        return Err(VefasError::invalid_input("http_request", "Empty HTTP path"));
    }

    if !path.starts_with('/') {
        return Err(VefasError::invalid_input(
            "http_request",
            "HTTP path must start with '/'",
        ));
    }

    // Validate path contains only valid URI characters
    if path.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '/'
            || c == '?'
            || c == '&'
            || c == '='
            || c == '-'
            || c == '_'
            || c == '.'
            || c == '~'
            || c == ':'
            || c == '@'
            || c == '!'
            || c == '$'
            || c == '\''
            || c == '('
            || c == ')'
            || c == '*'
            || c == '+'
            || c == ','
            || c == ';'
            || c == '%'
    }) {
        Ok(path.to_string())
    } else {
        Err(VefasError::invalid_input(
            "http_request",
            "Invalid characters in HTTP path",
        ))
    }
}

/// Validate HTTP version
fn validate_http_version(version: &str) -> VefasResult<String> {
    match version {
        "HTTP/1.0" | "HTTP/1.1" | "HTTP/2" | "HTTP/3" => Ok(version.to_string()),
        _ => Err(VefasError::invalid_input(
            "http",
            "Unsupported HTTP version",
        )),
    }
}

/// Parse HTTP status code
fn parse_status_code(status_str: &str) -> VefasResult<u16> {
    let status_code = status_str
        .parse::<u16>()
        .map_err(|_| VefasError::invalid_input("http_response", "Invalid status code format"))?;

    // Validate status code range
    if !(100..=599).contains(&status_code) {
        return Err(VefasError::invalid_input(
            "http_response",
            "Status code out of valid range (100-599)",
        ));
    }

    Ok(status_code)
}

/// Parse HTTP header line
fn parse_http_header(line: &str) -> VefasResult<(String, String)> {
    if let Some(colon_pos) = line.find(':') {
        let name = line[..colon_pos].trim();
        let value = line[colon_pos + 1..].trim();

        if name.is_empty() {
            return Err(VefasError::invalid_input(
                "http_header",
                "Empty header name",
            ));
        }

        // Validate header name contains only valid characters
        if name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            Ok((name.to_string(), value.to_string()))
        } else {
            Err(VefasError::invalid_input(
                "http_header",
                "Invalid characters in header name",
            ))
        }
    } else {
        Err(VefasError::invalid_input(
            "http_header",
            "Invalid header format (missing colon)",
        ))
    }
}

/// Get header value by name (case-insensitive)
pub fn get_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let name_lower = name.to_ascii_lowercase();
    for (header_name, header_value) in headers {
        if header_name.to_ascii_lowercase() == name_lower {
            return Some(header_value);
        }
    }
    None
}

/// Validate Content-Length header matches body size
pub fn validate_content_length(headers: &[(String, String)], body: &[u8]) -> VefasResult<()> {
    if let Some(content_length_str) = get_header_value(headers, "content-length") {
        let declared_length = content_length_str.parse::<usize>().map_err(|_| {
            VefasError::invalid_input("http_header", "Invalid Content-Length value")
        })?;

        if declared_length != body.len() {
            return Err(VefasError::invalid_input(
                "http_body",
                &format!(
                    "Content-Length mismatch: declared {}, actual {}",
                    declared_length,
                    body.len()
                ),
            ));
        }
    }

    Ok(())
}

/// Extract and validate host header
pub fn extract_host(headers: &[(String, String)]) -> VefasResult<String> {
    if let Some(host) = get_header_value(headers, "host") {
        validate_host_header(host).map(|h| h.to_string())
    } else {
        Err(VefasError::invalid_input(
            "http_header",
            "Missing required Host header",
        ))
    }
}

/// Validate host header format
fn validate_host_header(host: &str) -> VefasResult<&str> {
    if host.is_empty() {
        return Err(VefasError::invalid_input(
            "http_header",
            "Empty Host header",
        ));
    }

    // Basic validation - host should contain only valid hostname characters
    if host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '_')
    {
        Ok(host)
    } else {
        Err(VefasError::invalid_input(
            "http_header",
            "Invalid characters in Host header",
        ))
    }
}

/// Create hex string from bytes (lowercase)
pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Normalize HTTP data for consistent hashing
pub fn normalize_http_data(data: &[u8]) -> Vec<u8> {
    // Convert to string, normalize line endings, remove trailing whitespace
    if let Ok(text) = core::str::from_utf8(data) {
        let normalized = text
            .replace("\r\n", "\n") // Normalize CRLF to LF
            .replace('\r', "\n") // Normalize standalone CR to LF
            .lines()
            .map(|line| line.trim_end()) // Remove trailing whitespace from each line
            .collect::<Vec<_>>()
            .join("\n");

        normalized.into_bytes()
    } else {
        // If not valid UTF-8, return as-is
        data.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn parse_http_request_valid() {
        let request_data =
            b"GET /api/test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\ntest body";
        let request = parse_http_request(request_data).unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/test");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(request.headers.len(), 2);
        assert_eq!(request.body, b"test body");
    }

    #[test]
    fn parse_http_response_valid() {
        let response_data = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\ntest body";
        let response = parse_http_response(response_data).unwrap();

        assert_eq!(response.status_code, 200);
        assert_eq!(response.status_text, "OK");
        assert_eq!(response.version, "HTTP/1.1");
        assert_eq!(response.headers.len(), 2);
        assert_eq!(response.body, b"test body");
    }

    #[test]
    fn parse_http_request_invalid_method() {
        let request_data = b"INVALID$METHOD /api/test HTTP/1.1\r\n\r\n";
        let result = parse_http_request(request_data);
        assert!(result.is_err());
    }

    #[test]
    fn parse_http_request_invalid_path() {
        let request_data = b"GET invalid_path HTTP/1.1\r\n\r\n";
        let result = parse_http_request(request_data);
        assert!(result.is_err());
    }

    #[test]
    fn parse_http_response_invalid_status() {
        let response_data = b"HTTP/1.1 999 Invalid\r\n\r\n";
        let result = parse_http_response(response_data);
        assert!(result.is_err());
    }

    #[test]
    fn validate_http_method_valid() {
        assert_eq!(validate_http_method("GET").unwrap(), "GET");
        assert_eq!(validate_http_method("post").unwrap(), "POST");
        assert_eq!(
            validate_http_method("CUSTOM-METHOD").unwrap(),
            "CUSTOM-METHOD"
        );
    }

    #[test]
    fn validate_http_method_invalid() {
        assert!(validate_http_method("INVALID$METHOD").is_err());
        assert!(validate_http_method("").is_err());
    }

    #[test]
    fn validate_http_path_valid() {
        assert_eq!(validate_http_path("/").unwrap(), "/");
        assert_eq!(validate_http_path("/api/test").unwrap(), "/api/test");
        assert_eq!(
            validate_http_path("/api/test?param=value").unwrap(),
            "/api/test?param=value"
        );
    }

    #[test]
    fn validate_http_path_invalid() {
        assert!(validate_http_path("").is_err());
        assert!(validate_http_path("api/test").is_err()); // Must start with /
        assert!(validate_http_path("/api/test<script>").is_err()); // Invalid characters
    }

    #[test]
    fn parse_status_code_valid() {
        assert_eq!(parse_status_code("200").unwrap(), 200);
        assert_eq!(parse_status_code("404").unwrap(), 404);
        assert_eq!(parse_status_code("500").unwrap(), 500);
    }

    #[test]
    fn parse_status_code_invalid() {
        assert!(parse_status_code("99").is_err()); // Out of range
        assert!(parse_status_code("600").is_err()); // Out of range
        assert!(parse_status_code("abc").is_err()); // Not a number
    }

    #[test]
    fn parse_http_header_valid() {
        let (name, value) = parse_http_header("Content-Type: application/json").unwrap();
        assert_eq!(name, "Content-Type");
        assert_eq!(value, "application/json");
    }

    #[test]
    fn parse_http_header_invalid() {
        assert!(parse_http_header("Invalid header line").is_err());
        assert!(parse_http_header(": missing name").is_err());
    }

    #[test]
    fn get_header_value_case_insensitive() {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Host".to_string(), "example.com".to_string()),
        ];

        assert_eq!(
            get_header_value(&headers, "content-type"),
            Some("application/json")
        );
        assert_eq!(get_header_value(&headers, "HOST"), Some("example.com"));
        assert_eq!(get_header_value(&headers, "missing"), None);
    }

    #[test]
    fn validate_content_length_matching() {
        let headers = vec![("Content-Length".to_string(), "9".to_string())];
        let body = b"test body";
        let result = validate_content_length(&headers, body);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_content_length_mismatch() {
        let headers = vec![("Content-Length".to_string(), "5".to_string())];
        let body = b"test body"; // 9 bytes
        let result = validate_content_length(&headers, body);
        assert!(result.is_err());
    }

    #[test]
    fn hex_lower_conversion() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(hex_lower(&bytes), "0123456789abcdef");
    }

    #[test]
    fn normalize_http_data_line_endings() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let normalized = normalize_http_data(data);
        // The normalize function joins lines with \n but doesn't preserve trailing empty lines
        let expected = b"GET / HTTP/1.1\nHost: example.com\n";
        assert_eq!(normalized, expected);
    }

    #[test]
    fn parse_http_data_integration() {
        let request = b"GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"result\":\"ok\"}";

        let http_data = HttpData::new(request.to_vec(), response.to_vec());
        let (method, path, status_code) = parse_http_data(&http_data).unwrap();

        assert_eq!(method, "GET");
        assert_eq!(path, "/api/test");
        assert_eq!(status_code, 200);
    }
}
