//! HTTP protocol types and structures
//!
//! This module provides comprehensive HTTP/1.1 types designed for deterministic
//! serialization and verification in zkVM environments.

use crate::utils::format_decimal;
use crate::{VefasError, VefasResult, MAX_HTTP_BODY_SIZE, MAX_HTTP_HEADER_SIZE};
use alloc::{collections::BTreeMap, string::String, string::ToString, vec::Vec};
use serde::{Deserialize, Serialize};

/// HTTP request methods (RFC 7231)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    /// GET method
    Get,
    /// POST method
    Post,
    /// PUT method
    Put,
    /// DELETE method
    Delete,
    /// HEAD method
    Head,
    /// OPTIONS method
    Options,
    /// PATCH method
    Patch,
    /// TRACE method
    Trace,
    /// CONNECT method
    Connect,
}

impl HttpMethod {
    /// Get the string representation of the method
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Trace => "TRACE",
            HttpMethod::Connect => "CONNECT",
        }
    }

    /// Parse method from string
    pub fn from_str(s: &str) -> VefasResult<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "DELETE" => Ok(HttpMethod::Delete),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            "PATCH" => Ok(HttpMethod::Patch),
            "TRACE" => Ok(HttpMethod::Trace),
            "CONNECT" => Ok(HttpMethod::Connect),
            _ => Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidMethod,
                &("Invalid HTTP method: ".to_string() + s),
            )),
        }
    }

    /// Check if method typically has a request body
    pub fn typically_has_body(&self) -> bool {
        matches!(self, HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch)
    }

    /// Check if method is safe (no side effects)
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            HttpMethod::Get | HttpMethod::Head | HttpMethod::Options | HttpMethod::Trace
        )
    }

    /// Check if method is idempotent
    pub fn is_idempotent(&self) -> bool {
        matches!(
            self,
            HttpMethod::Get
                | HttpMethod::Head
                | HttpMethod::Put
                | HttpMethod::Delete
                | HttpMethod::Options
                | HttpMethod::Trace
        )
    }
}

/// HTTP status codes (RFC 7231)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HttpStatusCode(pub u16);

impl HttpStatusCode {
    /// Create a new status code
    pub fn new(code: u16) -> VefasResult<Self> {
        if (100..=599).contains(&code) {
            Ok(HttpStatusCode(code))
        } else {
            Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidStatusCode,
                &("Invalid HTTP status code: ".to_string() + &format_decimal(code as usize)),
            ))
        }
    }

    /// Get the numeric value
    pub fn value(&self) -> u16 {
        self.0
    }

    /// Get the status class
    pub fn class(&self) -> StatusClass {
        match self.0 {
            100..=199 => StatusClass::Informational,
            200..=299 => StatusClass::Success,
            300..=399 => StatusClass::Redirection,
            400..=499 => StatusClass::ClientError,
            500..=599 => StatusClass::ServerError,
            _ => StatusClass::Unknown,
        }
    }

    /// Get the reason phrase for common status codes
    pub fn reason_phrase(&self) -> &'static str {
        match self.0 {
            100 => "Continue",
            101 => "Switching Protocols",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
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

    /// Check if status indicates success
    pub fn is_success(&self) -> bool {
        matches!(self.class(), StatusClass::Success)
    }

    /// Check if status indicates client error
    pub fn is_client_error(&self) -> bool {
        matches!(self.class(), StatusClass::ClientError)
    }

    /// Check if status indicates server error
    pub fn is_server_error(&self) -> bool {
        matches!(self.class(), StatusClass::ServerError)
    }
}

/// HTTP status classes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StatusClass {
    /// 1xx - Informational
    Informational,
    /// 2xx - Success
    Success,
    /// 3xx - Redirection
    Redirection,
    /// 4xx - Client Error
    ClientError,
    /// 5xx - Server Error
    ServerError,
    /// Unknown/Invalid
    Unknown,
}

/// HTTP headers collection
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHeaders {
    /// Headers stored as lowercase name -> value mapping
    headers: BTreeMap<String, String>,
    /// Total serialized size for memory validation
    total_size: usize,
}

impl HttpHeaders {
    /// Create a new empty headers collection
    pub fn new() -> Self {
        Self {
            headers: BTreeMap::new(),
            total_size: 0,
        }
    }

    /// Insert a header (name will be lowercased)
    pub fn insert(&mut self, name: &str, value: &str) -> VefasResult<()> {
        let name_lower = name.to_lowercase();

        // Validate header name (RFC 7230)
        if !Self::is_valid_header_name(&name_lower) {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidHeader,
                &("Invalid header name: ".to_string() + name),
            ));
        }

        // Validate header value (RFC 7230)
        if !Self::is_valid_header_value(value) {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidHeader,
                &("Invalid header value for ".to_string() + name + ": " + value),
            ));
        }

        // Calculate size impact
        let old_value_size = self.headers.get(&name_lower).map(|v| v.len()).unwrap_or(0);
        let new_value_size = value.len();
        let name_size = if self.headers.contains_key(&name_lower) {
            0
        } else {
            name_lower.len()
        };

        let new_total_size = self.total_size - old_value_size + new_value_size + name_size;

        if new_total_size > MAX_HTTP_HEADER_SIZE {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::HeaderTooLarge,
                &("Headers too large: ".to_string()
                    + &format_decimal(new_total_size)
                    + " bytes (max "
                    + &format_decimal(MAX_HTTP_HEADER_SIZE)
                    + ")"),
            ));
        }

        self.headers.insert(name_lower, value.to_string());
        self.total_size = new_total_size;
        Ok(())
    }

    /// Get a header value
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    /// Remove a header
    pub fn remove(&mut self, name: &str) -> Option<String> {
        let name_lower = name.to_lowercase();
        if let Some(value) = self.headers.remove(&name_lower) {
            self.total_size -= name_lower.len() + value.len();
            Some(value)
        } else {
            None
        }
    }

    /// Check if header exists
    pub fn contains(&self, name: &str) -> bool {
        self.headers.contains_key(&name.to_lowercase())
    }

    /// Get all headers as iterator
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Get header count
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Check if headers are empty
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Get total serialized size
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Serialize headers to HTTP wire format
    pub fn serialize(&self) -> String {
        let mut result = String::new();
        for (name, value) in &self.headers {
            result.push_str(name);
            result.push_str(": ");
            result.push_str(value);
            result.push_str("\r\n");
        }
        result
    }

    /// Parse headers from HTTP wire format
    pub fn parse(input: &str) -> VefasResult<Self> {
        let mut headers = HttpHeaders::new();

        for line in input.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                headers.insert(name, value)?;
            } else {
                return Err(VefasError::http_error(
                    crate::errors::HttpErrorType::InvalidHeader,
                    &("Invalid header line: ".to_string() + line),
                ));
            }
        }

        Ok(headers)
    }

    /// Validate header name according to RFC 7230
    fn is_valid_header_name(name: &str) -> bool {
        !name.is_empty()
            && name.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(
                        c,
                        '!' | '#'
                            | '$'
                            | '%'
                            | '&'
                            | '\''
                            | '*'
                            | '+'
                            | '-'
                            | '.'
                            | '^'
                            | '_'
                            | '`'
                            | '|'
                            | '~'
                    )
            })
    }

    /// Validate header value according to RFC 7230
    fn is_valid_header_value(value: &str) -> bool {
        value
            .chars()
            .all(|c| c.is_ascii() && (c.is_ascii_graphic() || c == ' ' || c == '\t'))
    }
}

impl Default for HttpHeaders {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP request structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    /// HTTP method
    pub method: HttpMethod,
    /// Request URI (path + query string)
    pub uri: String,
    /// HTTP version (e.g., "HTTP/1.1")
    pub version: String,
    /// Request headers
    pub headers: HttpHeaders,
    /// Request body
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Create a new HTTP request
    pub fn new(
        method: HttpMethod,
        uri: &str,
        version: &str,
        headers: HttpHeaders,
        body: Vec<u8>,
    ) -> VefasResult<Self> {
        // Validate body size
        if body.len() > MAX_HTTP_BODY_SIZE {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::BodyTooLarge,
                &("Request body too large: ".to_string()
                    + &format_decimal(body.len())
                    + " bytes (max "
                    + &format_decimal(MAX_HTTP_BODY_SIZE)
                    + ")"),
            ));
        }

        // Validate URI format (basic check)
        if uri.is_empty() || !uri.starts_with('/') {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidUrl,
                &("Invalid request URI: ".to_string() + uri),
            ));
        }

        // Validate version
        if !version.starts_with("HTTP/") {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidVersion,
                &("Invalid HTTP version: ".to_string() + version),
            ));
        }

        Ok(Self {
            method,
            uri: uri.to_string(),
            version: version.to_string(),
            headers,
            body,
        })
    }

    /// Get content length from headers or body size
    pub fn content_length(&self) -> usize {
        self.headers
            .get("content-length")
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.body.len())
    }

    /// Get content type from headers
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type")
    }

    /// Get host from headers
    pub fn host(&self) -> Option<&str> {
        self.headers.get("host")
    }

    /// Get user agent from headers
    pub fn user_agent(&self) -> Option<&str> {
        self.headers.get("user-agent")
    }

    /// Check if request has body content
    pub fn has_body(&self) -> bool {
        !self.body.is_empty()
    }

    /// Serialize request to HTTP wire format
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Request line
        let mut request_line = String::new();
        request_line.push_str(self.method.as_str());
        request_line.push(' ');
        request_line.push_str(&self.uri);
        request_line.push(' ');
        request_line.push_str(&self.version);
        request_line.push_str("\r\n");
        result.extend_from_slice(request_line.as_bytes());

        // Headers
        result.extend_from_slice(self.headers.serialize().as_bytes());

        // Empty line
        result.extend_from_slice(b"\r\n");

        // Body
        result.extend_from_slice(&self.body);

        result
    }

    /// Parse request from HTTP wire format
    pub fn parse(input: &[u8]) -> VefasResult<Self> {
        let input_str = core::str::from_utf8(input).map_err(|_| {
            VefasError::http_error(
                crate::errors::HttpErrorType::InvalidRequest,
                "Invalid UTF-8 in request",
            )
        })?;

        // Find header/body boundary
        let header_end = input_str.find("\r\n\r\n").ok_or_else(|| {
            VefasError::http_error(
                crate::errors::HttpErrorType::InvalidRequest,
                "Missing header/body boundary",
            )
        })?;

        let header_part = &input_str[..header_end];
        let body_start = header_end + 4;

        // Parse request line
        let lines: Vec<&str> = header_part.lines().collect();
        if lines.is_empty() {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidRequest,
                "Empty request",
            ));
        }

        let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if request_line_parts.len() != 3 {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidRequest,
                &("Invalid request line: ".to_string() + &lines[0]),
            ));
        }

        let method = HttpMethod::from_str(request_line_parts[0])?;
        let uri = request_line_parts[1];
        let version = request_line_parts[2];

        // Parse headers
        let header_lines = lines[1..].join("\n");
        let headers = HttpHeaders::parse(&header_lines)?;

        // Extract body
        let body = if body_start < input.len() {
            input[body_start..].to_vec()
        } else {
            Vec::new()
        };

        Self::new(method, uri, version, headers, body)
    }
}

/// HTTP response structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// HTTP version (e.g., "HTTP/1.1")
    pub version: String,
    /// Status code
    pub status_code: HttpStatusCode,
    /// Reason phrase
    pub reason_phrase: String,
    /// Response headers
    pub headers: HttpHeaders,
    /// Response body
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Create a new HTTP response
    pub fn new(
        version: &str,
        status_code: HttpStatusCode,
        reason_phrase: &str,
        headers: HttpHeaders,
        body: Vec<u8>,
    ) -> VefasResult<Self> {
        // Validate body size
        if body.len() > MAX_HTTP_BODY_SIZE {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::BodyTooLarge,
                &("Response body too large: ".to_string()
                    + &format_decimal(body.len())
                    + " bytes (max "
                    + &format_decimal(MAX_HTTP_BODY_SIZE)
                    + ")"),
            ));
        }

        // Validate version
        if !version.starts_with("HTTP/") {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidVersion,
                &("Invalid HTTP version: ".to_string() + version),
            ));
        }

        Ok(Self {
            version: version.to_string(),
            status_code,
            reason_phrase: reason_phrase.to_string(),
            headers,
            body,
        })
    }

    /// Get content length from headers or body size
    pub fn content_length(&self) -> usize {
        self.headers
            .get("content-length")
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.body.len())
    }

    /// Get content type from headers
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type")
    }

    /// Check if response has body content
    pub fn has_body(&self) -> bool {
        !self.body.is_empty()
    }

    /// Serialize response to HTTP wire format
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Status line
        let mut status_line = String::new();
        status_line.push_str(&self.version);
        status_line.push(' ');
        status_line.push_str(&format_decimal(self.status_code.value() as usize));
        status_line.push(' ');
        status_line.push_str(&self.reason_phrase);
        status_line.push_str("\r\n");
        result.extend_from_slice(status_line.as_bytes());

        // Headers
        result.extend_from_slice(self.headers.serialize().as_bytes());

        // Empty line
        result.extend_from_slice(b"\r\n");

        // Body
        result.extend_from_slice(&self.body);

        result
    }

    /// Parse response from HTTP wire format
    pub fn parse(input: &[u8]) -> VefasResult<Self> {
        let input_str = core::str::from_utf8(input).map_err(|_| {
            VefasError::http_error(
                crate::errors::HttpErrorType::InvalidResponse,
                "Invalid UTF-8 in response",
            )
        })?;

        // Find header/body boundary
        let header_end = input_str.find("\r\n\r\n").ok_or_else(|| {
            VefasError::http_error(
                crate::errors::HttpErrorType::InvalidResponse,
                "Missing header/body boundary",
            )
        })?;

        let header_part = &input_str[..header_end];
        let body_start = header_end + 4;

        // Parse status line
        let lines: Vec<&str> = header_part.lines().collect();
        if lines.is_empty() {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidResponse,
                "Empty response",
            ));
        }

        let status_line_parts: Vec<&str> = lines[0].splitn(3, ' ').collect();
        if status_line_parts.len() < 2 {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidResponse,
                &("Invalid status line: ".to_string() + &lines[0]),
            ));
        }

        let version = status_line_parts[0];
        let status_code = status_line_parts[1].parse::<u16>().map_err(|_| {
            VefasError::http_error(
                crate::errors::HttpErrorType::InvalidStatusCode,
                &("Invalid status code: ".to_string() + status_line_parts[1]),
            )
        })?;
        let status_code = HttpStatusCode::new(status_code)?;
        let reason_phrase = status_line_parts.get(2).unwrap_or(&"").to_string();

        // Parse headers
        let header_lines = lines[1..].join("\n");
        let headers = HttpHeaders::parse(&header_lines)?;

        // Extract body
        let body = if body_start < input.len() {
            input[body_start..].to_vec()
        } else {
            Vec::new()
        };

        Self::new(version, status_code, &reason_phrase, headers, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_http_method_parsing() {
        assert_eq!(HttpMethod::from_str("GET").unwrap(), HttpMethod::Get);
        assert_eq!(HttpMethod::from_str("post").unwrap(), HttpMethod::Post);
        assert!(HttpMethod::from_str("INVALID").is_err());
    }

    #[test]
    fn test_http_status_code() {
        let status = HttpStatusCode::new(200).unwrap();
        assert_eq!(status.value(), 200);
        assert_eq!(status.reason_phrase(), "OK");
        assert!(status.is_success());
        assert!(!status.is_client_error());
    }

    #[test]
    fn test_http_headers() {
        let mut headers = HttpHeaders::new();
        headers.insert("Content-Type", "application/json").unwrap();
        headers.insert("Content-Length", "42").unwrap();

        assert_eq!(headers.get("content-type"), Some("application/json"));
        assert_eq!(headers.get("Content-Length"), Some("42"));
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn test_http_request_serialization() {
        let mut headers = HttpHeaders::new();
        headers.insert("Host", "example.com").unwrap();
        headers.insert("User-Agent", "VEFAS/1.0").unwrap();

        let request = HttpRequest::new(
            HttpMethod::Get,
            "/api/test",
            "HTTP/1.1",
            headers,
            Vec::new(),
        )
        .unwrap();

        let serialized = request.serialize();
        let parsed = HttpRequest::parse(&serialized).unwrap();
        assert_eq!(request, parsed);
    }

    #[test]
    fn test_http_response_serialization() {
        let mut headers = HttpHeaders::new();
        headers.insert("Content-Type", "application/json").unwrap();
        headers.insert("Content-Length", "13").unwrap();

        let body = b"{\"ok\": true}".to_vec();
        let response = HttpResponse::new(
            "HTTP/1.1",
            HttpStatusCode::new(200).unwrap(),
            "OK",
            headers,
            body,
        )
        .unwrap();

        let serialized = response.serialize();
        let parsed = HttpResponse::parse(&serialized).unwrap();
        assert_eq!(response, parsed);
    }

    #[test]
    fn test_header_size_limits() {
        let mut headers = HttpHeaders::new();
        let large_value = "x".repeat(MAX_HTTP_HEADER_SIZE);
        assert!(headers.insert("Large-Header", &large_value).is_err());
    }

    #[test]
    fn test_body_size_limits() {
        let large_body = vec![0u8; MAX_HTTP_BODY_SIZE + 1];
        let headers = HttpHeaders::new();

        assert!(HttpRequest::new(
            HttpMethod::Post,
            "/test",
            "HTTP/1.1",
            headers.clone(),
            large_body.clone(),
        )
        .is_err());

        assert!(HttpResponse::new(
            "HTTP/1.1",
            HttpStatusCode::new(200).unwrap(),
            "OK",
            headers,
            large_body,
        )
        .is_err());
    }
}
