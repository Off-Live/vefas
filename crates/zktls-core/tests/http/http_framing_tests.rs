//! Tests for HTTP/1.1 Message Framing within TLS
//!
//! This module tests HTTP message parsing and serialization for use
//! within TLS application data records.

#[cfg(test)]
mod tests {
    use zktls_core::tls::application::HttpMessage;
    use std::collections::BTreeMap;

    #[test]
    fn test_http_request_parsing() {
        let raw_request = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        
        let request = HttpMessage::parse_request(raw_request).unwrap();
        
        assert_eq!(request.method(), "GET");
        assert_eq!(request.path(), "/");
        assert_eq!(request.version(), "HTTP/1.1");
        assert_eq!(request.header("Host"), Some("example.com"));
        assert_eq!(request.header("Connection"), Some("keep-alive"));
    }

    #[test]
    fn test_http_response_parsing() {
        let raw_response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!";
        
        let response = HttpMessage::parse_response(raw_response).unwrap();
        
        assert_eq!(response.version(), "HTTP/1.1");
        assert_eq!(response.status_code(), 200);
        assert_eq!(response.reason_phrase(), "OK");
        assert_eq!(response.header("Content-Type"), Some("text/html"));
        assert_eq!(response.header("Content-Length"), Some("13"));
        assert_eq!(response.body(), b"Hello, World!");
    }

    #[test]
    fn test_http_request_serialization() {
        let mut headers = BTreeMap::new();
        headers.insert("Host".to_string(), "example.com".to_string());
        headers.insert("User-Agent".to_string(), "zkTLS/1.0".to_string());
        
        let request = HttpMessage::request("GET", "/api/data", "HTTP/1.1", headers, vec![]);
        let serialized = request.serialize();
        
        let expected = b"GET /api/data HTTP/1.1\r\nHost: example.com\r\nUser-Agent: zkTLS/1.0\r\n\r\n";
        // Note: header order may vary due to HashMap, so we'll check components
        
        let parsed = HttpMessage::parse_request(&serialized).unwrap();
        assert_eq!(parsed.method(), "GET");
        assert_eq!(parsed.path(), "/api/data");
        assert_eq!(parsed.header("Host"), Some("example.com"));
        assert_eq!(parsed.header("User-Agent"), Some("zkTLS/1.0"));
    }

    #[test]
    fn test_http_response_serialization() {
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Content-Length".to_string(), "17".to_string());
        
        let body = b"{\"status\":\"ok\"}".to_vec();
        let response = HttpMessage::response("HTTP/1.1", 200, "OK", headers, body);
        let serialized = response.serialize();
        
        let parsed = HttpMessage::parse_response(&serialized).unwrap();
        assert_eq!(parsed.status_code(), 200);
        assert_eq!(parsed.reason_phrase(), "OK");
        assert_eq!(parsed.header("Content-Type"), Some("application/json"));
        assert_eq!(parsed.body(), b"{\"status\":\"ok\"}");
    }

    #[test]
    fn test_content_length_handling() {
        // Test with explicit Content-Length
        let raw_response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
        let response = HttpMessage::parse_response(raw_response).unwrap();
        assert_eq!(response.body(), b"Hello");
        
        // Test with longer content than Content-Length (should truncate)
        let raw_response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHelloWorld";
        let response = HttpMessage::parse_response(raw_response).unwrap();
        assert_eq!(response.body(), b"Hel");
    }

    #[test]
    fn test_no_content_length() {
        // Test without Content-Length - should read to end of data
        let raw_response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, World!";
        let response = HttpMessage::parse_response(raw_response).unwrap();
        assert_eq!(response.body(), b"Hello, World!");
    }

    #[test]
    fn test_chunked_transfer_encoding() {
        // Test parsing of chunked encoding (basic case)
        let raw_response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n7\r\n World!\r\n0\r\n\r\n";
        let response = HttpMessage::parse_response(raw_response).unwrap();
        assert_eq!(response.body(), b"Hello World!");
    }

    #[test]
    fn test_http_parsing_errors() {
        // Test malformed request line
        let bad_request = b"INVALID REQUEST LINE\r\n\r\n";
        assert!(HttpMessage::parse_request(bad_request).is_err());
        
        // Test malformed status line
        let bad_response = b"HTTP/1.1 INVALID STATUS\r\n\r\n";
        assert!(HttpMessage::parse_response(bad_response).is_err());
        
        // Test missing headers terminator
        let incomplete = b"GET / HTTP/1.1\r\nHost: example.com";
        assert!(HttpMessage::parse_request(incomplete).is_err());
    }

    #[test]
    fn test_case_insensitive_headers() {
        let raw_request = b"GET / HTTP/1.1\r\nhost: example.com\r\ncontent-length: 0\r\n\r\n";
        let request = HttpMessage::parse_request(raw_request).unwrap();
        
        // Headers should be accessible case-insensitively
        assert_eq!(request.header("Host"), Some("example.com"));
        assert_eq!(request.header("HOST"), Some("example.com"));
        assert_eq!(request.header("Content-Length"), Some("0"));
    }

    #[test]
    fn test_http_version_validation() {
        // Valid versions
        assert!(HttpMessage::parse_request(b"GET / HTTP/1.0\r\n\r\n").is_ok());
        assert!(HttpMessage::parse_request(b"GET / HTTP/1.1\r\n\r\n").is_ok());
        
        // Invalid version
        assert!(HttpMessage::parse_request(b"GET / HTTP/2.0\r\n\r\n").is_err());
    }
}