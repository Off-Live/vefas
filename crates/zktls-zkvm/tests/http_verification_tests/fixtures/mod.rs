//! Test fixtures for HTTP verification tests
//!
//! This module provides HTTP request/response test data
//! for testing HTTP verification functionality.

/// Simple GET request
pub const SIMPLE_GET_REQUEST: &[u8] = b"GET /api/data HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";

/// Simple GET response
pub const SIMPLE_GET_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"status\":\"success\"}";

/// POST request with JSON body
pub const POST_JSON_REQUEST: &[u8] = b"POST /api/submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"key\":\"value\"}";

/// POST response with JSON body
pub const POST_JSON_RESPONSE: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nLocation: /api/submit/123\r\nContent-Length: 29\r\n\r\n{\"id\":123,\"status\":\"created\"}";

/// Error response (404 Not Found)
pub const ERROR_RESPONSE: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 22\r\n\r\n<h1>404 Not Found</h1>";

/// Malformed request (missing headers terminator)
pub const MALFORMED_REQUEST: &[u8] = b"GET /api/data HTTP/1.1\r\nHost: example.com\r\nConnection: close";

/// Malformed response (invalid status line)
pub const MALFORMED_RESPONSE: &[u8] = b"HTTP/1.1 INVALID OK\r\nContent-Type: application/json\r\n\r\n{}";

/// HTML request
pub const HTML_REQUEST: &[u8] = b"GET /page.html HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n";

/// HTML response
pub const HTML_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 20\r\n\r\n<html><body>Hello</body></html>";

/// XML request
pub const XML_REQUEST: &[u8] = b"GET /data.xml HTTP/1.1\r\nHost: example.com\r\nAccept: application/xml\r\n\r\n";

/// XML response
pub const XML_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 35\r\n\r\n<root><item>value</item></root>";

/// Text request
pub const TEXT_REQUEST: &[u8] = b"GET /data.txt HTTP/1.1\r\nHost: example.com\r\nAccept: text/plain\r\n\r\n";

/// Text response
pub const TEXT_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHello, World!";

/// Large request with big payload
pub const LARGE_REQUEST: &[u8] = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: 1500\r\n\r\n";

/// Large response with big payload
pub const LARGE_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1500\r\n\r\n";

/// Chunked response
pub const CHUNKED_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\nD\r\nHello, World!\r\n1A\r\n This is chunked data.\r\n0\r\n\r\n";

/// Helper function to create large payload data
pub fn create_large_payload(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    for i in 0..size {
        data.push((i % 256) as u8);
    }
    data
}

/// Helper function to create large request with payload
pub fn create_large_request(payload_size: usize) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: ");
    request.extend_from_slice(payload_size.to_string().as_bytes());
    request.extend_from_slice(b"\r\n\r\n");
    request.extend_from_slice(&create_large_payload(payload_size));
    request
}

/// Helper function to create large response with payload
pub fn create_large_response(payload_size: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ");
    response.extend_from_slice(payload_size.to_string().as_bytes());
    response.extend_from_slice(b"\r\n\r\n");
    response.extend_from_slice(&create_large_payload(payload_size));
    response
}
