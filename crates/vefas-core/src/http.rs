//! # HTTP Request/Response Processing
//!
//! This module provides production-grade HTTP parsing and processing capabilities
//! for extracting HTTP data from TLS application records. It handles HTTP/1.1
//! request/response parsing, header processing, and content encoding.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::{Result, VefasCoreError};
use httparse::{Request, Response, Status};

/// HTTP request/response data extracted from TLS application records
#[derive(Debug, Clone, PartialEq)]
pub struct HttpData {
    /// Raw HTTP request bytes
    pub request_bytes: Vec<u8>,
    /// Raw HTTP response bytes
    pub response_bytes: Vec<u8>,
    /// HTTP status code from response
    pub status_code: u16,
    /// HTTP headers from response
    pub headers: Vec<(String, String)>,
    /// Request method (GET, POST, etc.)
    pub method: String,
    /// Request path
    pub path: String,
    /// Request headers
    pub request_headers: Vec<(String, String)>,
    /// Response body (after content-encoding processing)
    pub response_body: Vec<u8>,
}

/// HTTP processor for parsing requests and responses from TLS application data
#[derive(Debug, Default)]
pub struct HttpProcessor {
    /// Buffer for incomplete HTTP data
    buffer: Vec<u8>,
}

impl HttpProcessor {
    /// Create a new HTTP processor
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Parse HTTP request from raw bytes
    pub fn parse_http_request(&self, data: &[u8]) -> Result<HttpRequest> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers);

        match req.parse(data)? {
            Status::Complete(amt) => {
                let method = req
                    .method
                    .ok_or_else(|| VefasCoreError::HttpError("Missing HTTP method".to_string()))?;

                let path = req
                    .path
                    .ok_or_else(|| VefasCoreError::HttpError("Missing HTTP path".to_string()))?;

                let headers = req
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_string(),
                            String::from_utf8_lossy(h.value).to_string(),
                        )
                    })
                    .collect();

                let body = if amt < data.len() {
                    data[amt..].to_vec()
                } else {
                    Vec::new()
                };

                Ok(HttpRequest {
                    method: method.to_string(),
                    path: path.to_string(),
                    headers,
                    body,
                    raw_bytes: data.to_vec(),
                })
            }
            Status::Partial => Err(VefasCoreError::HttpError(
                "Incomplete HTTP request".to_string(),
            )),
        }
    }

    /// Parse HTTP response from raw bytes
    pub fn parse_http_response(&self, data: &[u8]) -> Result<HttpResponse> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = Response::new(&mut headers);

        match resp.parse(data)? {
            Status::Complete(amt) => {
                let status_code = resp.code.ok_or_else(|| {
                    VefasCoreError::HttpError("Missing HTTP status code".to_string())
                })?;

                let headers = resp
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_string(),
                            String::from_utf8_lossy(h.value).to_string(),
                        )
                    })
                    .collect();

                let body = if amt < data.len() {
                    data[amt..].to_vec()
                } else {
                    Vec::new()
                };

                Ok(HttpResponse {
                    status_code,
                    headers,
                    body,
                    raw_bytes: data.to_vec(),
                })
            }
            Status::Partial => Err(VefasCoreError::HttpError(
                "Incomplete HTTP response".to_string(),
            )),
        }
    }

    /// Extract HTTP data from TLS application data records
    pub fn extract_http_data(
        &mut self,
        request_data: &[u8],
        response_data: &[u8],
    ) -> Result<HttpData> {
        let request = self.parse_http_request(request_data)?;
        let response = self.parse_http_response(response_data)?;

        // Process response body (handle content encoding if needed)
        let response_body = self.process_response_body(&response)?;

        Ok(HttpData {
            request_bytes: request.raw_bytes,
            response_bytes: response.raw_bytes,
            status_code: response.status_code,
            headers: response.headers.clone(),
            method: request.method,
            path: request.path,
            request_headers: request.headers,
            response_body,
        })
    }

    /// Extract HTTP data from a stream of application data (TLS decrypted)
    pub fn extract_http_data_from_stream(&mut self, app_data: &[u8]) -> Result<HttpData> {
        // Parse the application data stream to separate HTTP request and response
        let (request_data, response_data) = self.split_request_response_stream(app_data)?;

        // Process the separated HTTP data
        self.extract_http_data(&request_data, &response_data)
    }

    /// Split application data stream into HTTP request and response parts
    fn split_request_response_stream(&self, app_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Look for HTTP request start pattern
        let request_start = self.find_http_request_start(app_data)?;

        // Look for HTTP response start pattern after the request
        let response_start = self.find_http_response_start(app_data, request_start)?;

        if response_start > app_data.len() {
            return Err(VefasCoreError::HttpError(
                "No HTTP response found in application data".to_string(),
            ));
        }

        let request_data = app_data[request_start..response_start].to_vec();
        let response_data = app_data[response_start..].to_vec();

        Ok((request_data, response_data))
    }

    /// Find the start of HTTP request in application data
    fn find_http_request_start(&self, data: &[u8]) -> Result<usize> {
        // Look for HTTP method patterns at start of data
        let http_methods: &[&[u8]] = &[
            b"GET ",
            b"POST ",
            b"PUT ",
            b"DELETE ",
            b"HEAD ",
            b"OPTIONS ",
            b"PATCH ",
        ];

        for &method in http_methods {
            if data.starts_with(method) {
                return Ok(0);
            }
        }

        // If not at start, search within the data
        for (i, window) in data.windows(4).enumerate() {
            for &method in http_methods {
                if window == &method[..4.min(method.len())] {
                    // Verify this is likely a real HTTP method by checking for more context
                    if i + method.len() < data.len() {
                        return Ok(i);
                    }
                }
            }
        }

        Err(VefasCoreError::HttpError(
            "No HTTP request found in application data".to_string(),
        ))
    }

    /// Find the start of HTTP response in application data
    fn find_http_response_start(&self, data: &[u8], after_offset: usize) -> Result<usize> {
        let search_data = &data[after_offset..];

        // Look for HTTP response pattern "HTTP/1.1" or "HTTP/1.0"
        let http_response_patterns: &[&[u8]] = &[b"HTTP/1.1 ", b"HTTP/1.0 ", b"HTTP/2"];

        for &pattern in http_response_patterns {
            if let Some(pos) = search_data
                .windows(pattern.len())
                .position(|window| window == pattern)
            {
                return Ok(after_offset + pos);
            }
        }

        Err(VefasCoreError::HttpError(
            "No HTTP response found in application data".to_string(),
        ))
    }

    /// Process response body, handling Transfer-Encoding and Content-Encoding (RFC 7230)
    pub fn process_response_body(&self, response: &HttpResponse) -> Result<Vec<u8>> {
        // Apply Transfer-Encoding (chunked) first
        let is_chunked = response.headers.iter().any(|(k, v)| {
            if !k.eq_ignore_ascii_case("Transfer-Encoding") {
                return false;
            }
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
        });

        let mut body = if is_chunked {
            self.dechunk(&response.body)?
        } else {
            response.body.clone()
        };

        // Then apply Content-Encoding (compression)
        let content_encoding = response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Content-Encoding"))
            .map(|(_, value)| value.to_lowercase());

        match content_encoding.as_deref() {
            Some("gzip") => self.decompress_gzip(&body),
            Some("deflate") => self.decompress_deflate(&body),
            Some("br") | Some("brotli") => self.decompress_brotli(&body),
            Some("identity") | None => Ok(body),
            Some(encoding) => {
                eprintln!(
                    "Warning: Unknown content encoding '{}', returning raw body",
                    encoding
                );
                Ok(body)
            }
        }
    }

    /// De-chunk a chunked transfer-encoded body (RFC 7230 §4.1)
    fn dechunk(&self, data: &[u8]) -> Result<Vec<u8>> {
        const MAX_DECHUNKED_SIZE: usize = 16 * 1024 * 1024; // 16 MiB safety cap
        let mut out = Vec::with_capacity(core::cmp::min(data.len(), 8 * 1024));
        let mut i = 0;

        loop {
            // Parse chunk-size [; chunk-ext] CRLF
            let line_start = i;
            let mut line_end = None;
            while i + 1 < data.len() {
                if data[i] == b'\r' && data[i + 1] == b'\n' {
                    line_end = Some(i);
                    break;
                }
                i += 1;
            }
            let end = line_end.ok_or_else(|| {
                VefasCoreError::HttpError("Malformed chunk-size line".to_string())
            })?;
            let line = &data[line_start..end];
            i = end + 2; // skip CRLF

            // Extract size up to ';' (ignore chunk extensions)
            let semi = line.iter().position(|&b| b == b';').unwrap_or(line.len());
            let size_str = std::str::from_utf8(&line[..semi])
                .map_err(|_| VefasCoreError::HttpError("Invalid chunk-size UTF-8".to_string()))?;
            let size_trimmed = size_str.trim();
            if size_trimmed.is_empty() {
                return Err(VefasCoreError::HttpError("Empty chunk-size".to_string()));
            }
            let size = usize::from_str_radix(size_trimmed, 16)
                .map_err(|_| VefasCoreError::HttpError("Invalid hex chunk-size".to_string()))?;

            if size == 0 {
                // Parse optional trailer headers until CRLF CRLF
                loop {
                    let mut k = i;
                    let mut eol = None;
                    while k + 1 < data.len() {
                        if data[k] == b'\r' && data[k + 1] == b'\n' {
                            eol = Some(k);
                            break;
                        }
                        k += 1;
                    }
                    let eol_pos = eol.ok_or_else(|| {
                        VefasCoreError::HttpError("Malformed trailer".to_string())
                    })?;
                    if eol_pos == i {
                        i += 2;
                        break;
                    } // empty line -> end of trailers
                    i = eol_pos + 2; // next line
                }
                break;
            }

            if i + size + 2 > data.len() {
                return Err(VefasCoreError::HttpError(
                    "Chunk exceeds buffer".to_string(),
                ));
            }
            out.extend_from_slice(&data[i..i + size]);
            if out.len() > MAX_DECHUNKED_SIZE {
                return Err(VefasCoreError::HttpError(
                    "Dechunked body too large".to_string(),
                ));
            }
            i += size;
            if !(data[i] == b'\r' && data[i + 1] == b'\n') {
                return Err(VefasCoreError::HttpError(
                    "Missing CRLF after chunk-data".to_string(),
                ));
            }
            i += 2;
        }

        Ok(out)
    }

    /// Decompress gzip-encoded content
    fn decompress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "flate2")]
        {
            use flate2::read::GzDecoder;
            use std::io::Read;

            let mut decoder = GzDecoder::new(data);
            let mut decompressed = Vec::new();

            decoder.read_to_end(&mut decompressed).map_err(|e| {
                VefasCoreError::HttpError(format!("Failed to decompress gzip content: {}", e))
            })?;

            Ok(decompressed)
        }
        #[cfg(not(feature = "flate2"))]
        {
            Err(VefasCoreError::HttpError(
                "Gzip decompression not supported - compile with 'flate2' feature".to_string(),
            ))
        }
    }

    /// Decompress deflate-encoded content
    fn decompress_deflate(&self, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "flate2")]
        {
            use flate2::read::DeflateDecoder;
            use std::io::Read;

            let mut decoder = DeflateDecoder::new(data);
            let mut decompressed = Vec::new();

            decoder.read_to_end(&mut decompressed).map_err(|e| {
                VefasCoreError::HttpError(format!("Failed to decompress deflate content: {}", e))
            })?;

            Ok(decompressed)
        }
        #[cfg(not(feature = "flate2"))]
        {
            Err(VefasCoreError::HttpError(
                "Deflate decompression not supported - compile with 'flate2' feature".to_string(),
            ))
        }
    }

    /// Decompress brotli-encoded content
    fn decompress_brotli(&self, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "brotli")]
        {
            use brotli::Decompressor;
            use std::io::Read;

            let mut decoder = Decompressor::new(data, 4096); // 4KB buffer
            let mut decompressed = Vec::new();

            decoder.read_to_end(&mut decompressed).map_err(|e| {
                VefasCoreError::HttpError(format!("Failed to decompress brotli content: {}", e))
            })?;

            Ok(decompressed)
        }
        #[cfg(not(feature = "brotli"))]
        {
            Err(VefasCoreError::HttpError(
                "Brotli decompression not supported - compile with 'brotli' feature".to_string(),
            ))
        }
    }

    /// Build HTTP request bytes
    pub fn build_request(
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut request = format!("{} {} HTTP/1.1\r\n", method, path);

        for (name, value) in headers {
            request.push_str(&format!("{}: {}\r\n", name, value));
        }

        if let Some(body) = body {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }

        request.push_str("\r\n");
        let mut request_bytes = request.into_bytes();

        if let Some(body) = body {
            request_bytes.extend_from_slice(body);
        }

        request_bytes
    }
}

/// Parsed HTTP request
#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request path
    pub path: String,
    /// Request headers
    pub headers: Vec<(String, String)>,
    /// Request body
    pub body: Vec<u8>,
    /// Raw request bytes
    pub raw_bytes: Vec<u8>,
}

/// Parsed HTTP response
#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponse {
    /// HTTP status code
    pub status_code: u16,
    /// Response headers
    pub headers: Vec<(String, String)>,
    /// Response body
    pub body: Vec<u8>,
    /// Raw response bytes
    pub raw_bytes: Vec<u8>,
}

/// HTTP headers collection
pub type HttpHeaders = Vec<(String, String)>;

impl From<httparse::Error> for VefasCoreError {
    fn from(err: httparse::Error) -> Self {
        VefasCoreError::HttpError(format!("HTTP parsing error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_get_request() {
        let processor = HttpProcessor::new();
        let request_data = b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";

        let request = processor.parse_http_request(request_data).unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/test");
        assert_eq!(request.headers.len(), 2);
        assert_eq!(
            request.headers[0],
            ("Host".to_string(), "example.com".to_string())
        );
        assert_eq!(
            request.headers[1],
            ("User-Agent".to_string(), "test".to_string())
        );
    }

    #[test]
    fn test_parse_post_request_with_body() {
        let processor = HttpProcessor::new();
        let request_data = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"test\":true}";

        let request = processor.parse_http_request(request_data).unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api/data");
        assert_eq!(request.body, b"{\"test\":true}");
    }

    #[test]
    fn test_parse_http_response() {
        let processor = HttpProcessor::new();
        let response_data = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";

        let response = processor.parse_http_response(response_data).unwrap();

        assert_eq!(response.status_code, 200);
        assert_eq!(response.headers.len(), 2);
        assert_eq!(response.body, b"{\"status\":\"ok\"}");
    }

    #[test]
    fn test_build_request() {
        let request_bytes = HttpProcessor::build_request(
            "GET",
            "/test",
            &[("Host", "example.com"), ("User-Agent", "vefas-core")],
            None,
        );

        let expected = b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: vefas-core\r\n\r\n";
        assert_eq!(request_bytes, expected);
    }

    #[test]
    fn test_build_request_with_body() {
        let body = b"{\"test\":true}";
        let request_bytes = HttpProcessor::build_request(
            "POST",
            "/api/data",
            &[
                ("Host", "api.example.com"),
                ("Content-Type", "application/json"),
            ],
            Some(body),
        );

        let request_str = String::from_utf8(request_bytes).unwrap();
        assert!(request_str.contains("POST /api/data HTTP/1.1"));
        assert!(request_str.contains("Content-Length: 13"));
        assert!(request_str.contains("{\"test\":true}"));
    }

    #[test]
    fn test_extract_http_data() {
        let mut processor = HttpProcessor::new();
        let request_data = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let response_data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello World";

        let http_data = processor
            .extract_http_data(request_data, response_data)
            .unwrap();

        assert_eq!(http_data.method, "GET");
        assert_eq!(http_data.path, "/test");
        assert_eq!(http_data.status_code, 200);
        assert_eq!(http_data.response_body, b"Hello World");
    }

    #[test]
    fn test_incomplete_request_fails() {
        let processor = HttpProcessor::new();
        let incomplete_data = b"GET /test HTTP/1.1\r\nHost: exam";

        let result = processor.parse_http_request(incomplete_data);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VefasCoreError::HttpError { .. }
        ));
    }
}
