//! HTTP Verification Tests for zkTLS Verification
//!
//! This module contains comprehensive TDD tests for HTTP verification
//! functionality in the zkVM guest program, following TLS 1.3 specification (RFC 8446).

#[cfg(feature = "sp1")]
mod http_verification_tests {
    use zktls_zkvm::types::*;
    use zktls_zkvm::guest::{HandshakeData, SessionKeys, verify_http_exchange};
    use zktls_core::http::{HttpRequest, HttpResponse, HttpMethod};
    use zktls_crypto::native::NativeCryptoProvider;
    use zktls_crypto::Hash;
    
    mod fixtures;
    use fixtures::*;

    /// Test HTTP request parsing from raw bytes
    #[test]
    fn test_http_request_parsing() {
        let request_data = SIMPLE_GET_REQUEST;
        
        let request = HttpRequest::parse(request_data)
            .expect("Failed to parse HTTP request");
        
        // Verify request structure
        assert_eq!(*request.method(), HttpMethod::Get);
        assert_eq!(request.path(), "/api/data");
        assert_eq!(request.version(), "HTTP/1.1");
        assert_eq!(request.header("host"), Some(&"example.com".to_string()));
        assert_eq!(request.header("connection"), Some(&"close".to_string()));
        assert!(request.body().is_empty());
    }

    /// Test HTTP response parsing from raw bytes
    #[test]
    fn test_http_response_parsing() {
        let response_data = SIMPLE_GET_RESPONSE;
        
        let response = HttpResponse::parse(response_data)
            .expect("Failed to parse HTTP response");
        
        // Verify response structure
        assert_eq!(response.status(), 200);
        assert_eq!(response.reason_phrase(), "OK");
        assert_eq!(response.version(), "HTTP/1.1");
        assert_eq!(response.header("content-type"), Some(&"application/json".to_string()));
        assert_eq!(response.header("content-length"), Some(&"20".to_string()));
        assert_eq!(response.body(), b"{\"status\":\"success\"}");
    }

    /// Test HTTP request with POST method and JSON body
    #[test]
    fn test_http_post_request_parsing() {
        let request_data = POST_JSON_REQUEST;
        
        let request = HttpRequest::parse(request_data)
            .expect("Failed to parse POST request");
        
        // Verify request structure
        assert_eq!(*request.method(), HttpMethod::Post);
        assert_eq!(request.path(), "/api/submit");
        assert_eq!(request.header("content-type"), Some(&"application/json".to_string()));
        assert_eq!(request.header("content-length"), Some(&"15".to_string()));
        assert_eq!(request.body(), b"{\"key\":\"value\"}");
    }

    /// Test HTTP response with error status
    #[test]
    fn test_http_error_response_parsing() {
        let response_data = ERROR_RESPONSE;
        
        let response = HttpResponse::parse(response_data)
            .expect("Failed to parse error response");
        
        // Verify response structure
        assert_eq!(response.status(), 404);
        assert_eq!(response.reason_phrase(), "Not Found");
        assert_eq!(response.header("content-type"), Some(&"text/html".to_string()));
        assert_eq!(response.body(), b"<h1>404 Not Found</h1>");
    }

    /// Test HTTP verification with simple GET request/response
    #[test]
    fn test_http_verification_simple_get() {
        let session_keys = create_test_session_keys();
        
        // Test with simple GET request/response
        let result = verify_http_exchange(
            SIMPLE_GET_REQUEST,
            SIMPLE_GET_RESPONSE,
            &session_keys
        ).expect("HTTP verification should succeed");
        
        // Verify result structure
        assert_eq!(result.status_code, 200);
        assert!(!result.request_headers.is_empty());
        assert!(!result.response_headers.is_empty());
        assert_eq!(result.request_body, b"");
        assert_eq!(result.response_body, b"{\"status\":\"success\"}");
        
        // Verify specific headers
        assert!(result.request_headers.iter().any(|(k, v)| k == "host" && v == "example.com"));
        assert!(result.response_headers.iter().any(|(k, v)| k == "content-type" && v == "application/json"));
    }

    /// Test HTTP verification with POST request/response
    #[test]
    fn test_http_verification_post_request() {
        let session_keys = create_test_session_keys();
        
        // Test with POST request/response
        let result = verify_http_exchange(
            POST_JSON_REQUEST,
            POST_JSON_RESPONSE,
            &session_keys
        ).expect("HTTP verification should succeed");
        
        // Verify result structure
        assert_eq!(result.status_code, 201);
        assert!(!result.request_headers.is_empty());
        assert!(!result.response_headers.is_empty());
        assert_eq!(result.request_body, b"{\"key\":\"value\"}");
        assert_eq!(result.response_body, b"{\"id\":123,\"status\":\"created\"}");
        
        // Verify specific headers
        assert!(result.request_headers.iter().any(|(k, v)| k == "content-type" && v == "application/json"));
        assert!(result.response_headers.iter().any(|(k, v)| k == "location" && v == "/api/submit/123"));
    }

    /// Test HTTP verification with error response
    #[test]
    fn test_http_verification_error_response() {
        let session_keys = create_test_session_keys();
        
        // Test with error response
        let result = verify_http_exchange(
            SIMPLE_GET_REQUEST,
            ERROR_RESPONSE,
            &session_keys
        ).expect("HTTP verification should succeed");
        
        // Verify result structure
        assert_eq!(result.status_code, 404);
        assert_eq!(result.response_body, b"<h1>404 Not Found</h1>");
        
        // Verify error headers
        assert!(result.response_headers.iter().any(|(k, v)| k == "content-type" && v == "text/html"));
    }

    /// Test HTTP verification with malformed request
    #[test]
    fn test_http_verification_malformed_request() {
        let session_keys = create_test_session_keys();
        
        // Test with malformed request
        let result = verify_http_exchange(
            MALFORMED_REQUEST,
            SIMPLE_GET_RESPONSE,
            &session_keys
        );
        
        // Should fail with malformed request
        assert!(result.is_err(), "Should fail with malformed request");
    }

    /// Test HTTP verification with malformed response
    #[test]
    fn test_http_verification_malformed_response() {
        let session_keys = create_test_session_keys();
        
        // Test with malformed response
        let result = verify_http_exchange(
            SIMPLE_GET_REQUEST,
            MALFORMED_RESPONSE,
            &session_keys
        );
        
        // Should fail with malformed response
        assert!(result.is_err(), "Should fail with malformed response");
    }

    /// Test HTTP verification with empty request
    #[test]
    fn test_http_verification_empty_request() {
        let session_keys = create_test_session_keys();
        
        // Test with empty request
        let result = verify_http_exchange(
            &[],
            SIMPLE_GET_RESPONSE,
            &session_keys
        );
        
        // Should fail with empty request
        assert!(result.is_err(), "Should fail with empty request");
    }

    /// Test HTTP verification with empty response
    #[test]
    fn test_http_verification_empty_response() {
        let session_keys = create_test_session_keys();
        
        // Test with empty response
        let result = verify_http_exchange(
            SIMPLE_GET_REQUEST,
            &[],
            &session_keys
        );
        
        // Should fail with empty response
        assert!(result.is_err(), "Should fail with empty response");
    }

    /// Test HTTP verification performance
    #[test]
    fn test_http_verification_performance() {
        let session_keys = create_test_session_keys();
        
        // Measure verification time
        let start = std::time::Instant::now();
        
        for _ in 0..100 {
            let _result = verify_http_exchange(
                SIMPLE_GET_REQUEST,
                SIMPLE_GET_RESPONSE,
                &session_keys
            ).expect("HTTP verification should succeed");
        }
        
        let duration = start.elapsed();
        let avg_time = duration.as_millis() / 100;
        
        // HTTP verification should be fast (under 5ms per operation)
        assert!(avg_time < 5, "HTTP verification should be fast, got {}ms average", avg_time);
    }

    /// Test HTTP verification with different content types
    #[test]
    fn test_http_verification_different_content_types() {
        let session_keys = create_test_session_keys();
        
        let test_cases = vec![
            (HTML_REQUEST, HTML_RESPONSE, "text/html"),
            (XML_REQUEST, XML_RESPONSE, "application/xml"),
            (TEXT_REQUEST, TEXT_RESPONSE, "text/plain"),
        ];
        
        for (request_data, response_data, expected_content_type) in test_cases {
            let result = verify_http_exchange(
                request_data,
                response_data,
                &session_keys
            ).expect("HTTP verification should succeed");
            
            // Verify content type header
            assert!(result.response_headers.iter().any(|(k, v)| 
                k.to_lowercase() == "content-type" && v.contains(expected_content_type)
            ), "Should have correct content type: {}", expected_content_type);
        }
    }

    /// Test HTTP verification with large payloads
    #[test]
    fn test_http_verification_large_payloads() {
        let session_keys = create_test_session_keys();
        
        // Test with large request/response
        let result = verify_http_exchange(
            LARGE_REQUEST,
            LARGE_RESPONSE,
            &session_keys
        ).expect("HTTP verification should succeed");
        
        // Verify large payload handling
        assert!(result.request_body.len() > 1000, "Should handle large request body");
        assert!(result.response_body.len() > 1000, "Should handle large response body");
        
        // Verify content length headers
        assert!(result.request_headers.iter().any(|(k, v)| 
            k.to_lowercase() == "content-length" && v.parse::<usize>().unwrap() > 1000
        ));
        assert!(result.response_headers.iter().any(|(k, v)| 
            k.to_lowercase() == "content-length" && v.parse::<usize>().unwrap() > 1000
        ));
    }

    /// Test HTTP verification with chunked encoding
    #[test]
    fn test_http_verification_chunked_encoding() {
        let session_keys = create_test_session_keys();
        
        // Test with chunked response
        let result = verify_http_exchange(
            SIMPLE_GET_REQUEST,
            CHUNKED_RESPONSE,
            &session_keys
        ).expect("HTTP verification should succeed");
        
        // Verify chunked encoding handling
        assert!(result.response_headers.iter().any(|(k, v)| 
            k.to_lowercase() == "transfer-encoding" && v == "chunked"
        ));
        
        // Verify body is properly reconstructed
        assert_eq!(result.response_body, b"Hello, World! This is chunked data.");
    }

    /// Create test session keys for HTTP verification
    fn create_test_session_keys() -> SessionKeys {
        SessionKeys {
            handshake_secret: [0x01; 32],
            master_secret: [0x02; 32],
            client_write_key: [0x03; 16],
            server_write_key: [0x04; 16],
            client_write_iv: [0x05; 12],
            server_write_iv: [0x06; 12],
        }
    }
}
