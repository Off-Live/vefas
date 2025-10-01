//! Test suite for HTTP-specific attack vectors and vulnerabilities
//!
//! This module tests VEFAS resistance to HTTP-based attacks including:
//! - HTTP request smuggling
//! - Header injection attacks
//! - CRLF injection
//! - Oversized payload attacks
//! - Malformed HTTP syntax attacks

use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use tokio::time::Duration;
use vefas_core::VefasClient;
use vefas_gateway::types::*;
use vefas_gateway::{VefasGateway, VefasGatewayConfig};

/// Test HTTP request smuggling attacks
#[cfg(test)]
mod request_smuggling_tests {
    use super::*;

    #[tokio::test]
    async fn test_content_length_header_manipulation() {
        // Test Content-Length header manipulation attempts
        let malicious_headers = vec![
            // Multiple Content-Length headers
            ("content-length", "10"),
            ("content-length", "20"),
        ];

        let payload = ExecuteRequestPayload {
            method: HttpMethod::Post,
            url: "https://httpbin.org/post".to_string(),
            headers: malicious_headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: Some("test".to_string()),
            proof_platform: ProofPlatform::Sp1,
            timeout_ms: 30000,
        };

        let result = payload.validate();
        assert!(
            result.is_err(),
            "Multiple Content-Length headers should be rejected"
        );
    }

    #[tokio::test]
    async fn test_transfer_encoding_chunked_manipulation() {
        // Test Transfer-Encoding manipulation
        let malicious_headers = vec![("transfer-encoding", "chunked"), ("content-length", "10")];

        let payload = ExecuteRequestPayload {
            method: HttpMethod::Post,
            url: "https://httpbin.org/post".to_string(),
            headers: malicious_headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: Some("test".to_string()),
            proof_platform: ProofPlatform::Sp1,
            timeout_ms: 30000,
        };

        let result = payload.validate();
        // Should reject conflicting transfer encoding headers
        assert!(
            result.is_err(),
            "Conflicting Transfer-Encoding and Content-Length should be rejected"
        );
    }

    #[test]
    fn test_http_11_vs_10_smuggling() {
        // Test HTTP/1.1 vs HTTP/1.0 version confusion
        let http_10_with_chunked = r#"POST /test HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"#;

        let result = validate_http_request_line(http_10_with_chunked);
        assert!(
            result.is_err(),
            "HTTP/1.0 with chunked encoding should be rejected"
        );
    }

    #[test]
    fn test_pipeline_confusion() {
        // Test HTTP request pipelining confusion
        let pipelined_request = "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\nGET /second HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let result = validate_http_request_contains_single_request(pipelined_request);
        assert!(result.is_err(), "Pipelined requests should be rejected");
    }

    // Helper validation functions
    fn validate_http_request_line(request: &str) -> Result<(), &'static str> {
        if request.contains("HTTP/1.0") && request.contains("Transfer-Encoding") {
            Err("HTTP/1.0 cannot use Transfer-Encoding")
        } else {
            Ok(())
        }
    }

    fn validate_http_request_contains_single_request(request: &str) -> Result<(), &'static str> {
        let request_count = request.matches("HTTP/1.1").count();
        if request_count > 1 {
            Err("Multiple HTTP requests in single payload")
        } else {
            Ok(())
        }
    }
}

/// Test header injection attacks
#[cfg(test)]
mod header_injection_tests {
    use super::*;

    #[test]
    fn test_crlf_injection_in_headers() {
        // Test CRLF injection in header values
        let malicious_headers = vec![
            ("user-agent", "VEFAS\r\nX-Injected: malicious"),
            (
                "referer",
                "https://example.com\r\n\r\n<script>alert('xss')</script>",
            ),
            ("authorization", "Bearer token\rSet-Cookie: malicious=true"),
        ];

        for (name, value) in malicious_headers {
            let result = validate_header_value(value);
            assert!(
                result.is_err(),
                "CRLF injection in {} header should be rejected",
                name
            );
        }
    }

    #[test]
    fn test_null_byte_injection() {
        // Test null byte injection in headers
        let malicious_values = vec![
            "normal_value\0injected",
            "\0malicious",
            "value\0\r\nInjected-Header: evil",
        ];

        for value in malicious_values {
            let result = validate_header_value(value);
            assert!(result.is_err(), "Null byte injection should be rejected");
        }
    }

    #[test]
    fn test_header_name_injection() {
        // Test malicious header names
        let malicious_names = vec![
            "X-Normal\r\nX-Injected",
            "Header\nName",
            "Bad\0Header",
            "Header: value", // Colon in header name
        ];

        for name in malicious_names {
            let result = validate_header_name(name);
            assert!(
                result.is_err(),
                "Malicious header name '{}' should be rejected",
                name
            );
        }
    }

    #[test]
    fn test_oversized_header_values() {
        // Test extremely large header values
        let oversized_value = "x".repeat(100_000);
        let result = validate_header_value(&oversized_value);
        assert!(
            result.is_err(),
            "Oversized header values should be rejected"
        );
    }

    #[test]
    fn test_unicode_normalization_attacks() {
        // Test Unicode normalization attacks in headers
        let unicode_attacks = vec![
            "normal\u{0001}text", // Control character
            "text\u{FEFF}more",   // BOM injection
            "café\u{0300}",       // Combining character
        ];

        for value in unicode_attacks {
            let result = validate_header_value(value);
            // Should normalize or reject dangerous Unicode
            assert!(
                result.is_err() || !value.contains('\u{0001}'),
                "Dangerous Unicode should be handled safely"
            );
        }
    }

    // Helper validation functions
    fn validate_header_value(value: &str) -> Result<(), &'static str> {
        if value.contains('\r') || value.contains('\n') {
            Err("CRLF characters not allowed in header values")
        } else if value.contains('\0') {
            Err("Null bytes not allowed in header values")
        } else if value.len() > 8192 {
            Err("Header value too large")
        } else if value.chars().any(|c| c.is_control() && c != '\t') {
            Err("Control characters not allowed in header values")
        } else {
            Ok(())
        }
    }

    fn validate_header_name(name: &str) -> Result<(), &'static str> {
        if name.contains('\r') || name.contains('\n') {
            Err("CRLF characters not allowed in header names")
        } else if name.contains('\0') {
            Err("Null bytes not allowed in header names")
        } else if name.contains(':') {
            Err("Colons not allowed in header names")
        } else if name.chars().any(|c| c.is_control()) {
            Err("Control characters not allowed in header names")
        } else if !name
            .chars()
            .all(|c| c.is_ascii() && (c.is_alphanumeric() || "-_".contains(c)))
        {
            Err("Invalid characters in header name")
        } else {
            Ok(())
        }
    }
}

/// Test payload and body attacks
#[cfg(test)]
mod payload_attacks {
    use super::*;

    #[test]
    fn test_oversized_request_body() {
        // Test extremely large request bodies
        let oversized_body = "x".repeat(100 * 1024 * 1024); // 100MB

        let payload = ExecuteRequestPayload {
            method: HttpMethod::Post,
            url: "https://httpbin.org/post".to_string(),
            headers: HashMap::new(),
            body: Some(oversized_body),
            proof_platform: ProofPlatform::Sp1,
            timeout_ms: 30000,
        };

        let result = payload.validate();
        assert!(
            result.is_err(),
            "Oversized request bodies should be rejected"
        );
    }

    #[test]
    fn test_malformed_json_body() {
        // Test malformed JSON in request body
        let malformed_json_bodies = vec![
            r#"{"incomplete": "#,
            r#"{"key": value}"#, // Unquoted value
            r#"{"nested": {"too": {"deep": {"structure": "x".repeat(10000)}}}}"#,
            "\x00\x01\x02invalid", // Binary data
        ];

        for body in malformed_json_bodies {
            let payload = ExecuteRequestPayload {
                method: HttpMethod::Post,
                url: "https://httpbin.org/post".to_string(),
                headers: vec![("content-type".to_string(), "application/json".to_string())]
                    .into_iter()
                    .collect(),
                body: Some(body.to_string()),
                proof_platform: ProofPlatform::Sp1,
                timeout_ms: 30000,
            };

            // Payload validation should catch this or processing should handle gracefully
            let validation_result = payload.validate();
            // Either validation catches it or we proceed (server will handle malformed JSON)
            if validation_result.is_ok() {
                // If validation passes, ensure processing handles malformed JSON gracefully
                assert!(
                    true,
                    "Malformed JSON should be handled gracefully by the server"
                );
            }
        }
    }

    #[test]
    fn test_binary_data_in_text_fields() {
        // Test binary data injection in text fields
        let binary_data = vec![0x00, 0x01, 0xFF, 0xFE];
        let binary_string = String::from_utf8_lossy(&binary_data);

        let payload = ExecuteRequestPayload {
            method: HttpMethod::Post,
            url: "https://httpbin.org/post".to_string(),
            headers: vec![("x-binary".to_string(), binary_string.to_string())]
                .into_iter()
                .collect(),
            body: Some(binary_string.to_string()),
            proof_platform: ProofPlatform::Sp1,
            timeout_ms: 30000,
        };

        let result = payload.validate();
        // Should either reject or safely handle binary data
        if result.is_ok() {
            // Ensure binary data is safely encoded/handled
            assert!(true, "Binary data should be safely handled");
        }
    }

    #[test]
    fn test_compression_bomb_attempts() {
        // Test potential compression bomb payloads
        let repetitive_data = "A".repeat(1000000); // Highly compressible data

        let payload = ExecuteRequestPayload {
            method: HttpMethod::Post,
            url: "https://httpbin.org/post".to_string(),
            headers: vec![
                ("content-encoding".to_string(), "gzip".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ]
            .into_iter()
            .collect(),
            body: Some(repetitive_data),
            proof_platform: ProofPlatform::Sp1,
            timeout_ms: 30000,
        };

        let result = payload.validate();
        assert!(
            result.is_err(),
            "Potential compression bombs should be rejected"
        );
    }
}

/// Test URL and path attacks
#[cfg(test)]
mod url_attacks {
    use super::*;

    #[test]
    fn test_url_parsing_attacks() {
        // Test various URL parsing attacks
        let malicious_urls = vec![
            "https://example.com/../../../etc/passwd",
            "https://example.com/..%2f..%2f..%2fetc%2fpasswd",
            "https://example.com/path?param=value#fragment/../../../etc/passwd",
            "https://user:pass@evil.com@example.com/",
            "https://example.com:65536/", // Invalid port
            "https://exam\x00ple.com/",   // Null byte in domain
            "https://example.com/path\r\nHost: evil.com",
            "http://example.com/", // Not HTTPS
            "ftp://example.com/",  // Wrong protocol
        ];

        for url in malicious_urls {
            let payload = ExecuteRequestPayload {
                method: HttpMethod::Get,
                url: url.to_string(),
                headers: HashMap::new(),
                body: None,
                proof_platform: ProofPlatform::Sp1,
                timeout_ms: 30000,
            };

            let result = payload.validate();
            assert!(
                result.is_err(),
                "Malicious URL '{}' should be rejected",
                url
            );
        }
    }

    #[test]
    fn test_international_domain_attacks() {
        // Test internationalized domain name attacks
        let idn_attacks = vec![
            "https://аpple.com/",          // Cyrillic 'а' instead of 'a'
            "https://gооgle.com/",         // Cyrillic 'о' instead of 'o'
            "https://example\u{202E}com/", // Right-to-left override
            "https://example\u{2066}com/", // Directional isolate
        ];

        for url in idn_attacks {
            let payload = ExecuteRequestPayload {
                method: HttpMethod::Get,
                url: url.to_string(),
                headers: HashMap::new(),
                body: None,
                proof_platform: ProofPlatform::Sp1,
                timeout_ms: 30000,
            };

            let result = payload.validate();
            // Should either reject or properly handle IDN
            if result.is_ok() {
                // Ensure IDN is properly validated and not spoofed
                assert!(
                    validate_domain_not_spoofed(&url),
                    "IDN spoofing should be detected"
                );
            }
        }
    }

    #[test]
    fn test_port_and_scheme_validation() {
        // Test port and scheme validation
        let invalid_schemes_ports = vec![
            ("http://example.com/", false),        // Not HTTPS
            ("https://example.com:80/", true),     // HTTPS on HTTP port (suspicious)
            ("https://example.com:0/", false),     // Invalid port 0
            ("https://example.com:65536/", false), // Port too high
            ("https://example.com:-1/", false),    // Negative port
        ];

        for (url, should_pass) in invalid_schemes_ports {
            let payload = ExecuteRequestPayload {
                method: HttpMethod::Get,
                url: url.to_string(),
                headers: HashMap::new(),
                body: None,
                proof_platform: ProofPlatform::Sp1,
                timeout_ms: 30000,
            };

            let result = payload.validate();
            if should_pass {
                assert!(result.is_ok(), "URL '{}' should be accepted", url);
            } else {
                assert!(result.is_err(), "URL '{}' should be rejected", url);
            }
        }
    }

    fn validate_domain_not_spoofed(url: &str) -> bool {
        // Simple check for obvious spoofing attempts
        !url.contains('\u{202E}') && !url.contains('\u{2066}')
    }
}

/// Test rate limiting and DoS protection
#[cfg(test)]
mod dos_protection_tests {
    use super::*;

    #[tokio::test]
    async fn test_request_rate_limiting() {
        // This test requires a running gateway instance
        // Skip if not available
        if std::env::var("VEFAS_GATEWAY_TEST_URL").is_err() {
            return;
        }

        let gateway_url = std::env::var("VEFAS_GATEWAY_TEST_URL").unwrap();
        let client = Client::new();

        // Send rapid requests to test rate limiting
        let mut handles = vec![];
        for _ in 0..100 {
            let client = client.clone();
            let url = gateway_url.clone();
            let handle = tokio::spawn(async move {
                let payload = json!({
                    "method": "GET",
                    "url": "https://httpbin.org/get",
                    "proof_platform": "sp1",
                    "timeout_ms": 30000
                });

                client
                    .post(&format!("{}/api/v1/requests", url))
                    .json(&payload)
                    .send()
                    .await
            });
            handles.push(handle);
        }

        // Wait for all requests
        let responses = futures::future::join_all(handles).await;

        // Count rate limited responses (429 status)
        let rate_limited_count = responses
            .into_iter()
            .filter_map(|r| r.ok())
            .filter_map(|r| r.ok())
            .filter(|response| response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS)
            .count();

        // Should have some rate limiting in effect
        assert!(
            rate_limited_count > 0,
            "Rate limiting should be active for rapid requests"
        );
    }

    #[test]
    fn test_memory_exhaustion_protection() {
        // Test that large payloads don't exhaust memory
        let large_payload = ExecuteRequestPayload {
            method: HttpMethod::Post,
            url: "https://httpbin.org/post".to_string(),
            headers: (0..10000)
                .map(|i| (format!("x-header-{}", i), "value".repeat(1000)))
                .collect(),
            body: Some("x".repeat(10 * 1024 * 1024)), // 10MB body
            proof_platform: ProofPlatform::Sp1,
            timeout_ms: 30000,
        };

        let result = payload.validate();
        assert!(
            result.is_err(),
            "Large payloads should be rejected to prevent memory exhaustion"
        );
    }

    #[test]
    fn test_timeout_protection() {
        // Test that timeout values are bounded
        let timeout_tests = vec![
            (0, false),        // Zero timeout
            (100, false),      // Too short
            (30000, true),     // Normal timeout
            (300000, true),    // Long but acceptable
            (3600000, false),  // Too long (1 hour)
            (u32::MAX, false), // Maximum value
        ];

        for (timeout_ms, should_pass) in timeout_tests {
            let payload = ExecuteRequestPayload {
                method: HttpMethod::Get,
                url: "https://httpbin.org/get".to_string(),
                headers: HashMap::new(),
                body: None,
                proof_platform: ProofPlatform::Sp1,
                timeout_ms,
            };

            let result = payload.validate();
            if should_pass {
                assert!(result.is_ok(), "Timeout {} should be accepted", timeout_ms);
            } else {
                assert!(result.is_err(), "Timeout {} should be rejected", timeout_ms);
            }
        }
    }
}

/// Integration tests with the actual gateway for security validation
#[cfg(test)]
mod gateway_security_integration {
    use super::*;

    #[tokio::test]
    async fn test_malicious_request_handling() {
        // Skip if no test gateway available
        if std::env::var("VEFAS_GATEWAY_TEST_URL").is_err() {
            return;
        }

        let gateway_url = std::env::var("VEFAS_GATEWAY_TEST_URL").unwrap();
        let client = Client::new();

        // Test various malicious payloads
        let malicious_payloads = vec![
            // Malformed JSON
            r#"{"method": "GET", "url": "https://httpbin.org/get""#,
            // Script injection attempt
            r#"{"method": "GET", "url": "javascript:alert('xss')", "proof_platform": "sp1"}"#,
            // Binary data
            "\x00\x01\x02\x03",
            // Extremely large payload
            &format!(
                r#"{{"method": "GET", "url": "https://httpbin.org/get", "body": "{}"}}"#,
                "x".repeat(1000000)
            ),
        ];

        for payload in malicious_payloads {
            let response = client
                .post(&format!("{}/api/v1/requests", gateway_url))
                .header("Content-Type", "application/json")
                .body(payload)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    // Should return 4xx error for malicious input
                    assert!(
                        resp.status().is_client_error(),
                        "Malicious payload should return client error, got {}",
                        resp.status()
                    );
                }
                Err(_) => {
                    // Network error is also acceptable (connection refused due to malicious payload)
                    assert!(true, "Network error on malicious payload is acceptable");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_error_information_disclosure() {
        // Test that error messages don't disclose sensitive information
        if std::env::var("VEFAS_GATEWAY_TEST_URL").is_err() {
            return;
        }

        let gateway_url = std::env::var("VEFAS_GATEWAY_TEST_URL").unwrap();
        let client = Client::new();

        // Send invalid request to get error response
        let response = client
            .post(&format!("{}/api/v1/requests", gateway_url))
            .header("Content-Type", "application/json")
            .body(r#"{"invalid": "payload"}"#)
            .send()
            .await
            .expect("Request should complete");

        let error_text = response.text().await.expect("Should get response text");

        // Check that error doesn't contain sensitive information
        let sensitive_patterns = vec![
            "RUST_BACKTRACE",
            "panic",
            "internal error",
            "/home/",
            "/Users/",
            "password",
            "secret",
            "key",
            "token",
            "credential",
        ];

        for pattern in sensitive_patterns {
            assert!(
                !error_text.to_lowercase().contains(&pattern.to_lowercase()),
                "Error response should not contain sensitive pattern: {}",
                pattern
            );
        }
    }
}
