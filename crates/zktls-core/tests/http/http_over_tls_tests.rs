//! Integration Tests for HTTP-over-TLS
//!
//! This module tests the complete integration of HTTP message framing
//! with TLS application data encryption/decryption.

#[cfg(test)]
mod tests {
    use zktls_core::tls::application::{ApplicationDataHandler, HttpMessage};
    use zktls_core::tls::TlsRecord;
    use std::collections::BTreeMap;

    #[test]
    fn test_http_request_over_tls_encryption() {
        // Create an HTTP request
        let mut headers = BTreeMap::new();
        headers.insert("Host".to_string(), "api.example.com".to_string());
        headers.insert("User-Agent".to_string(), "zkTLS/1.0".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Content-Length".to_string(), "25".to_string());

        let body = b"{\"query\": \"test data\"}".to_vec();
        let request = HttpMessage::request("POST", "/api/v1/data", "HTTP/1.1", headers, body);
        let http_bytes = request.serialize();

        // Encrypt the HTTP request using TLS application data handler
        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0x42u8; 32]; // Mock traffic key
        let sequence_number = 1;

        let encrypted_record = handler
            .create_encrypted_record(&http_bytes, &traffic_key, sequence_number)
            .unwrap();

        // Verify it's an application data record
        assert!(encrypted_record.is_application_data());
        assert!(encrypted_record.fragment.len() > http_bytes.len()); // Should be larger due to encryption

        // Decrypt and parse back
        let decrypted_bytes = handler
            .decrypt_record(&encrypted_record, &traffic_key, sequence_number)
            .unwrap();

        let decrypted_request = HttpMessage::parse_request(&decrypted_bytes).unwrap();
        
        // Verify the request was preserved
        assert_eq!(decrypted_request.method(), "POST");
        assert_eq!(decrypted_request.path(), "/api/v1/data");
        assert_eq!(decrypted_request.header("Host"), Some("api.example.com"));
        assert_eq!(decrypted_request.body(), b"{\"query\": \"test data\"}");
    }

    #[test]
    fn test_http_response_over_tls_encryption() {
        // Create an HTTP response
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Content-Length".to_string(), "27".to_string());
        headers.insert("Server".to_string(), "nginx/1.18.0".to_string());

        let body = b"{\"result\": \"success\"}".to_vec();
        let response = HttpMessage::response("HTTP/1.1", 200, "OK", headers, body);
        let http_bytes = response.serialize();

        // Encrypt the HTTP response using TLS application data handler
        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0x99u8; 32]; // Different traffic key
        let sequence_number = 5;

        let encrypted_record = handler
            .create_encrypted_record(&http_bytes, &traffic_key, sequence_number)
            .unwrap();

        // Decrypt and parse back
        let decrypted_bytes = handler
            .decrypt_record(&encrypted_record, &traffic_key, sequence_number)
            .unwrap();

        let decrypted_response = HttpMessage::parse_response(&decrypted_bytes).unwrap();
        
        // Verify the response was preserved
        assert_eq!(decrypted_response.status_code(), 200);
        assert_eq!(decrypted_response.reason_phrase(), "OK");
        assert_eq!(decrypted_response.header("Content-Type"), Some("application/json"));
        assert_eq!(decrypted_response.body(), b"{\"result\": \"success\"}");
    }

    #[test]
    fn test_multiple_http_requests_with_sequence_numbers() {
        // Test multiple HTTP requests with different sequence numbers
        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0xAAu8; 32];

        // First request
        let headers1 = BTreeMap::from([
            ("Host".to_string(), "example.com".to_string()),
            ("Connection".to_string(), "keep-alive".to_string()),
        ]);
        let request1 = HttpMessage::request("GET", "/", "HTTP/1.1", headers1, vec![]);
        let http_bytes1 = request1.serialize();

        let encrypted_record1 = handler
            .create_encrypted_record(&http_bytes1, &traffic_key, 0)
            .unwrap();

        // Second request
        let headers2 = BTreeMap::from([
            ("Host".to_string(), "example.com".to_string()),
            ("Connection".to_string(), "keep-alive".to_string()),
        ]);
        let request2 = HttpMessage::request("GET", "/about", "HTTP/1.1", headers2, vec![]);
        let http_bytes2 = request2.serialize();

        let encrypted_record2 = handler
            .create_encrypted_record(&http_bytes2, &traffic_key, 1)
            .unwrap();

        // Verify different sequence numbers produce different ciphertext
        assert_ne!(encrypted_record1.fragment, encrypted_record2.fragment);

        // Decrypt both with correct sequence numbers
        let decrypted1 = handler.decrypt_record(&encrypted_record1, &traffic_key, 0).unwrap();
        let decrypted2 = handler.decrypt_record(&encrypted_record2, &traffic_key, 1).unwrap();

        let parsed1 = HttpMessage::parse_request(&decrypted1).unwrap();
        let parsed2 = HttpMessage::parse_request(&decrypted2).unwrap();

        assert_eq!(parsed1.path(), "/");
        assert_eq!(parsed2.path(), "/about");
    }

    #[test]
    fn test_chunked_http_response_over_tls() {
        // Test HTTP response with chunked encoding over TLS
        let raw_response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nd\r\nHello, World!\r\n0\r\n\r\n";
        
        // Parse as HTTP first
        let response = HttpMessage::parse_response(raw_response).unwrap();
        assert_eq!(response.body(), b"Hello, World!");

        // Encrypt over TLS
        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0x77u8; 32];
        let sequence_number = 3;

        let encrypted_record = handler
            .create_encrypted_record(raw_response, &traffic_key, sequence_number)
            .unwrap();

        // Decrypt and parse
        let decrypted_raw = handler
            .decrypt_record(&encrypted_record, &traffic_key, sequence_number)
            .unwrap();

        let decrypted_response = HttpMessage::parse_response(&decrypted_raw).unwrap();
        assert_eq!(decrypted_response.body(), b"Hello, World!");
    }

    #[test]
    fn test_large_http_payload_over_tls() {
        // Test larger HTTP payloads (multi-KB)
        let large_body = vec![b'X'; 4096]; // 4KB payload
        
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".to_string(), "text/plain".to_string());
        headers.insert("Content-Length".to_string(), "4096".to_string());

        let response = HttpMessage::response("HTTP/1.1", 200, "OK", headers, large_body.clone());
        let http_bytes = response.serialize();

        // Encrypt
        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0x55u8; 32];
        let sequence_number = 10;

        let encrypted_record = handler
            .create_encrypted_record(&http_bytes, &traffic_key, sequence_number)
            .unwrap();

        // Verify encryption worked for large payload
        assert!(encrypted_record.fragment.len() > http_bytes.len());

        // Decrypt and verify
        let decrypted_bytes = handler
            .decrypt_record(&encrypted_record, &traffic_key, sequence_number)
            .unwrap();

        let decrypted_response = HttpMessage::parse_response(&decrypted_bytes).unwrap();
        assert_eq!(decrypted_response.body(), large_body.as_slice());
    }

    #[test]
    fn test_http_over_tls_authentication_failure() {
        // Test that tampered HTTP over TLS fails authentication
        let headers = BTreeMap::from([
            ("Host".to_string(), "secure.example.com".to_string()),
        ]);
        let request = HttpMessage::request("GET", "/secure", "HTTP/1.1", headers, vec![]);
        let http_bytes = request.serialize();

        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0x33u8; 32];
        let sequence_number = 7;

        let mut encrypted_record = handler
            .create_encrypted_record(&http_bytes, &traffic_key, sequence_number)
            .unwrap();

        // Tamper with encrypted data
        if let Some(last_byte) = encrypted_record.fragment.last_mut() {
            *last_byte = last_byte.wrapping_add(1);
        }

        // Decryption should fail
        let result = handler.decrypt_record(&encrypted_record, &traffic_key, sequence_number);
        assert!(result.is_err());
    }

    #[test]
    fn test_http_keep_alive_over_tls() {
        // Test HTTP keep-alive connection over TLS
        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0x11u8; 32];

        // Multiple requests on same connection
        for i in 0..3 {
            let headers = BTreeMap::from([
                ("Host".to_string(), "example.com".to_string()),
                ("Connection".to_string(), "keep-alive".to_string()),
            ]);
            
            let path = format!("/page{}", i);
            let request = HttpMessage::request("GET", &path, "HTTP/1.1", headers, vec![]);
            let http_bytes = request.serialize();

            let encrypted_record = handler
                .create_encrypted_record(&http_bytes, &traffic_key, i as u64)
                .unwrap();

            let decrypted_bytes = handler
                .decrypt_record(&encrypted_record, &traffic_key, i as u64)
                .unwrap();

            let decrypted_request = HttpMessage::parse_request(&decrypted_bytes).unwrap();
            assert_eq!(decrypted_request.path(), &path);
            assert_eq!(decrypted_request.header("Connection"), Some("keep-alive"));
        }
    }
}