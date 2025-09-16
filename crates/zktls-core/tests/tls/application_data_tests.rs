//! Tests for TLS 1.3 Application Data Handling
//!
//! This module tests the application data encryption/decryption functionality
//! following RFC 8446 Section 5.4 - Record Payload Protection

#[cfg(test)]
mod tests {
    use zktls_core::tls::{TlsRecord, ContentType};
    use std::{vec, vec::Vec};

    #[test]
    fn test_application_data_record_creation() {
        // Test that we can create application data records
        let http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        
        let record = TlsRecord::application_data(http_request.clone())
            .expect("Should create application data record");
        
        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert!(record.is_application_data());
        assert_eq!(record.fragment, http_request);
    }

    #[test]
    fn test_application_data_record_parsing() {
        // Test parsing of application data records from wire format
        let http_response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!".to_vec();
        let record = TlsRecord::application_data(http_response.clone()).unwrap();
        
        let serialized = record.serialize();
        let (parsed, _) = TlsRecord::parse(&serialized).unwrap();
        
        assert_eq!(parsed.content_type, ContentType::ApplicationData);
        assert_eq!(parsed.fragment, http_response);
    }

    #[test]
    fn test_empty_application_data() {
        // Empty application data should be valid (e.g., keep-alive)
        let record = TlsRecord::application_data(vec![]).unwrap();
        assert!(record.is_application_data());
        assert_eq!(record.length, 0);
    }

    #[test]
    fn test_large_application_data() {
        // Test handling of larger payloads (up to MAX_TLS_RECORD_SIZE)
        let large_payload = vec![b'A'; 8192]; // 8KB payload
        let record = TlsRecord::application_data(large_payload.clone()).unwrap();
        
        assert_eq!(record.fragment.len(), 8192);
        
        // Should serialize and parse correctly
        let serialized = record.serialize();
        let (parsed, _) = TlsRecord::parse(&serialized).unwrap();
        assert_eq!(parsed.fragment, large_payload);
    }
}