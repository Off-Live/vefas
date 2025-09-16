//! TLS handshake parsing tests
//! 
//! These tests verify the TLS 1.3 handshake parsing functionality
//! following TDD principles from REQUIREMENTS.md.

mod fixtures;

#[cfg(feature = "sp1")]
mod tls_handshake_tests {
    use zktls_zkvm::*;
    use zktls_zkvm::guest::parse_handshake_transcript;
    use crate::fixtures::tls_handshake_data::*;

    #[test]
    fn test_parse_client_hello() {
        // Test parsing ClientHello message (with handshake header)
        let client_hello = CLIENT_HELLO; // Include handshake header
        println!("ClientHello data length: {}", client_hello.len());
        println!("First 20 bytes: {:?}", &client_hello[..20.min(client_hello.len())]);
        let result = parse_handshake_transcript(client_hello);
        
        // This should fail initially (Red phase)
        match &result {
            Ok(_) => {},
            Err(e) => {
                panic!("ClientHello parsing failed: {:?}", e);
            }
        }
        assert!(result.is_ok(), "ClientHello parsing should succeed");
        
        let handshake_data = result.unwrap();
        assert_eq!(handshake_data.tls_version, "1.3");
        assert_eq!(handshake_data.cipher_suite, "TLS_AES_128_GCM_SHA256");
        
        // Verify client random extraction
        let expected_client_random = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        assert_eq!(handshake_data.client_random, expected_client_random);
        
        // Verify key exchange parameters extraction
        assert!(!handshake_data.key_exchange_params.is_empty());
        assert_eq!(handshake_data.key_exchange_params.len(), 32);
    }

    #[test]
    fn test_parse_server_hello() {
        // Test parsing ServerHello message (with handshake header)
        let server_hello = SERVER_HELLO; // Include handshake header
        let result = parse_handshake_transcript(server_hello);
        
        // This should fail initially (Red phase)
        if let Err(e) = &result {
            panic!("ServerHello parsing failed: {}", e);
        }
        assert!(result.is_ok(), "ServerHello parsing should succeed");
        
        let handshake_data = result.unwrap();
        assert_eq!(handshake_data.tls_version, "1.3");
        assert_eq!(handshake_data.cipher_suite, "TLS_AES_128_GCM_SHA256");
        
        // Verify server random extraction
        let expected_server_random = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
            0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        ];
        assert_eq!(handshake_data.server_random, expected_server_random);
    }

    #[test]
    fn test_parse_complete_handshake_transcript() {
        // Test parsing complete handshake transcript
        let transcript = COMPLETE_HANDSHAKE_TRANSCRIPT;
        let result = parse_handshake_transcript(transcript);
        
        // This should fail initially (Red phase)
        if let Err(e) = &result {
            panic!("Complete handshake parsing failed: {}", e);
        }
        
        let handshake_data = result.unwrap();
        assert_eq!(handshake_data.tls_version, "1.3");
        assert_eq!(handshake_data.cipher_suite, "TLS_AES_128_GCM_SHA256");
        
        // Verify both client and server random values
        let expected_client_random = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let expected_server_random = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
            0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        ];
        
        assert_eq!(handshake_data.client_random, expected_client_random);
        if handshake_data.server_random != expected_server_random {
            panic!("Server random mismatch: got {:?}, expected {:?}", 
                   handshake_data.server_random, expected_server_random);
        }
        assert_eq!(handshake_data.server_random, expected_server_random);
        
        // Verify key exchange parameters
        assert!(!handshake_data.key_exchange_params.is_empty());
        assert_eq!(handshake_data.key_exchange_params.len(), 32);
    }

    #[test]
    fn test_parse_handshake_with_invalid_data() {
        // Test parsing with invalid handshake data
        let invalid_data = b"invalid handshake data";
        let result = parse_handshake_transcript(invalid_data);
        
        // This should fail
        assert!(result.is_err(), "Invalid handshake data should fail");
        
        let error = result.unwrap_err();
        assert!(matches!(error, ZkTlsError::ProtocolError(_)));
    }

    #[test]
    fn test_parse_handshake_with_empty_data() {
        // Test parsing with empty data
        let empty_data = b"";
        let result = parse_handshake_transcript(empty_data);
        
        // This should fail
        assert!(result.is_err(), "Empty handshake data should fail");
        
        let error = result.unwrap_err();
        assert!(matches!(error, ZkTlsError::ProtocolError(_)));
    }

    #[test]
    fn test_parse_handshake_with_unsupported_tls_version() {
        // Test parsing with unsupported TLS version
        let unsupported_version = &[
            0x01, 0x00, 0x00, 0x04, // Type: ClientHello, Length: 4
            0x03, 0x01, // TLS 1.0 (unsupported)
            0x00, 0x00, // Random (truncated)
        ];
        let result = parse_handshake_transcript(unsupported_version);
        
        // This should fail
        assert!(result.is_err(), "Unsupported TLS version should fail");
        
        let error = result.unwrap_err();
        assert!(matches!(error, ZkTlsError::ProtocolError(_)));
    }

    #[test]
    fn test_parse_handshake_with_unsupported_cipher_suite() {
        // Test parsing with unsupported cipher suite
        let unsupported_cipher = &[
            0x01, 0x00, 0x00, 0x0a, // Type: ClientHello, Length: 10
            0x03, 0x03, // TLS 1.3
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // Random (8 bytes)
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // Random (8 bytes)
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // Random (8 bytes)
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // Random (8 bytes)
            0x00, // Session ID length
            0x00, 0x02, // Cipher suites length
            0x00, 0x39, // TLS_RSA_WITH_AES_256_CBC_SHA (unsupported)
            0x01, // Compression methods length
            0x00, // NULL compression
            0x00, 0x00, // Extensions length
        ];
        let result = parse_handshake_transcript(unsupported_cipher);
        
        // This should fail
        assert!(result.is_err(), "Unsupported cipher suite should fail");
        
        let error = result.unwrap_err();
        assert!(matches!(error, ZkTlsError::ProtocolError(_)));
    }

    #[test]
    fn test_parse_handshake_extract_extensions() {
        // Test that extensions are properly extracted and parsed
        let transcript = COMPLETE_HANDSHAKE_TRANSCRIPT;
        let result = parse_handshake_transcript(transcript);
        
        assert!(result.is_ok(), "Handshake parsing should succeed");
        
        let handshake_data = result.unwrap();
        
        // Verify that key exchange parameters were extracted from extensions
        assert!(!handshake_data.key_exchange_params.is_empty());
        assert_eq!(handshake_data.key_exchange_params.len(), 32);
        
        // Verify the key exchange parameters match expected values
        let expected_key_exchange = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        ];
        assert_eq!(handshake_data.key_exchange_params, expected_key_exchange);
    }

    #[test]
    fn test_parse_handshake_verify_tls_version_negotiation() {
        // Test that TLS version negotiation is properly handled
        let transcript = COMPLETE_HANDSHAKE_TRANSCRIPT;
        let result = parse_handshake_transcript(transcript);
        
        assert!(result.is_ok(), "Handshake parsing should succeed");
        
        let handshake_data = result.unwrap();
        
        // Verify that the negotiated TLS version is 1.3
        assert_eq!(handshake_data.tls_version, "1.3");
        
        // Verify that the cipher suite is appropriate for TLS 1.3
        assert_eq!(handshake_data.cipher_suite, "TLS_AES_128_GCM_SHA256");
    }
}
