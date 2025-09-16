//! Tests for TLS 1.3 Application Data Encryption/Decryption
//!
//! This module tests encrypted application data handling following
//! RFC 8446 Section 5.4 - Record Payload Protection

use std::vec::Vec;

#[cfg(test)]
mod tests {
    use zktls_core::tls::application::ApplicationDataHandler;
    use zktls_core::errors::ZkTlsError;

    #[test]
    fn test_application_data_handler_creation() {
        // Test that we can create an application data handler
        // This test should initially fail since we haven't implemented ApplicationDataHandler yet
        let handler = ApplicationDataHandler::new();
        assert!(handler.is_ok());
    }

    #[test]
    fn test_encrypt_application_data() {
        // Test encrypting application data with traffic keys
        let handler = ApplicationDataHandler::new().unwrap();
        let plaintext = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // Mock traffic key (32 bytes for AES-256)
        let traffic_key = [0u8; 32];
        
        let encrypted = handler.encrypt(plaintext, &traffic_key, 0).unwrap();
        
        // Encrypted data should be different from plaintext
        assert_ne!(encrypted.as_slice(), plaintext);
        // Should contain additional data for authentication tag
        assert!(encrypted.len() > plaintext.len());
    }

    #[test]
    fn test_decrypt_application_data() {
        // Test decrypting application data with traffic keys
        let handler = ApplicationDataHandler::new().unwrap();
        let plaintext = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
        
        // Mock traffic key (32 bytes for AES-256)
        let traffic_key = [0u8; 32];
        
        // Encrypt then decrypt
        let encrypted = handler.encrypt(plaintext, &traffic_key, 0).unwrap();
        let decrypted = handler.decrypt(&encrypted, &traffic_key, 0).unwrap();
        
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_sequence_number_handling() {
        // Test that sequence numbers are handled correctly for replay protection
        let handler = ApplicationDataHandler::new().unwrap();
        let plaintext = b"Hello, World!";
        let traffic_key = [0u8; 32];
        
        // Same plaintext with different sequence numbers should produce different ciphertext
        let encrypted_0 = handler.encrypt(plaintext, &traffic_key, 0).unwrap();
        let encrypted_1 = handler.encrypt(plaintext, &traffic_key, 1).unwrap();
        
        assert_ne!(encrypted_0, encrypted_1);
        
        // Should decrypt correctly with matching sequence numbers
        let decrypted_0 = handler.decrypt(&encrypted_0, &traffic_key, 0).unwrap();
        let decrypted_1 = handler.decrypt(&encrypted_1, &traffic_key, 1).unwrap();
        
        assert_eq!(decrypted_0.as_slice(), plaintext);
        assert_eq!(decrypted_1.as_slice(), plaintext);
    }

    #[test]
    fn test_authentication_failure() {
        // Test that tampering with encrypted data causes authentication failure
        let handler = ApplicationDataHandler::new().unwrap();
        let plaintext = b"Sensitive data";
        let traffic_key = [0u8; 32];
        
        let mut encrypted = handler.encrypt(plaintext, &traffic_key, 0).unwrap();
        
        // Tamper with the encrypted data
        if let Some(last_byte) = encrypted.last_mut() {
            *last_byte = last_byte.wrapping_add(1);
        }
        
        // Decryption should fail due to authentication tag mismatch
        let result = handler.decrypt(&encrypted, &traffic_key, 0);
        assert!(result.is_err());
        if let Err(ZkTlsError::InvalidTlsMessage(msg)) = result {
            assert!(msg.contains("Authentication") || msg.contains("authentication"));
        }
    }

    #[test]
    fn test_empty_data_handling() {
        // Test handling of empty application data (e.g., keep-alive)
        let handler = ApplicationDataHandler::new().unwrap();
        let plaintext = b"";
        let traffic_key = [0u8; 32];
        
        let encrypted = handler.encrypt(plaintext, &traffic_key, 0).unwrap();
        let decrypted = handler.decrypt(&encrypted, &traffic_key, 0).unwrap();
        
        assert_eq!(decrypted.as_slice(), plaintext);
        assert!(decrypted.is_empty());
    }
}