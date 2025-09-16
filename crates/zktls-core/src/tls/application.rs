//! TLS 1.3 Application Data Handling
//!
//! This module implements application data encryption/decryption for TLS 1.3
//! following RFC 8446 Section 5.4 - Record Payload Protection
//!
//! Key features:
//! - AES-GCM encryption/decryption for application data
//! - Sequence number handling for replay protection
//! - Integration with TLS record layer
//! - Memory-safe operations with proper error handling

use super::{TlsRecord, ContentType, ProtocolVersion};
use crate::errors::{ZkTlsError, CryptoError};
use alloc::vec::Vec;
use zktls_crypto::native::NativeCryptoProvider;
use zktls_crypto::traits::Aead;

// Re-export HttpMessage from the http module for backward compatibility
pub use crate::http::HttpMessage;

/// Application Data Handler for TLS 1.3
///
/// Handles encryption/decryption of application data using AES-GCM
/// with proper sequence number management for replay protection.
#[derive(Debug, Clone)]
pub struct ApplicationDataHandler {
    // For now, we'll keep this simple - in a full implementation
    // this would contain cipher suite information, key material, etc.
}

impl ApplicationDataHandler {
    /// Create a new ApplicationDataHandler
    pub fn new() -> Result<Self, ZkTlsError> {
        Ok(ApplicationDataHandler {})
    }

    /// Encrypt application data using AES-GCM
    ///
    /// # Arguments
    /// * `plaintext` - The application data to encrypt
    /// * `traffic_key` - The application traffic key (32 bytes for AES-256)
    /// * `sequence_number` - The TLS record sequence number for nonce construction
    ///
    /// # Returns
    /// Encrypted application data as a TLS record fragment
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        traffic_key: &[u8; 32],
        sequence_number: u64,
    ) -> Result<Vec<u8>, ZkTlsError> {
        if traffic_key.is_empty() {
            return Err(ZkTlsError::InvalidTlsMessage(
                "Traffic key cannot be empty".into()
            ));
        }

        // Construct the nonce from sequence number (RFC 8446 Section 5.3)
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&sequence_number.to_be_bytes());
        
        // Use real AES-GCM encryption
        let crypto_provider = NativeCryptoProvider::new();
        
        // Encrypt using AES-GCM with the traffic key and nonce
        let encrypted_data = crypto_provider.encrypt(
            traffic_key,
            &nonce,
            &[], // No additional authenticated data for TLS application data
            plaintext
        ).map_err(|_e| ZkTlsError::CryptoError(CryptoError::AesGcmFailed))?;
        
        // Format: [nonce (12 bytes)] [encrypted_data] [auth_tag (16 bytes)]
        let mut result = Vec::with_capacity(12 + encrypted_data.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&encrypted_data);
        
        Ok(result)
    }

    /// Decrypt application data using AES-GCM
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted application data
    /// * `traffic_key` - The application traffic key (32 bytes for AES-256)
    /// * `sequence_number` - The TLS record sequence number for nonce construction
    ///
    /// # Returns
    /// Decrypted plaintext application data
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        traffic_key: &[u8; 32],
        sequence_number: u64,
    ) -> Result<Vec<u8>, ZkTlsError> {
        if ciphertext.len() < 28 {  // minimum: 12 (nonce) + 0 (data) + 16 (tag)
            return Err(ZkTlsError::InvalidTlsMessage(
                "Ciphertext too short for AES-GCM".into()
            ));
        }

        // Extract components
        let nonce = &ciphertext[..12];
        let encrypted_data = &ciphertext[12..];

        // Verify nonce matches expected sequence number
        let mut expected_nonce = [0u8; 12];
        expected_nonce[4..].copy_from_slice(&sequence_number.to_be_bytes());
        if nonce != expected_nonce {
            return Err(ZkTlsError::InvalidTlsMessage(
                "Nonce mismatch in encrypted data".into()
            ));
        }

        // Use real AES-GCM decryption
        let crypto_provider = NativeCryptoProvider::new();
        
        // Decrypt using AES-GCM with the traffic key and nonce
        let plaintext = crypto_provider.decrypt(
            traffic_key,
            nonce,
            &[], // No additional authenticated data for TLS application data
            encrypted_data
        ).map_err(|_e| ZkTlsError::CryptoError(CryptoError::AesGcmFailed))?;

        Ok(plaintext)
    }

    /// Create an encrypted TLS application data record
    pub fn create_encrypted_record(
        &self,
        plaintext: &[u8],
        traffic_key: &[u8; 32],
        sequence_number: u64,
    ) -> Result<TlsRecord, ZkTlsError> {
        let encrypted_fragment = self.encrypt(plaintext, traffic_key, sequence_number)?;
        
        TlsRecord::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLS_1_2, // Legacy record version for TLS 1.3
            encrypted_fragment.into(),
        )
    }

    /// Decrypt a TLS application data record
    pub fn decrypt_record(
        &self,
        record: &TlsRecord,
        traffic_key: &[u8; 32],
        sequence_number: u64,
    ) -> Result<Vec<u8>, ZkTlsError> {
        if !record.is_application_data() {
            return Err(ZkTlsError::InvalidTlsMessage(
                "Record is not application data".into()
            ));
        }

        self.decrypt(&record.fragment, traffic_key, sequence_number)
    }

}

impl Default for ApplicationDataHandler {
    fn default() -> Self {
        Self::new().expect("Failed to create default ApplicationDataHandler")
    }
}

/// Application data buffer for accumulating decrypted data
#[derive(Debug, Clone, Default)]
pub struct ApplicationDataBuffer {
    buffer: Vec<u8>,
    position: usize,
}

impl ApplicationDataBuffer {
    /// Create a new application data buffer
    pub fn new() -> Self {
        ApplicationDataBuffer {
            buffer: Vec::new(),
            position: 0,
        }
    }

    /// Add decrypted application data to the buffer
    pub fn add_data(&mut self, data: Vec<u8>) {
        self.buffer.extend(data);
    }

    /// Read data from the buffer
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let available = self.buffer.len() - self.position;
        let to_read = buf.len().min(available);
        
        if to_read > 0 {
            buf[..to_read].copy_from_slice(&self.buffer[self.position..self.position + to_read]);
            self.position += to_read;
            
            // Compact buffer if we've read everything
            if self.position == self.buffer.len() {
                self.buffer.clear();
                self.position = 0;
            }
        }
        
        to_read
    }

    /// Check if buffer has available data
    pub fn has_data(&self) -> bool {
        self.position < self.buffer.len()
    }

    /// Get the amount of available data
    pub fn available(&self) -> usize {
        self.buffer.len() - self.position
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.position = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_application_data_handler_creation() {
        let handler = ApplicationDataHandler::new();
        assert!(handler.is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0x42u8; 32];
        let sequence_number = 1;
        let plaintext = b"Hello, World!";

        let encrypted = handler.encrypt(plaintext, &traffic_key, sequence_number).unwrap();
        let decrypted = handler.decrypt(&encrypted, &traffic_key, sequence_number).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_sequence_number_affects_encryption() {
        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0x42u8; 32];
        let plaintext = b"Test data";

        let encrypted1 = handler.encrypt(plaintext, &traffic_key, 1).unwrap();
        let encrypted2 = handler.encrypt(plaintext, &traffic_key, 2).unwrap();

        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0x42u8; 32];
        let sequence_number = 1;
        let plaintext = b"Test data";

        let mut encrypted = handler.encrypt(plaintext, &traffic_key, sequence_number).unwrap();
        
        // Tamper with the ciphertext
        if let Some(last_byte) = encrypted.last_mut() {
            *last_byte = last_byte.wrapping_add(1);
        }

        let result = handler.decrypt(&encrypted, &traffic_key, sequence_number);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_sequence_number_fails() {
        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0x42u8; 32];
        let plaintext = b"Test data";

        let encrypted = handler.encrypt(plaintext, &traffic_key, 1).unwrap();
        let result = handler.decrypt(&encrypted, &traffic_key, 2);  // Wrong sequence number

        assert!(result.is_err());
    }

    #[test]
    fn test_create_and_decrypt_record() {
        let handler = ApplicationDataHandler::new().unwrap();
        let traffic_key = [0x99u8; 32];
        let sequence_number = 5;
        let plaintext = b"Application data payload";

        let record = handler.create_encrypted_record(plaintext, &traffic_key, sequence_number).unwrap();
        assert!(record.is_application_data());
        assert!(record.fragment.len() > plaintext.len()); // Should be larger due to encryption overhead

        let decrypted = handler.decrypt_record(&record, &traffic_key, sequence_number).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_application_data_buffer() {
        let mut buffer = ApplicationDataBuffer::new();
        assert!(!buffer.has_data());
        assert_eq!(buffer.available(), 0);

        // Add some data
        buffer.add_data(b"Hello, ".to_vec());
        buffer.add_data(b"World!".to_vec());
        
        assert!(buffer.has_data());
        assert_eq!(buffer.available(), 13);

        // Read partial data
        let mut read_buf = [0u8; 5];
        let read_count = buffer.read(&mut read_buf);
        assert_eq!(read_count, 5);
        assert_eq!(&read_buf[..read_count], b"Hello");
        assert_eq!(buffer.available(), 8);

        // Read remaining data
        let mut read_buf = [0u8; 20]; // Larger than available
        let read_count = buffer.read(&mut read_buf);
        assert_eq!(read_count, 8);
        assert_eq!(&read_buf[..read_count], b", World!");
        assert!(!buffer.has_data());
    }

    #[test]
    fn test_buffer_clear() {
        let mut buffer = ApplicationDataBuffer::new();
        buffer.add_data(b"test data".to_vec());
        
        assert!(buffer.has_data());
        buffer.clear();
        assert!(!buffer.has_data());
        assert_eq!(buffer.available(), 0);
    }
}