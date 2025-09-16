//! TLS 1.3 Protocol Implementation
//!
//! This module implements TLS 1.3 message parsing and serialization following RFC 8446.
//! All components are designed for zero-knowledge environments and integrate with SP1 zkVM.
//!
//! Key features:
//! - TLS 1.3 record layer and handshake message parsing
//! - Support for essential extensions (key_share, supported_versions, signature_algorithms)
//! - Memory-safe parsing with comprehensive bounds checking
//! - Integration with zktls-crypto for cryptographic operations
//! - Production-grade error handling using Result<T, E> patterns

use crate::errors::ZkTlsError;
use alloc::{format, vec::Vec};
use serde::{Deserialize, Serialize};

// TLS protocol constants from RFC 8446
pub const TLS_VERSION_1_3: u16 = 0x0304;
pub const TLS_VERSION_1_2: u16 = 0x0303;  // For compatibility/legacy record version

// Maximum sizes for TLS 1.3 messages
pub const MAX_TLS_RECORD_SIZE: usize = 16384;
pub const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 16777215;  // 2^24 - 1
pub const MAX_EXTENSION_SIZE: usize = 65535;  // 2^16 - 1

// Sub-modules
pub mod messages;
pub mod handshake;
pub mod extensions;
pub mod application;
pub mod transcript;
pub mod state_machine;
pub mod enhanced_state_machine;
pub mod key_schedule;

// Re-export key types
pub use messages::*;
pub use handshake::*;
pub use extensions::*;
pub use application::*;
pub use transcript::*;
pub use state_machine::*;
pub use enhanced_state_machine::*;
pub use key_schedule::*;

/// TLS Content Types (RFC 8446, Section 5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl TryFrom<u8> for ContentType {
    type Error = ZkTlsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            20 => Ok(ContentType::ChangeCipherSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            _ => Err(ZkTlsError::InvalidTlsMessage(
                format!("Invalid content type: {}", value)
            )),
        }
    }
}

/// TLS Protocol Version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    pub const TLS_1_3: ProtocolVersion = ProtocolVersion(TLS_VERSION_1_3);
    pub const TLS_1_2: ProtocolVersion = ProtocolVersion(TLS_VERSION_1_2);
    
    pub fn is_tls13(&self) -> bool {
        self.0 == TLS_VERSION_1_3
    }
    
    pub fn is_tls12(&self) -> bool {
        self.0 == TLS_VERSION_1_2
    }
}

impl From<u16> for ProtocolVersion {
    fn from(version: u16) -> Self {
        ProtocolVersion(version)
    }
}

impl From<ProtocolVersion> for u16 {
    fn from(version: ProtocolVersion) -> u16 {
        version.0
    }
}

/// Type alias for consistent byte handling across the TLS module
pub type TlsBytes = Vec<u8>;

/// Common TLS parsing utilities
pub mod utils {
    use super::*;
    use crate::errors::ZkTlsError;
    
    /// Read a u8 from the buffer and advance the cursor
    pub fn read_u8(data: &[u8], cursor: &mut usize) -> Result<u8, ZkTlsError> {
        if *cursor >= data.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                "Unexpected end of data when reading u8".into()
            ));
        }
        let value = data[*cursor];
        *cursor += 1;
        Ok(value)
    }
    
    /// Read a u16 (big-endian) from the buffer and advance the cursor
    pub fn read_u16(data: &[u8], cursor: &mut usize) -> Result<u16, ZkTlsError> {
        if *cursor + 2 > data.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                "Unexpected end of data when reading u16".into()
            ));
        }
        let value = u16::from_be_bytes([data[*cursor], data[*cursor + 1]]);
        *cursor += 2;
        Ok(value)
    }
    
    /// Read a u24 (24-bit big-endian) from the buffer and advance the cursor
    pub fn read_u24(data: &[u8], cursor: &mut usize) -> Result<u32, ZkTlsError> {
        if *cursor + 3 > data.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                "Unexpected end of data when reading u24".into()
            ));
        }
        let value = u32::from_be_bytes([0, data[*cursor], data[*cursor + 1], data[*cursor + 2]]);
        *cursor += 3;
        Ok(value)
    }
    
    /// Read a byte slice of specified length from the buffer and advance the cursor
    pub fn read_bytes<'a>(data: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], ZkTlsError> {
        if *cursor + length > data.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Unexpected end of data when reading {} bytes", length)
            ));
        }
        let slice = &data[*cursor..*cursor + length];
        *cursor += length;
        Ok(slice)
    }
    
    /// Write a u8 to the buffer
    pub fn write_u8(buffer: &mut Vec<u8>, value: u8) {
        buffer.push(value);
    }
    
    /// Write a u16 (big-endian) to the buffer
    pub fn write_u16(buffer: &mut Vec<u8>, value: u16) {
        buffer.extend_from_slice(&value.to_be_bytes());
    }
    
    /// Write a u24 (24-bit big-endian) to the buffer
    pub fn write_u24(buffer: &mut Vec<u8>, value: u32) {
        let bytes = value.to_be_bytes();
        // Skip the first byte (most significant) for u24
        buffer.extend_from_slice(&bytes[1..]);
    }
    
    /// Write a byte slice to the buffer
    pub fn write_bytes(buffer: &mut Vec<u8>, data: &[u8]) {
        buffer.extend_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::utils::*;
    use alloc::vec;
    
    #[test]
    fn test_content_type_conversion() {
        assert_eq!(ContentType::try_from(22).unwrap(), ContentType::Handshake);
        assert_eq!(ContentType::try_from(23).unwrap(), ContentType::ApplicationData);
        assert!(ContentType::try_from(255).is_err());
    }
    
    #[test]
    fn test_protocol_version() {
        let version = ProtocolVersion::TLS_1_3;
        assert!(version.is_tls13());
        assert!(!version.is_tls12());
        
        let version_u16: u16 = version.into();
        assert_eq!(version_u16, 0x0304);
    }
    
    #[test]
    fn test_read_write_u8() {
        let data = vec![0x42];
        let mut cursor = 0;
        assert_eq!(read_u8(&data, &mut cursor).unwrap(), 0x42);
        assert_eq!(cursor, 1);
        
        let mut buffer = Vec::new();
        write_u8(&mut buffer, 0x42);
        assert_eq!(buffer, vec![0x42]);
    }
    
    #[test]
    fn test_read_write_u16() {
        let data = vec![0x12, 0x34];
        let mut cursor = 0;
        assert_eq!(read_u16(&data, &mut cursor).unwrap(), 0x1234);
        assert_eq!(cursor, 2);
        
        let mut buffer = Vec::new();
        write_u16(&mut buffer, 0x1234);
        assert_eq!(buffer, vec![0x12, 0x34]);
    }
    
    #[test]
    fn test_read_write_u24() {
        let data = vec![0x12, 0x34, 0x56];
        let mut cursor = 0;
        assert_eq!(read_u24(&data, &mut cursor).unwrap(), 0x123456);
        assert_eq!(cursor, 3);
        
        let mut buffer = Vec::new();
        write_u24(&mut buffer, 0x123456);
        assert_eq!(buffer, vec![0x12, 0x34, 0x56]);
    }
    
    #[test]
    fn test_read_bytes() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let mut cursor = 1;
        let slice = read_bytes(&data, &mut cursor, 2).unwrap();
        assert_eq!(slice, &[0x02, 0x03]);
        assert_eq!(cursor, 3);
    }
    
    #[test]
    fn test_read_bounds_checking() {
        let data = vec![0x01];
        let mut cursor = 0;
        
        // This should work
        assert!(read_u8(&data, &mut cursor).is_ok());
        
        // This should fail - cursor now at end
        assert!(read_u8(&data, &mut cursor).is_err());
        
        // Reset cursor
        cursor = 0;
        
        // This should fail - not enough data for u16
        assert!(read_u16(&data, &mut cursor).is_err());
    }
}