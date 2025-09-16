//! Utility functions for zkTLS operations
//! 
//! This module provides helper functions for working with hex data, 
//! conversions, and other common operations in no_std environment.

use crate::*;

/// Utility functions for working with hex data in no_std environment
pub mod hex_utils {
    use super::*;
    
    /// Convert hex string to bytes, returns error if data is too large
    pub fn hex_to_bytes<const N: usize>(hex_str: &str) -> Result<FixedVec<u8, N>, ZkTlsError> {
        if hex_str.len() / 2 > N {
            return Err(ZkTlsError::DataTooLarge);
        }
        
        let bytes = hex::decode(hex_str).map_err(|_| ZkTlsError::InvalidFormat)?;
        let mut fixed_vec = FixedVec::new();
        
        for byte in bytes {
            fixed_vec.push(byte).map_err(|_| ZkTlsError::DataTooLarge)?;
        }
        
        Ok(fixed_vec)
    }
    
    /// Convert hex string to fixed-size array
    pub fn hex_to_array<const N: usize>(hex_str: &str) -> Result<[u8; N], ZkTlsError> {
        if hex_str.len() != N * 2 {
            return Err(ZkTlsError::InvalidFormat);
        }
        
        let bytes = hex::decode(hex_str).map_err(|_| ZkTlsError::InvalidFormat)?;
        if bytes.len() != N {
            return Err(ZkTlsError::InvalidFormat);
        }
        
        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
    
    /// Convert bytes to hex string (requires alloc feature)
    #[cfg(feature = "std")]
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }
}

/// Cryptographic utility functions
pub mod crypto_utils {
    use super::*;
    
    /// Constant-time comparison of byte slices
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
    
    /// Zero out a byte slice (constant time)
    pub fn secure_zero(data: &mut [u8]) {
        for byte in data.iter_mut() {
            *byte = 0;
        }
    }
    
    /// XOR two byte arrays of the same length
    pub fn xor_bytes(a: &[u8], b: &[u8], output: &mut [u8]) -> Result<(), ZkTlsError> {
        if a.len() != b.len() || a.len() != output.len() {
            return Err(ZkTlsError::InvalidFormat);
        }
        
        for ((x, y), out) in a.iter().zip(b.iter()).zip(output.iter_mut()) {
            *out = x ^ y;
        }
        Ok(())
    }
}

/// TLS protocol utility functions
pub mod tls_utils {
    use super::*;
    
    /// Extract TLS record header information
    pub fn parse_tls_record_header(data: &[u8]) -> Result<TlsRecordHeader, ZkTlsError> {
        if data.len() < 5 {
            return Err(ZkTlsError::InvalidFormat);
        }
        
        let content_type = data[0];
        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]);
        
        Ok(TlsRecordHeader {
            content_type,
            version,
            length,
        })
    }
    
    /// Calculate TLS sequence number for record encryption
    pub const fn calculate_sequence_number(record_count: u64) -> [u8; 8] {
        record_count.to_be_bytes()
    }
    
    /// Create TLS record additional authenticated data (AAD)
    pub fn create_aad(seq_num: u64, content_type: u8, version: u16, length: u16) -> [u8; 13] {
        let mut aad = [0u8; 13];
        aad[0..8].copy_from_slice(&seq_num.to_be_bytes());
        aad[8] = content_type;
        aad[9..11].copy_from_slice(&version.to_be_bytes());
        aad[11..13].copy_from_slice(&length.to_be_bytes());
        aad
    }
}

/// TLS record header structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsRecordHeader {
    /// Content type (handshake, application data, etc.)
    pub content_type: u8,
    /// TLS version
    pub version: u16,
    /// Record length
    pub length: u16,
}

/// Memory management utilities for zkVM
pub mod memory_utils {
    use super::*;
    
    /// Copy data safely between fixed-size arrays
    pub fn safe_copy<const N: usize>(src: &[u8], dst: &mut [u8; N]) -> Result<(), ZkTlsError> {
        if src.len() > N {
            return Err(ZkTlsError::DataTooLarge);
        }
        
        dst[..src.len()].copy_from_slice(src);
        Ok(())
    }
    
    /// Create a fixed-size vector from a slice
    pub fn slice_to_fixed_vec<T: Clone, const N: usize>(
        slice: &[T]
    ) -> Result<FixedVec<T, N>, ZkTlsError> {
        if slice.len() > N {
            return Err(ZkTlsError::DataTooLarge);
        }
        
        let mut vec = FixedVec::new();
        for item in slice {
            vec.push(item.clone()).map_err(|_| ZkTlsError::DataTooLarge)?;
        }
        Ok(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    
    #[test]
    fn test_hex_utils() {
        let result = hex_utils::hex_to_array::<4>("deadbeef").unwrap();
        assert_eq!(result, [0xde, 0xad, 0xbe, 0xef]);
        
        let vec_result = hex_utils::hex_to_bytes::<8>("deadbeef").unwrap();
        assert_eq!(vec_result.len(), 4);
        assert_eq!(vec_result[0], 0xde);
    }
    
    #[test]
    fn test_constant_time_eq() {
        assert!(crypto_utils::constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!crypto_utils::constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!crypto_utils::constant_time_eq(&[1, 2], &[1, 2, 3]));
    }
    
    #[test]
    fn test_xor_bytes() {
        let a = [0x01, 0x02, 0x03];
        let b = [0x04, 0x05, 0x06];
        let mut output = [0u8; 3];
        
        crypto_utils::xor_bytes(&a, &b, &mut output).unwrap();
        assert_eq!(output, [0x05, 0x07, 0x05]);
    }
    
    #[test]
    fn test_tls_record_parsing() {
        let data = [0x16, 0x03, 0x03, 0x00, 0x10]; // Handshake record
        let header = tls_utils::parse_tls_record_header(&data).unwrap();
        
        assert_eq!(header.content_type, 0x16);
        assert_eq!(header.version, 0x0303);
        assert_eq!(header.length, 0x0010);
    }
    
    #[test]
    fn test_memory_utils() {
        let src = [1, 2, 3, 4];
        let mut dst = [0u8; 8];
        
        memory_utils::safe_copy(&src, &mut dst).unwrap();
        assert_eq!(&dst[..4], &src);
        assert_eq!(&dst[4..], &[0, 0, 0, 0]);
    }
}