//! TLS 1.3 Record Layer Messages (RFC 8446, Section 5)
//!
//! This module implements the TLS record layer structures and parsing functionality.
//! The record layer sits below the handshake layer and provides message framing.

use super::{ContentType, ProtocolVersion, TlsBytes, utils::*, MAX_TLS_RECORD_SIZE};
use crate::errors::ZkTlsError;
use alloc::{format, vec::Vec};
use serde::{Deserialize, Serialize};

/// TLS Record Layer structure (RFC 8446, Section 5.1)
/// 
/// ```
/// struct {
///     ContentType type;
///     ProtocolVersion legacy_record_version;
///     uint16 length;
///     opaque fragment[TLSPlaintext.length];
/// } TLSPlaintext;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsRecord {
    /// The content type of the record
    pub content_type: ContentType,
    /// The legacy record version (should be 0x0303 for TLS 1.3)
    pub legacy_record_version: ProtocolVersion,
    /// The length of the fragment data
    pub length: u16,
    /// The actual message data
    pub fragment: TlsBytes,
}

impl TlsRecord {
    /// Create a new TLS record
    pub fn new(
        content_type: ContentType, 
        legacy_record_version: ProtocolVersion, 
        fragment: TlsBytes
    ) -> Result<Self, ZkTlsError> {
        if fragment.len() > MAX_TLS_RECORD_SIZE {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Fragment size {} exceeds maximum {}", fragment.len(), MAX_TLS_RECORD_SIZE)
            ));
        }
        
        let length = fragment.len() as u16;
        
        Ok(TlsRecord {
            content_type,
            legacy_record_version,
            length,
            fragment,
        })
    }
    
    /// Create a handshake record for TLS 1.3
    pub fn handshake(fragment: TlsBytes) -> Result<Self, ZkTlsError> {
        Self::new(
            ContentType::Handshake, 
            ProtocolVersion::TLS_1_2,  // Legacy version for TLS 1.3
            fragment
        )
    }
    
    /// Create an application data record for TLS 1.3
    pub fn application_data(fragment: TlsBytes) -> Result<Self, ZkTlsError> {
        Self::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLS_1_2,  // Legacy version for TLS 1.3
            fragment
        )
    }
    
    /// Parse a TLS record from wire format
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ZkTlsError> {
        if data.len() < 5 {  // Minimum record header size
            return Err(ZkTlsError::InvalidTlsMessage(
                "TLS record too short".into()
            ));
        }
        
        let mut cursor = 0;
        
        // Parse content type (1 byte)
        let content_type_byte = read_u8(data, &mut cursor)?;
        let content_type = ContentType::try_from(content_type_byte)?;
        
        // Parse legacy record version (2 bytes)
        let version = read_u16(data, &mut cursor)?;
        let legacy_record_version = ProtocolVersion::from(version);
        
        // Parse length (2 bytes)
        let length = read_u16(data, &mut cursor)?;
        
        // Validate length
        if length as usize > MAX_TLS_RECORD_SIZE {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Record length {} exceeds maximum {}", length, MAX_TLS_RECORD_SIZE)
            ));
        }
        
        if cursor + length as usize > data.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Record claims {} bytes but only {} available", length, data.len() - cursor)
            ));
        }
        
        // Parse fragment
        let fragment_data = read_bytes(data, &mut cursor, length as usize)?;
        let fragment = fragment_data.to_vec();
        
        let record = TlsRecord {
            content_type,
            legacy_record_version,
            length,
            fragment,
        };
        
        Ok((record, cursor))
    }
    
    /// Serialize the TLS record to wire format
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::with_capacity(5 + self.fragment.len());
        
        // Write content type (1 byte)
        write_u8(&mut buffer, self.content_type as u8);
        
        // Write legacy record version (2 bytes)
        write_u16(&mut buffer, self.legacy_record_version.into());
        
        // Write length (2 bytes)
        write_u16(&mut buffer, self.length);
        
        // Write fragment
        write_bytes(&mut buffer, &self.fragment);
        
        buffer
    }
    
    /// Get the total size of the record when serialized
    pub fn size(&self) -> usize {
        5 + self.fragment.len()  // 5 bytes header + fragment
    }
    
    /// Validate the record structure
    pub fn validate(&self) -> Result<(), ZkTlsError> {
        // Check length consistency
        if self.length as usize != self.fragment.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Length field {} doesn't match fragment size {}", 
                    self.length, self.fragment.len())
            ));
        }
        
        // Check maximum size
        if self.fragment.len() > MAX_TLS_RECORD_SIZE {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Fragment size {} exceeds maximum {}", 
                    self.fragment.len(), MAX_TLS_RECORD_SIZE)
            ));
        }
        
        // For TLS 1.3, legacy_record_version should typically be 0x0303
        if !self.legacy_record_version.is_tls12() && !self.legacy_record_version.is_tls13() {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Invalid legacy record version: 0x{:04x}", 
                    self.legacy_record_version.0)
            ));
        }
        
        Ok(())
    }
    
    /// Check if this is a handshake record
    pub fn is_handshake(&self) -> bool {
        self.content_type == ContentType::Handshake
    }
    
    /// Check if this is an application data record
    pub fn is_application_data(&self) -> bool {
        self.content_type == ContentType::ApplicationData
    }
    
    /// Check if this is an alert record
    pub fn is_alert(&self) -> bool {
        self.content_type == ContentType::Alert
    }
}

/// Multiple TLS records can be concatenated in a single buffer
pub struct TlsRecordBatch {
    records: Vec<TlsRecord>,
}

impl TlsRecordBatch {
    /// Create a new empty batch
    pub fn new() -> Self {
        TlsRecordBatch {
            records: Vec::new(),
        }
    }
    
    /// Parse multiple TLS records from wire format
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        let mut records = Vec::new();
        let mut cursor = 0;
        
        while cursor < data.len() {
            let (record, consumed) = TlsRecord::parse(&data[cursor..])?;
            records.push(record);
            cursor += consumed;
        }
        
        Ok(TlsRecordBatch { records })
    }
    
    /// Add a record to the batch
    pub fn add_record(&mut self, record: TlsRecord) {
        self.records.push(record);
    }
    
    /// Get all records in the batch
    pub fn records(&self) -> &[TlsRecord] {
        &self.records
    }
    
    /// Serialize all records to wire format
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::new();
        for record in &self.records {
            buffer.extend_from_slice(&record.serialize());
        }
        buffer
    }
    
    /// Get total size of all records when serialized
    pub fn size(&self) -> usize {
        self.records.iter().map(|r| r.size()).sum()
    }
    
    /// Filter records by content type
    pub fn filter_by_type(&self, content_type: ContentType) -> Vec<&TlsRecord> {
        self.records.iter()
            .filter(|r| r.content_type == content_type)
            .collect()
    }
    
    /// Get all handshake records
    pub fn handshake_records(&self) -> Vec<&TlsRecord> {
        self.filter_by_type(ContentType::Handshake)
    }
}

impl Default for TlsRecordBatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use alloc::vec;
    
    #[test]
    fn test_tls_record_creation() {
        let fragment = vec![0x01, 0x02, 0x03, 0x04];
        let record = TlsRecord::new(
            ContentType::Handshake,
            ProtocolVersion::TLS_1_2,
            fragment.clone()
        ).unwrap();
        
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.legacy_record_version, ProtocolVersion::TLS_1_2);
        assert_eq!(record.length, 4);
        assert_eq!(record.fragment, fragment);
    }
    
    #[test]
    fn test_tls_record_handshake_helper() {
        let fragment = vec![0x01, 0x00, 0x00, 0x2c]; // ClientHello start
        let record = TlsRecord::handshake(fragment.clone()).unwrap();
        
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.legacy_record_version, ProtocolVersion::TLS_1_2);
        assert!(record.is_handshake());
        assert!(!record.is_application_data());
    }
    
    #[test]
    fn test_tls_record_serialization_round_trip() {
        let fragment = vec![0x16, 0x03, 0x01, 0x00, 0x2c];
        let original = TlsRecord::handshake(fragment).unwrap();
        
        let serialized = original.serialize();
        let (parsed, consumed) = TlsRecord::parse(&serialized).unwrap();
        
        assert_eq!(consumed, serialized.len());
        assert_eq!(parsed, original);
    }
    
    #[test] 
    fn test_tls_record_parsing_known_data() {
        // A simple handshake record with 4 bytes of data
        let data = hex!("16 0303 0004 01020304");
        //              ^^ ^^^^ ^^^^ ^^^^^^^^
        //              |  |    |    +-- 4 bytes of fragment data
        //              |  |    +------- length = 4
        //              |  +------------ legacy version = TLS 1.2 (0x0303)
        //              +--------------- content type = handshake (22)
        
        let (record, consumed) = TlsRecord::parse(&data).unwrap();
        
        assert_eq!(consumed, 9); // 5 byte header + 4 byte fragment
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.legacy_record_version.0, 0x0303);
        assert_eq!(record.length, 4);
        assert_eq!(record.fragment, vec![0x01, 0x02, 0x03, 0x04]);
        
        // Validate round trip
        let serialized = record.serialize();
        assert_eq!(serialized, data.to_vec());
    }
    
    #[test]
    fn test_tls_record_parsing_errors() {
        // Too short
        let data = hex!("16 03");
        assert!(TlsRecord::parse(&data).is_err());
        
        // Length exceeds available data
        let data = hex!("16 0303 0010 0102");  // Claims 16 bytes but only has 2
        assert!(TlsRecord::parse(&data).is_err());
        
        // Invalid content type
        let data = hex!("FF 0303 0004 01020304");
        assert!(TlsRecord::parse(&data).is_err());
    }
    
    #[test]
    fn test_tls_record_validation() {
        let fragment = vec![0x01, 0x02, 0x03];
        let mut record = TlsRecord::new(
            ContentType::Handshake,
            ProtocolVersion::TLS_1_2,
            fragment
        ).unwrap();
        
        // Valid record should pass
        assert!(record.validate().is_ok());
        
        // Corrupt length field
        record.length = 100;
        assert!(record.validate().is_err());
        
        // Fix length but set invalid version
        record.length = 3;
        record.legacy_record_version = ProtocolVersion(0x1234);
        assert!(record.validate().is_err());
    }
    
    #[test]
    fn test_tls_record_batch() {
        let data1 = vec![0x01, 0x02];
        let data2 = vec![0x03, 0x04, 0x05];
        
        let record1 = TlsRecord::handshake(data1).unwrap();
        let record2 = TlsRecord::application_data(data2).unwrap();
        
        let mut batch = TlsRecordBatch::new();
        batch.add_record(record1);
        batch.add_record(record2);
        
        assert_eq!(batch.records().len(), 2);
        assert_eq!(batch.handshake_records().len(), 1);
        
        // Test serialization round trip
        let serialized = batch.serialize();
        let parsed_batch = TlsRecordBatch::parse(&serialized).unwrap();
        assert_eq!(parsed_batch.records().len(), 2);
    }
    
    #[test]
    fn test_tls_record_max_size() {
        // Test record size limit
        let fragment = vec![0u8; MAX_TLS_RECORD_SIZE + 1];
        assert!(TlsRecord::handshake(fragment).is_err());
        
        // Max size should be OK
        let fragment = vec![0u8; MAX_TLS_RECORD_SIZE];
        assert!(TlsRecord::handshake(fragment).is_ok());
    }
    
    #[test]
    fn test_empty_fragment() {
        // Empty fragment should be valid
        let record = TlsRecord::handshake(vec![]).unwrap();
        assert_eq!(record.length, 0);
        assert!(record.fragment.is_empty());
        
        // Should serialize and parse correctly
        let serialized = record.serialize();
        let (parsed, _) = TlsRecord::parse(&serialized).unwrap();
        assert_eq!(parsed, record);
    }
}