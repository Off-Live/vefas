//! # TLS Record Parsing and Processing
//!
//! This module provides production-grade TLS 1.3 record parsing capabilities
//! for extracting and processing TLS records, handshake messages, and application data
//! according to RFC 8446.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::{Result, VefasCoreError};
use tls_parser;

/// TLS Content Types (RFC 8446 Section 5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    /// Invalid content type
    Invalid = 0,
    /// Change cipher spec (legacy)
    ChangeCipherSpec = 20,
    /// Alert messages
    Alert = 21,
    /// Handshake messages
    Handshake = 22,
    /// Application data
    ApplicationData = 23,
}

impl From<u8> for ContentType {
    fn from(value: u8) -> Self {
        match value {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Invalid,
        }
    }
}

/// TLS Record as defined in RFC 8446 Section 5.1
#[derive(Debug, Clone, PartialEq)]
pub struct TlsRecord {
    /// Content type of the record
    pub content_type: ContentType,
    /// Legacy record version (should be TLS 1.0 for TLS 1.3)
    pub legacy_version: [u8; 2],
    /// Length of the payload
    pub length: u16,
    /// Record payload
    pub payload: Vec<u8>,
}

impl TlsRecord {
    /// Reconstruct full on-wire bytes for this TLS record (5-byte header + payload)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.payload.len());
        out.push(self.content_type as u8);
        out.extend_from_slice(&self.legacy_version);
        out.extend_from_slice(&self.length.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

/// Handshake Message Types (RFC 8446 Section 4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// Invalid handshake type
    Invalid = 0,
    /// Client Hello
    ClientHello = 1,
    /// Server Hello
    ServerHello = 2,
    /// New Session Ticket
    NewSessionTicket = 4,
    /// End of Early Data
    EndOfEarlyData = 5,
    /// Encrypted Extensions
    EncryptedExtensions = 8,
    /// Certificate
    Certificate = 11,
    /// Certificate Request
    CertificateRequest = 13,
    /// Certificate Verify
    CertificateVerify = 15,
    /// Finished
    Finished = 20,
    /// Key Update
    KeyUpdate = 24,
    /// Message Hash
    MessageHash = 254,
}

impl From<u8> for HandshakeType {
    fn from(value: u8) -> Self {
        match value {
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            4 => HandshakeType::NewSessionTicket,
            5 => HandshakeType::EndOfEarlyData,
            8 => HandshakeType::EncryptedExtensions,
            11 => HandshakeType::Certificate,
            13 => HandshakeType::CertificateRequest,
            15 => HandshakeType::CertificateVerify,
            20 => HandshakeType::Finished,
            24 => HandshakeType::KeyUpdate,
            254 => HandshakeType::MessageHash,
            _ => HandshakeType::Invalid,
        }
    }
}

/// Handshake message as defined in RFC 8446 Section 4
#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeMessage {
    /// Handshake message type
    pub msg_type: HandshakeType,
    /// Length of the message (24-bit value)
    pub length: u32,
    /// Message payload
    pub payload: Vec<u8>,
    /// Raw handshake message bytes (header + payload) as they appeared on the wire
    /// This preserves the exact bytes used for transcript hash computation
    pub raw_bytes: Vec<u8>,
}

/// TLS Extension Types commonly used in TLS 1.3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TlsExtensionType {
    /// Server Name Indication
    ServerName = 0,
    /// Supported Groups
    SupportedGroups = 10,
    /// Signature Algorithms
    SignatureAlgorithms = 13,
    /// Application Layer Protocol Negotiation
    ApplicationLayerProtocolNegotiation = 16,
    /// Key Share
    KeyShare = 51,
    /// Supported Versions
    SupportedVersions = 43,
    /// PSK Key Exchange Modes
    PskKeyExchangeModes = 45,
}

/// TLS Extension structure
#[derive(Debug, Clone, PartialEq)]
pub struct TlsExtension {
    /// Extension type
    pub extension_type: u16,
    /// Extension data length
    pub length: u16,
    /// Extension data
    pub data: Vec<u8>,
}

impl TlsExtension {
    /// Create a Supported Versions extension
    pub const SupportedVersions: TlsExtensionType = TlsExtensionType::SupportedVersions;

    /// Create a Key Share extension
    pub const KeyShare: TlsExtensionType = TlsExtensionType::KeyShare;

    /// Create a Server Name extension
    pub const ServerName: TlsExtensionType = TlsExtensionType::ServerName;

    /// Create a Signature Algorithms extension
    pub const SignatureAlgorithms: TlsExtensionType = TlsExtensionType::SignatureAlgorithms;
}

/// TLS Record Parser for parsing TLS 1.3 records and handshake messages
#[derive(Debug, Default)]
pub struct TlsRecordParser {
    /// Buffer for incomplete records
    buffer: Vec<u8>,
}

impl TlsRecordParser {
    /// Create a new TLS record parser
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Parse TLS records from raw bytes
    pub fn parse_records(&mut self, data: &[u8]) -> Result<Vec<TlsRecord>> {
        // Add new data to buffer
        self.buffer.extend_from_slice(data);

        let mut records = Vec::new();
        let mut offset = 0;

        while offset + 5 <= self.buffer.len() {
            // Parse TLS record header (5 bytes)
            let content_type = ContentType::from(self.buffer[offset]);
            let legacy_version = [self.buffer[offset + 1], self.buffer[offset + 2]];
            let length = u16::from_be_bytes([self.buffer[offset + 3], self.buffer[offset + 4]]);

            // Check if we have the complete record
            let record_end = offset + 5 + length as usize;
            if record_end > self.buffer.len() {
                // Incomplete record, break and wait for more data
                break;
            }

            // Extract payload
            let payload = self.buffer[offset + 5..record_end].to_vec();

            records.push(TlsRecord {
                content_type,
                legacy_version,
                length,
                payload,
            });

            offset = record_end;
        }

        // Remove processed data from buffer
        if offset > 0 {
            self.buffer.drain(0..offset);
        }

        Ok(records)
    }

    /// Extract handshake messages from TLS records
    pub fn extract_handshake_messages(
        &self,
        records: &[TlsRecord],
    ) -> Result<Vec<HandshakeMessage>> {
        // Concatenate all handshake record payloads to correctly reassemble fragmented messages
        let mut concatenated = Vec::new();
        for record in records {
            if record.content_type == ContentType::Handshake {
                concatenated.extend_from_slice(&record.payload);
            }
        }

        let mut messages = Vec::new();
        let mut offset: usize = 0;

        // Parse messages from the concatenated stream
        while offset + 4 <= concatenated.len() {
            let msg_type = HandshakeType::from(concatenated[offset]);
            let length = u32::from_be_bytes([
                0,
                concatenated[offset + 1],
                concatenated[offset + 2],
                concatenated[offset + 3],
            ]);

            let message_end = offset + 4 + length as usize;
            if message_end > concatenated.len() {
                return Err(VefasCoreError::TlsError(
                    "Incomplete handshake message across records".to_string(),
                ));
            }

            let payload = concatenated[offset + 4..message_end].to_vec();
            let raw_bytes = concatenated[offset..message_end].to_vec();
            messages.push(HandshakeMessage {
                msg_type,
                length,
                payload,
                raw_bytes,
            });
            offset = message_end;
        }

        Ok(messages)
    }

    /// Parse extensions from handshake message payload
    pub fn parse_extensions(&self, payload: &[u8], offset: usize) -> Result<Vec<TlsExtension>> {
        if offset + 2 > payload.len() {
            return Ok(Vec::new());
        }

        // Read extensions length
        let extensions_length = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let extensions_end = offset + 2 + extensions_length as usize;

        if extensions_end > payload.len() {
            return Err(VefasCoreError::TlsError(
                "Invalid extensions length".to_string(),
            ));
        }

        let mut extensions = Vec::new();
        let mut ext_offset = offset + 2;

        while ext_offset + 4 <= extensions_end {
            let extension_type = u16::from_be_bytes([payload[ext_offset], payload[ext_offset + 1]]);
            let extension_length =
                u16::from_be_bytes([payload[ext_offset + 2], payload[ext_offset + 3]]);

            let data_end = ext_offset + 4 + extension_length as usize;
            if data_end > extensions_end {
                return Err(VefasCoreError::TlsError(
                    "Invalid extension length".to_string(),
                ));
            }

            let data = payload[ext_offset + 4..data_end].to_vec();

            extensions.push(TlsExtension {
                extension_type,
                length: extension_length,
                data,
            });

            ext_offset = data_end;
        }

        Ok(extensions)
    }

    /// Extract application data from TLS records
    pub fn extract_application_data(&self, records: &[TlsRecord]) -> Vec<u8> {
        let mut app_data = Vec::new();

        for record in records {
            if record.content_type == ContentType::ApplicationData {
                app_data.extend_from_slice(&record.payload);
            }
        }

        app_data
    }

    /// Find the first ApplicationData record and return its full on-wire bytes (header + payload)
    pub fn first_application_record_bytes(&self, records: &[TlsRecord]) -> Option<Vec<u8>> {
        for record in records {
            if record.content_type == ContentType::ApplicationData {
                return Some(record.to_bytes());
            }
        }
        None
    }

    /// Concatenate ALL ApplicationData records into a single byte stream
    /// This captures the complete TLS application data, even if split across multiple records
    pub fn all_application_record_bytes(&self, records: &[TlsRecord]) -> Option<Vec<u8>> {
        let mut result = Vec::new();
        let mut found_any = false;

        for record in records {
            if record.content_type == ContentType::ApplicationData {
                result.extend_from_slice(&record.to_bytes());
                found_any = true;
            }
        }

        if found_any {
            Some(result)
        } else {
            None
        }
    }

    /// Clear the internal buffer
    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_record() {
        let mut parser = TlsRecordParser::new();

        // Create a simple handshake record
        let mut record_data = Vec::new();
        record_data.push(22); // Handshake content type
        record_data.extend_from_slice(&[3, 1]); // Legacy version (TLS 1.0)
        record_data.extend_from_slice(&[0, 10]); // Length (10 bytes)
        record_data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]); // Payload

        let records = parser.parse_records(&record_data).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, ContentType::Handshake);
        assert_eq!(records[0].legacy_version, [3, 1]);
        assert_eq!(records[0].length, 10);
        assert_eq!(records[0].payload.len(), 10);
    }

    #[test]
    fn test_parse_multiple_records() {
        let mut parser = TlsRecordParser::new();

        let mut data = Vec::new();

        // First record
        data.push(22); // Handshake
        data.extend_from_slice(&[3, 3]); // TLS 1.2
        data.extend_from_slice(&[0, 4]); // Length 4
        data.extend_from_slice(&[1, 2, 3, 4]); // Payload

        // Second record
        data.push(23); // Application Data
        data.extend_from_slice(&[3, 3]); // TLS 1.2
        data.extend_from_slice(&[0, 3]); // Length 3
        data.extend_from_slice(&[5, 6, 7]); // Payload

        let records = parser.parse_records(&data).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].content_type, ContentType::Handshake);
        assert_eq!(records[1].content_type, ContentType::ApplicationData);
    }

    #[test]
    fn test_parse_handshake_message() {
        let parser = TlsRecordParser::new();

        // Create a handshake record with a client hello message
        let mut payload = Vec::new();
        payload.push(1); // ClientHello type
        payload.extend_from_slice(&[0, 0, 6]); // Length (6 bytes)
        payload.extend_from_slice(&[1, 2, 3, 4, 5, 6]); // Message payload

        let record = TlsRecord {
            content_type: ContentType::Handshake,
            legacy_version: [3, 3],
            length: payload.len() as u16,
            payload,
        };

        let messages = parser.extract_handshake_messages(&[record]).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].msg_type, HandshakeType::ClientHello);
        assert_eq!(messages[0].length, 6);
        assert_eq!(messages[0].payload, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_incomplete_record() {
        let mut parser = TlsRecordParser::new();

        // Incomplete record (header says 10 bytes but only 5 provided)
        let mut data = Vec::new();
        data.push(22); // Handshake
        data.extend_from_slice(&[3, 3]); // TLS 1.2
        data.extend_from_slice(&[0, 10]); // Length 10
        data.extend_from_slice(&[1, 2, 3, 4, 5]); // Only 5 bytes

        let records = parser.parse_records(&data).unwrap();

        // Should return empty since record is incomplete
        assert_eq!(records.len(), 0);
        // Buffer should contain the incomplete data
        assert_eq!(parser.buffer.len(), 10);
    }

    #[test]
    fn test_extract_application_data() {
        let parser = TlsRecordParser::new();

        let records = vec![
            TlsRecord {
                content_type: ContentType::Handshake,
                legacy_version: [3, 3],
                length: 4,
                payload: vec![1, 2, 3, 4],
            },
            TlsRecord {
                content_type: ContentType::ApplicationData,
                legacy_version: [3, 3],
                length: 3,
                payload: vec![5, 6, 7],
            },
            TlsRecord {
                content_type: ContentType::ApplicationData,
                legacy_version: [3, 3],
                length: 2,
                payload: vec![8, 9],
            },
        ];

        let app_data = parser.extract_application_data(&records);
        assert_eq!(app_data, vec![5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_content_type_conversion() {
        assert_eq!(ContentType::from(20), ContentType::ChangeCipherSpec);
        assert_eq!(ContentType::from(21), ContentType::Alert);
        assert_eq!(ContentType::from(22), ContentType::Handshake);
        assert_eq!(ContentType::from(23), ContentType::ApplicationData);
        assert_eq!(ContentType::from(255), ContentType::Invalid);
    }

    #[test]
    fn test_handshake_type_conversion() {
        assert_eq!(HandshakeType::from(1), HandshakeType::ClientHello);
        assert_eq!(HandshakeType::from(2), HandshakeType::ServerHello);
        assert_eq!(HandshakeType::from(11), HandshakeType::Certificate);
        assert_eq!(HandshakeType::from(20), HandshakeType::Finished);
        assert_eq!(HandshakeType::from(255), HandshakeType::Invalid);
    }
}
