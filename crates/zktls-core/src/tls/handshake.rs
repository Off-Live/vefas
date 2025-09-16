//! TLS 1.3 Handshake Messages (RFC 8446, Section 4)
//!
//! This module implements all TLS 1.3 handshake message types and their parsing/serialization.
//! Each handshake message follows the standard format:
//! 
//! ```
//! struct {
//!     HandshakeType msg_type;
//!     uint24 length;
//!     select (Handshake.msg_type) {
//!         case client_hello:          ClientHello;
//!         case server_hello:          ServerHello;
//!         // ... other message types
//!     };
//! } Handshake;
//! ```

use super::{TlsBytes, utils::*, MAX_HANDSHAKE_MESSAGE_SIZE};
use crate::errors::ZkTlsError;
use alloc::{format, vec::Vec};
use serde::{Deserialize, Serialize};

/// Handshake message types from RFC 8446, Section 4
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl TryFrom<u8> for HandshakeType {
    type Error = ZkTlsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            4 => Ok(HandshakeType::NewSessionTicket),
            5 => Ok(HandshakeType::EndOfEarlyData),
            8 => Ok(HandshakeType::EncryptedExtensions),
            11 => Ok(HandshakeType::Certificate),
            13 => Ok(HandshakeType::CertificateRequest),
            15 => Ok(HandshakeType::CertificateVerify),
            20 => Ok(HandshakeType::Finished),
            24 => Ok(HandshakeType::KeyUpdate),
            254 => Ok(HandshakeType::MessageHash),
            _ => Err(ZkTlsError::InvalidTlsMessage(
                format!("Invalid handshake type: {}", value)
            )),
        }
    }
}

/// Generic handshake message structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub msg_type: HandshakeType,
    pub length: u32,  // 24-bit length
    pub payload: TlsBytes,
}

impl HandshakeMessage {
    /// Create a new handshake message
    pub fn new(msg_type: HandshakeType, payload: TlsBytes) -> Result<Self, ZkTlsError> {
        if payload.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Handshake message size {} exceeds maximum {}", 
                    payload.len(), MAX_HANDSHAKE_MESSAGE_SIZE)
            ));
        }
        
        let length = payload.len() as u32;
        
        Ok(HandshakeMessage {
            msg_type,
            length,
            payload,
        })
    }
    
    /// Parse a handshake message from wire format
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ZkTlsError> {
        if data.len() < 4 {  // Minimum handshake header size
            return Err(ZkTlsError::InvalidTlsMessage(
                "Handshake message too short".into()
            ));
        }
        
        let mut cursor = 0;
        
        // Parse message type (1 byte)
        let msg_type_byte = read_u8(data, &mut cursor)?;
        let msg_type = HandshakeType::try_from(msg_type_byte)?;
        
        // Parse length (3 bytes, 24-bit)
        let length = read_u24(data, &mut cursor)?;
        
        // Validate length
        if length > MAX_HANDSHAKE_MESSAGE_SIZE as u32 {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Handshake message length {} exceeds maximum {}", 
                    length, MAX_HANDSHAKE_MESSAGE_SIZE)
            ));
        }
        
        if cursor + length as usize > data.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Handshake message claims {} bytes but only {} available", 
                    length, data.len() - cursor)
            ));
        }
        
        // Parse payload
        let payload_data = read_bytes(data, &mut cursor, length as usize)?;
        let payload = payload_data.to_vec();
        
        let message = HandshakeMessage {
            msg_type,
            length,
            payload,
        };
        
        Ok((message, cursor))
    }
    
    /// Serialize the handshake message to wire format
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::with_capacity(4 + self.payload.len());
        
        // Write message type (1 byte)
        write_u8(&mut buffer, self.msg_type as u8);
        
        // Write length (3 bytes, 24-bit)
        write_u24(&mut buffer, self.length);
        
        // Write payload
        write_bytes(&mut buffer, &self.payload);
        
        buffer
    }
    
    /// Get the total size of the message when serialized
    pub fn size(&self) -> usize {
        4 + self.payload.len()  // 4 bytes header + payload
    }
    
    /// Validate the message structure
    pub fn validate(&self) -> Result<(), ZkTlsError> {
        // Check length consistency
        if self.length as usize != self.payload.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Length field {} doesn't match payload size {}", 
                    self.length, self.payload.len())
            ));
        }
        
        // Check maximum size
        if self.payload.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Payload size {} exceeds maximum {}", 
                    self.payload.len(), MAX_HANDSHAKE_MESSAGE_SIZE)
            ));
        }
        
        Ok(())
    }
    
    /// Check if this is a ClientHello message
    pub fn is_client_hello(&self) -> bool {
        self.msg_type == HandshakeType::ClientHello
    }
    
    /// Check if this is a ServerHello message
    pub fn is_server_hello(&self) -> bool {
        self.msg_type == HandshakeType::ServerHello
    }
    
    /// Check if this is a Certificate message
    pub fn is_certificate(&self) -> bool {
        self.msg_type == HandshakeType::Certificate
    }
    
    /// Check if this is a Finished message
    pub fn is_finished(&self) -> bool {
        self.msg_type == HandshakeType::Finished
    }
}

/// ClientHello message structure (RFC 8446, Section 4.1.2)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub legacy_session_id: TlsBytes,
    pub cipher_suites: Vec<u16>,
    pub legacy_compression_methods: TlsBytes,
    pub extensions: TlsBytes,  // Will be parsed separately by extensions module
}

impl ClientHello {
    /// Parse ClientHello from payload data
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        let mut cursor = 0;
        
        // Parse legacy_version (2 bytes)
        let legacy_version = read_u16(data, &mut cursor)?;
        
        // Parse random (32 bytes)
        let random_slice = read_bytes(data, &mut cursor, 32)?;
        let mut random = [0u8; 32];
        random.copy_from_slice(random_slice);
        
        // Parse legacy_session_id (variable length, 1 byte length prefix)
        let session_id_len = read_u8(data, &mut cursor)? as usize;
        if session_id_len > 32 {  // RFC 8446: session ID limited to 32 bytes
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Session ID length {} exceeds maximum 32", session_id_len)
            ));
        }
        let legacy_session_id = read_bytes(data, &mut cursor, session_id_len)?.to_vec();
        
        // Parse cipher_suites (variable length, 2 byte length prefix)
        let cipher_suites_len = read_u16(data, &mut cursor)? as usize;
        if cipher_suites_len % 2 != 0 {
            return Err(ZkTlsError::InvalidTlsMessage(
                "Cipher suites length must be even".into()
            ));
        }
        
        let mut cipher_suites = Vec::with_capacity(cipher_suites_len / 2);
        for _ in 0..(cipher_suites_len / 2) {
            let suite = read_u16(data, &mut cursor)?;
            cipher_suites.push(suite);
        }
        
        // Parse legacy_compression_methods (variable length, 1 byte length prefix)
        let compression_len = read_u8(data, &mut cursor)? as usize;
        let legacy_compression_methods = read_bytes(data, &mut cursor, compression_len)?.to_vec();
        
        // Parse extensions (remaining data, 2 byte length prefix)
        let extensions = if cursor < data.len() {
            let extensions_len = read_u16(data, &mut cursor)? as usize;
            read_bytes(data, &mut cursor, extensions_len)?.to_vec()
        } else {
            Vec::new()  // Extensions are optional
        };
        
        Ok(ClientHello {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions,
        })
    }
    
    /// Serialize ClientHello to payload data
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::new();
        
        // Write legacy_version (2 bytes)
        write_u16(&mut buffer, self.legacy_version);
        
        // Write random (32 bytes)
        write_bytes(&mut buffer, &self.random);
        
        // Write legacy_session_id (1 byte length + data)
        write_u8(&mut buffer, self.legacy_session_id.len() as u8);
        write_bytes(&mut buffer, &self.legacy_session_id);
        
        // Write cipher_suites (2 byte length + data)
        write_u16(&mut buffer, (self.cipher_suites.len() * 2) as u16);
        for suite in &self.cipher_suites {
            write_u16(&mut buffer, *suite);
        }
        
        // Write legacy_compression_methods (1 byte length + data)
        write_u8(&mut buffer, self.legacy_compression_methods.len() as u8);
        write_bytes(&mut buffer, &self.legacy_compression_methods);
        
        // Write extensions (2 byte length + data)
        if !self.extensions.is_empty() {
            write_u16(&mut buffer, self.extensions.len() as u16);
            write_bytes(&mut buffer, &self.extensions);
        }
        
        buffer
    }
    
    /// Create a ClientHello handshake message
    pub fn to_handshake_message(&self) -> Result<HandshakeMessage, ZkTlsError> {
        let payload = self.serialize();
        HandshakeMessage::new(HandshakeType::ClientHello, payload)
    }
}

/// ServerHello message structure (RFC 8446, Section 4.1.3)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub legacy_session_id_echo: TlsBytes,
    pub cipher_suite: u16,
    pub legacy_compression_method: u8,
    pub extensions: TlsBytes,  // Will be parsed separately by extensions module
}

impl ServerHello {
    /// Parse ServerHello from payload data
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        let mut cursor = 0;
        
        // Parse legacy_version (2 bytes)
        let legacy_version = read_u16(data, &mut cursor)?;
        
        // Parse random (32 bytes)
        let random_slice = read_bytes(data, &mut cursor, 32)?;
        let mut random = [0u8; 32];
        random.copy_from_slice(random_slice);
        
        // Parse legacy_session_id_echo (variable length, 1 byte length prefix)
        let session_id_len = read_u8(data, &mut cursor)? as usize;
        let legacy_session_id_echo = read_bytes(data, &mut cursor, session_id_len)?.to_vec();
        
        // Parse cipher_suite (2 bytes)
        let cipher_suite = read_u16(data, &mut cursor)?;
        
        // Parse legacy_compression_method (1 byte, must be 0 for TLS 1.3)
        let legacy_compression_method = read_u8(data, &mut cursor)?;
        
        // Parse extensions (remaining data, 2 byte length prefix)
        let extensions = if cursor < data.len() {
            let extensions_len = read_u16(data, &mut cursor)? as usize;
            read_bytes(data, &mut cursor, extensions_len)?.to_vec()
        } else {
            Vec::new()
        };
        
        Ok(ServerHello {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suite,
            legacy_compression_method,
            extensions,
        })
    }
    
    /// Serialize ServerHello to payload data
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::new();
        
        // Write legacy_version (2 bytes)
        write_u16(&mut buffer, self.legacy_version);
        
        // Write random (32 bytes)
        write_bytes(&mut buffer, &self.random);
        
        // Write legacy_session_id_echo (1 byte length + data)
        write_u8(&mut buffer, self.legacy_session_id_echo.len() as u8);
        write_bytes(&mut buffer, &self.legacy_session_id_echo);
        
        // Write cipher_suite (2 bytes)
        write_u16(&mut buffer, self.cipher_suite);
        
        // Write legacy_compression_method (1 byte)
        write_u8(&mut buffer, self.legacy_compression_method);
        
        // Write extensions (2 byte length + data)
        if !self.extensions.is_empty() {
            write_u16(&mut buffer, self.extensions.len() as u16);
            write_bytes(&mut buffer, &self.extensions);
        }
        
        buffer
    }
    
    /// Create a ServerHello handshake message
    pub fn to_handshake_message(&self) -> Result<HandshakeMessage, ZkTlsError> {
        let payload = self.serialize();
        HandshakeMessage::new(HandshakeType::ServerHello, payload)
    }
}

/// Certificate message structure (simplified for now)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    pub certificate_request_context: TlsBytes,
    pub certificate_list: TlsBytes,  // Will be parsed by X.509 module
}

impl Certificate {
    /// Parse Certificate from payload data
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        let mut cursor = 0;
        
        // Parse certificate_request_context (1 byte length + data)
        let context_len = read_u8(data, &mut cursor)? as usize;
        let certificate_request_context = read_bytes(data, &mut cursor, context_len)?.to_vec();
        
        // Parse certificate_list (3 byte length + data)
        let list_len = read_u24(data, &mut cursor)? as usize;
        let certificate_list = read_bytes(data, &mut cursor, list_len)?.to_vec();
        
        Ok(Certificate {
            certificate_request_context,
            certificate_list,
        })
    }
    
    /// Serialize Certificate to payload data
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::new();
        
        // Write certificate_request_context (1 byte length + data)
        write_u8(&mut buffer, self.certificate_request_context.len() as u8);
        write_bytes(&mut buffer, &self.certificate_request_context);
        
        // Write certificate_list (3 byte length + data)
        write_u24(&mut buffer, self.certificate_list.len() as u32);
        write_bytes(&mut buffer, &self.certificate_list);
        
        buffer
    }
    
    /// Create a Certificate handshake message
    pub fn to_handshake_message(&self) -> Result<HandshakeMessage, ZkTlsError> {
        let payload = self.serialize();
        HandshakeMessage::new(HandshakeType::Certificate, payload)
    }
}

/// SignatureScheme values from RFC 8446, Section 4.2.3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum SignatureScheme {
    // RSASSA-PKCS1-v1_5 algorithms
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,
    
    // ECDSA algorithms
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,
    
    // RSASSA-PSS algorithms with public key OID rsaEncryption
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,
    
    // EdDSA algorithms
    Ed25519 = 0x0807,
    Ed448 = 0x0808,
    
    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    RsaPssPssSha256 = 0x0809,
    RsaPssPssSha384 = 0x080a,
    RsaPssPssSha512 = 0x080b,
}

impl TryFrom<u16> for SignatureScheme {
    type Error = ZkTlsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0401 => Ok(SignatureScheme::RsaPkcs1Sha256),
            0x0501 => Ok(SignatureScheme::RsaPkcs1Sha384),
            0x0601 => Ok(SignatureScheme::RsaPkcs1Sha512),
            0x0403 => Ok(SignatureScheme::EcdsaSecp256r1Sha256),
            0x0503 => Ok(SignatureScheme::EcdsaSecp384r1Sha384),
            0x0603 => Ok(SignatureScheme::EcdsaSecp521r1Sha512),
            0x0804 => Ok(SignatureScheme::RsaPssRsaeSha256),
            0x0805 => Ok(SignatureScheme::RsaPssRsaeSha384),
            0x0806 => Ok(SignatureScheme::RsaPssRsaeSha512),
            0x0807 => Ok(SignatureScheme::Ed25519),
            0x0808 => Ok(SignatureScheme::Ed448),
            0x0809 => Ok(SignatureScheme::RsaPssPssSha256),
            0x080a => Ok(SignatureScheme::RsaPssPssSha384),
            0x080b => Ok(SignatureScheme::RsaPssPssSha512),
            _ => Err(ZkTlsError::InvalidTlsMessage(
                format!("Invalid signature scheme: 0x{:04x}", value)
            )),
        }
    }
}

/// CertificateVerify message structure (RFC 8446, Section 4.4.3)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateVerify {
    pub algorithm: SignatureScheme,
    pub signature: TlsBytes,
}

impl CertificateVerify {
    /// Parse CertificateVerify from payload data
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        let mut cursor = 0;
        
        // Parse algorithm (2 bytes)
        let algorithm_value = read_u16(data, &mut cursor)?;
        let algorithm = SignatureScheme::try_from(algorithm_value)?;
        
        // Parse signature (2 byte length + data)
        let signature_len = read_u16(data, &mut cursor)? as usize;
        let signature = read_bytes(data, &mut cursor, signature_len)?.to_vec();
        
        Ok(CertificateVerify {
            algorithm,
            signature,
        })
    }
    
    /// Serialize CertificateVerify to payload data
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::new();
        
        // Write algorithm (2 bytes)
        write_u16(&mut buffer, self.algorithm as u16);
        
        // Write signature (2 byte length + data)
        write_u16(&mut buffer, self.signature.len() as u16);
        write_bytes(&mut buffer, &self.signature);
        
        buffer
    }
    
    /// Create a CertificateVerify handshake message
    pub fn to_handshake_message(&self) -> Result<HandshakeMessage, ZkTlsError> {
        let payload = self.serialize();
        HandshakeMessage::new(HandshakeType::CertificateVerify, payload)
    }
}

/// Finished message structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finished {
    pub verify_data: TlsBytes,  // HMAC of handshake transcript
}

impl Finished {
    /// Parse Finished from payload data
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        // Finished message is just the verify_data
        Ok(Finished {
            verify_data: data.to_vec(),
        })
    }
    
    /// Serialize Finished to payload data
    pub fn serialize(&self) -> TlsBytes {
        self.verify_data.clone()
    }
    
    /// Create a Finished handshake message
    pub fn to_handshake_message(&self) -> Result<HandshakeMessage, ZkTlsError> {
        let payload = self.serialize();
        HandshakeMessage::new(HandshakeType::Finished, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use alloc::vec;
    
    #[test]
    fn test_handshake_type_conversion() {
        assert_eq!(HandshakeType::try_from(1).unwrap(), HandshakeType::ClientHello);
        assert_eq!(HandshakeType::try_from(2).unwrap(), HandshakeType::ServerHello);
        assert_eq!(HandshakeType::try_from(11).unwrap(), HandshakeType::Certificate);
        assert!(HandshakeType::try_from(255).is_err());
    }
    
    #[test]
    fn test_handshake_message_creation() {
        let payload = vec![0x03, 0x03, 0x01, 0x02]; // Simple payload
        let message = HandshakeMessage::new(HandshakeType::ClientHello, payload.clone()).unwrap();
        
        assert_eq!(message.msg_type, HandshakeType::ClientHello);
        assert_eq!(message.length, 4);
        assert_eq!(message.payload, payload);
        assert!(message.is_client_hello());
    }
    
    #[test] 
    fn test_handshake_message_serialization_round_trip() {
        let payload = vec![0x03, 0x03, 0x01, 0x02, 0x03, 0x04];
        let original = HandshakeMessage::new(HandshakeType::ServerHello, payload).unwrap();
        
        let serialized = original.serialize();
        let (parsed, consumed) = HandshakeMessage::parse(&serialized).unwrap();
        
        assert_eq!(consumed, serialized.len());
        assert_eq!(parsed, original);
    }
    
    #[test]
    fn test_handshake_message_parsing_known_data() {
        // A simple handshake message: type=1 (ClientHello), length=4, payload=[01,02,03,04]
        let data = hex!("01 000004 01020304");
        //           ^^ ^^^^^^ ^^^^^^^^
        //           |  |      +------ 4 bytes of payload
        //           |  +------------- length = 4 (24-bit)
        //           +---------------- msg_type = ClientHello (1)
        
        let (message, consumed) = HandshakeMessage::parse(&data).unwrap();
        
        assert_eq!(consumed, 8); // 4 byte header + 4 byte payload
        assert_eq!(message.msg_type, HandshakeType::ClientHello);
        assert_eq!(message.length, 4);
        assert_eq!(message.payload, vec![0x01, 0x02, 0x03, 0x04]);
        
        // Validate round trip
        let serialized = message.serialize();
        assert_eq!(serialized, data.to_vec());
    }
    
    #[test]
    fn test_client_hello_basic_structure() {
        let mut random = [0u8; 32];
        random[0] = 0x01;
        random[31] = 0xFF;
        
        let client_hello = ClientHello {
            legacy_version: 0x0303,  // TLS 1.2 for compatibility
            random,
            legacy_session_id: vec![],
            cipher_suites: vec![0x1301, 0x1302], // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
            legacy_compression_methods: vec![0x00], // null compression
            extensions: vec![],
        };
        
        // Test serialization round trip
        let serialized = client_hello.serialize();
        let parsed = ClientHello::parse(&serialized).unwrap();
        assert_eq!(parsed, client_hello);
        
        // Test handshake message conversion
        let handshake_msg = client_hello.to_handshake_message().unwrap();
        assert_eq!(handshake_msg.msg_type, HandshakeType::ClientHello);
    }
    
    #[test]
    fn test_server_hello_basic_structure() {
        let mut random = [0u8; 32];
        random[0] = 0xFF;
        random[31] = 0x01;
        
        let server_hello = ServerHello {
            legacy_version: 0x0303,  // TLS 1.2 for compatibility
            random,
            legacy_session_id_echo: vec![],
            cipher_suite: 0x1301,  // TLS_AES_128_GCM_SHA256
            legacy_compression_method: 0x00,  // null compression
            extensions: vec![],
        };
        
        // Test serialization round trip
        let serialized = server_hello.serialize();
        let parsed = ServerHello::parse(&serialized).unwrap();
        assert_eq!(parsed, server_hello);
        
        // Test handshake message conversion
        let handshake_msg = server_hello.to_handshake_message().unwrap();
        assert_eq!(handshake_msg.msg_type, HandshakeType::ServerHello);
    }
    
    #[test]
    fn test_certificate_basic_structure() {
        let certificate = Certificate {
            certificate_request_context: vec![],
            certificate_list: vec![0x01, 0x02, 0x03, 0x04], // Placeholder cert data
        };
        
        // Test serialization round trip
        let serialized = certificate.serialize();
        let parsed = Certificate::parse(&serialized).unwrap();
        assert_eq!(parsed, certificate);
        
        // Test handshake message conversion
        let handshake_msg = certificate.to_handshake_message().unwrap();
        assert_eq!(handshake_msg.msg_type, HandshakeType::Certificate);
    }
    
    #[test]
    fn test_certificate_verify_basic_structure() {
        let certificate_verify = CertificateVerify {
            algorithm: SignatureScheme::EcdsaSecp256r1Sha256,
            signature: vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            ], // Mock signature
        };
        
        // Test serialization round trip
        let serialized = certificate_verify.serialize();
        let parsed = CertificateVerify::parse(&serialized).unwrap();
        assert_eq!(parsed, certificate_verify);
        
        // Test handshake message conversion
        let handshake_msg = certificate_verify.to_handshake_message().unwrap();
        assert_eq!(handshake_msg.msg_type, HandshakeType::CertificateVerify);
    }
    
    #[test]
    fn test_signature_scheme_conversion() {
        assert_eq!(SignatureScheme::try_from(0x0403).unwrap(), SignatureScheme::EcdsaSecp256r1Sha256);
        assert_eq!(SignatureScheme::try_from(0x0401).unwrap(), SignatureScheme::RsaPkcs1Sha256);
        assert_eq!(SignatureScheme::try_from(0x0807).unwrap(), SignatureScheme::Ed25519);
        assert!(SignatureScheme::try_from(0xFFFF).is_err());
    }

    #[test]
    fn test_finished_basic_structure() {
        let finished = Finished {
            verify_data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // Mock HMAC
        };
        
        // Test serialization round trip
        let serialized = finished.serialize();
        let parsed = Finished::parse(&serialized).unwrap();
        assert_eq!(parsed, finished);
        
        // Test handshake message conversion
        let handshake_msg = finished.to_handshake_message().unwrap();
        assert_eq!(handshake_msg.msg_type, HandshakeType::Finished);
    }
    
    #[test]
    fn test_handshake_parsing_errors() {
        // Too short for header
        let data = hex!("01 00");
        assert!(HandshakeMessage::parse(&data).is_err());
        
        // Length exceeds available data
        let data = hex!("01 000010 0102");  // Claims 16 bytes but only has 2
        assert!(HandshakeMessage::parse(&data).is_err());
        
        // Invalid message type
        let data = hex!("FF 000004 01020304");
        assert!(HandshakeMessage::parse(&data).is_err());
    }
    
    #[test]
    fn test_handshake_message_validation() {
        let payload = vec![0x01, 0x02, 0x03];
        let mut message = HandshakeMessage::new(
            HandshakeType::ClientHello,
            payload
        ).unwrap();
        
        // Valid message should pass
        assert!(message.validate().is_ok());
        
        // Corrupt length field
        message.length = 100;
        assert!(message.validate().is_err());
    }
    
    #[test]
    fn test_handshake_max_size() {
        // Test message size limit
        let payload = vec![0u8; MAX_HANDSHAKE_MESSAGE_SIZE + 1];
        assert!(HandshakeMessage::new(HandshakeType::ClientHello, payload).is_err());
        
        // Max size should be OK
        let payload = vec![0u8; MAX_HANDSHAKE_MESSAGE_SIZE];
        assert!(HandshakeMessage::new(HandshakeType::ClientHello, payload).is_ok());
    }
}