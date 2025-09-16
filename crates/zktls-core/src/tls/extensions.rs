//! TLS 1.3 Extensions (RFC 8446, Section 4.2)
//!
//! This module implements essential TLS 1.3 extensions for zkTLS functionality.
//! We focus on the minimal set required for secure TLS 1.3 handshakes.

use super::{TlsBytes, utils::*, MAX_EXTENSION_SIZE};
use crate::errors::ZkTlsError;
use alloc::{format, vec, vec::Vec};
use serde::{Deserialize, Serialize};

/// Extension types from the TLS Extension Type Registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum ExtensionType {
    ServerName = 0,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    ApplicationLayerProtocolNegotiation = 16,
    KeyShare = 51,
    SupportedVersions = 43,
}

impl TryFrom<u16> for ExtensionType {
    type Error = ZkTlsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ExtensionType::ServerName),
            10 => Ok(ExtensionType::SupportedGroups),
            13 => Ok(ExtensionType::SignatureAlgorithms),
            16 => Ok(ExtensionType::ApplicationLayerProtocolNegotiation),
            43 => Ok(ExtensionType::SupportedVersions),
            51 => Ok(ExtensionType::KeyShare),
            _ => Err(ZkTlsError::InvalidTlsMessage(
                format!("Unknown extension type: {}", value)
            )),
        }
    }
}

/// Generic extension structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub extension_data: TlsBytes,
}

impl Extension {
    /// Create a new extension
    pub fn new(extension_type: ExtensionType, extension_data: TlsBytes) -> Result<Self, ZkTlsError> {
        if extension_data.len() > MAX_EXTENSION_SIZE {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Extension data size {} exceeds maximum {}", 
                    extension_data.len(), MAX_EXTENSION_SIZE)
            ));
        }
        
        Ok(Extension {
            extension_type,
            extension_data,
        })
    }
    
    /// Parse an extension from wire format
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ZkTlsError> {
        if data.len() < 4 {  // Minimum extension size: type(2) + length(2)
            return Err(ZkTlsError::InvalidTlsMessage(
                "Extension too short".into()
            ));
        }
        
        let mut cursor = 0;
        
        // Parse extension type (2 bytes)
        let type_value = read_u16(data, &mut cursor)?;
        let extension_type = ExtensionType::try_from(type_value)
            .unwrap_or_else(|_| {
                // For unknown extensions, we'll still parse them but won't decode the content
                // This approach allows for better forward compatibility
                ExtensionType::ServerName  // Use a placeholder, the actual type is in type_value
            });
        
        // Parse extension data length (2 bytes)
        let data_length = read_u16(data, &mut cursor)? as usize;
        
        if data_length > MAX_EXTENSION_SIZE {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Extension data length {} exceeds maximum {}", 
                    data_length, MAX_EXTENSION_SIZE)
            ));
        }
        
        if cursor + data_length > data.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Extension claims {} bytes but only {} available", 
                    data_length, data.len() - cursor)
            ));
        }
        
        // Parse extension data
        let extension_data = read_bytes(data, &mut cursor, data_length)?.to_vec();
        
        // For unknown extension types, we need to preserve the original type value
        let extension = if ExtensionType::try_from(type_value).is_err() {
            // Store the raw type value in the data for unknown extensions
            let mut raw_data = Vec::with_capacity(2 + extension_data.len());
            raw_data.extend_from_slice(&type_value.to_be_bytes());
            raw_data.extend_from_slice(&extension_data);
            Extension {
                extension_type: ExtensionType::ServerName,  // Placeholder
                extension_data: raw_data,
            }
        } else {
            Extension {
                extension_type,
                extension_data,
            }
        };
        
        Ok((extension, cursor))
    }
    
    /// Serialize the extension to wire format
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::with_capacity(4 + self.extension_data.len());
        
        // Write extension type (2 bytes)
        write_u16(&mut buffer, self.extension_type as u16);
        
        // Write extension data length (2 bytes)
        write_u16(&mut buffer, self.extension_data.len() as u16);
        
        // Write extension data
        write_bytes(&mut buffer, &self.extension_data);
        
        buffer
    }
    
    /// Get the total size of the extension when serialized
    pub fn size(&self) -> usize {
        4 + self.extension_data.len()  // 4 bytes header + data
    }
}

/// Supported Versions extension (RFC 8446, Section 4.2.1)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportedVersions {
    pub versions: Vec<u16>,
}

impl SupportedVersions {
    /// Create a new SupportedVersions extension
    pub fn new(versions: Vec<u16>) -> Self {
        SupportedVersions { versions }
    }
    
    /// Create a TLS 1.3 only supported versions extension
    pub fn tls13_only() -> Self {
        SupportedVersions {
            versions: vec![0x0304],  // TLS 1.3
        }
    }
    
    /// Parse from extension data
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        if data.is_empty() {
            return Err(ZkTlsError::InvalidTlsMessage(
                "SupportedVersions extension cannot be empty".into()
            ));
        }
        
        let mut cursor = 0;
        
        // For ClientHello: 1-byte length prefix + versions
        // For ServerHello: just the version (2 bytes)
        let versions = if data.len() == 2 {
            // ServerHello format: just the selected version
            let version = read_u16(data, &mut cursor)?;
            vec![version]
        } else {
            // ClientHello format: length prefix + versions
            let length = read_u8(data, &mut cursor)? as usize;
            if length % 2 != 0 {
                return Err(ZkTlsError::InvalidTlsMessage(
                    "SupportedVersions length must be even".into()
                ));
            }
            
            if cursor + length > data.len() {
                return Err(ZkTlsError::InvalidTlsMessage(
                    "SupportedVersions length exceeds available data".into()
                ));
            }
            
            let mut versions = Vec::with_capacity(length / 2);
            for _ in 0..(length / 2) {
                let version = read_u16(data, &mut cursor)?;
                versions.push(version);
            }
            versions
        };
        
        Ok(SupportedVersions { versions })
    }
    
    /// Serialize for ClientHello (with length prefix)
    pub fn serialize_client_hello(&self) -> TlsBytes {
        let mut buffer = Vec::new();
        
        // Write length (1 byte)
        write_u8(&mut buffer, (self.versions.len() * 2) as u8);
        
        // Write versions (2 bytes each)
        for version in &self.versions {
            write_u16(&mut buffer, *version);
        }
        
        buffer
    }
    
    /// Serialize for ServerHello (just the version)
    pub fn serialize_server_hello(&self) -> TlsBytes {
        if self.versions.len() != 1 {
            panic!("ServerHello must contain exactly one version");
        }
        
        self.versions[0].to_be_bytes().to_vec()
    }
    
    /// Convert to extension
    pub fn to_extension_client_hello(&self) -> Result<Extension, ZkTlsError> {
        let data = self.serialize_client_hello();
        Extension::new(ExtensionType::SupportedVersions, data)
    }
    
    /// Convert to extension (ServerHello)
    pub fn to_extension_server_hello(&self) -> Result<Extension, ZkTlsError> {
        let data = self.serialize_server_hello();
        Extension::new(ExtensionType::SupportedVersions, data)
    }
    
    /// Check if TLS 1.3 is supported
    pub fn supports_tls13(&self) -> bool {
        self.versions.contains(&0x0304)
    }
}

/// Key Share extension (RFC 8446, Section 4.2.8)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyShareEntry {
    pub group: u16,           // Named group (e.g., x25519 = 29)
    pub key_exchange: TlsBytes, // Public key
}

impl KeyShareEntry {
    /// Create a new key share entry
    pub fn new(group: u16, key_exchange: TlsBytes) -> Self {
        KeyShareEntry { group, key_exchange }
    }
    
    /// Create an X25519 key share entry
    pub fn x25519(public_key: [u8; 32]) -> Self {
        KeyShareEntry {
            group: 29,  // X25519
            key_exchange: public_key.to_vec(),
        }
    }
    
    /// Parse from wire format
    pub fn parse(data: &[u8], cursor: &mut usize) -> Result<Self, ZkTlsError> {
        // Parse group (2 bytes)
        let group = read_u16(data, cursor)?;
        
        // Parse key exchange length (2 bytes)
        let key_length = read_u16(data, cursor)? as usize;
        
        // Parse key exchange data
        let key_exchange = read_bytes(data, cursor, key_length)?.to_vec();
        
        Ok(KeyShareEntry { group, key_exchange })
    }
    
    /// Serialize to wire format
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::new();
        
        // Write group (2 bytes)
        write_u16(&mut buffer, self.group);
        
        // Write key exchange length (2 bytes)
        write_u16(&mut buffer, self.key_exchange.len() as u16);
        
        // Write key exchange data
        write_bytes(&mut buffer, &self.key_exchange);
        
        buffer
    }
    
    /// Get the size when serialized
    pub fn size(&self) -> usize {
        4 + self.key_exchange.len()  // 4 bytes header + key data
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyShare {
    pub entries: Vec<KeyShareEntry>,
}

impl KeyShare {
    /// Create a new KeyShare extension
    pub fn new(entries: Vec<KeyShareEntry>) -> Self {
        KeyShare { entries }
    }
    
    /// Create a KeyShare with single X25519 entry
    pub fn x25519_only(public_key: [u8; 32]) -> Self {
        KeyShare {
            entries: vec![KeyShareEntry::x25519(public_key)],
        }
    }
    
    /// Parse from extension data
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        let mut cursor = 0;
        
        // Parse entries length (2 bytes)
        let entries_length = read_u16(data, &mut cursor)? as usize;
        
        if cursor + entries_length > data.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                "KeyShare entries length exceeds available data".into()
            ));
        }
        
        let mut entries = Vec::new();
        let end_cursor = cursor + entries_length;
        
        while cursor < end_cursor {
            let entry = KeyShareEntry::parse(data, &mut cursor)?;
            entries.push(entry);
        }
        
        Ok(KeyShare { entries })
    }
    
    /// Serialize to extension data
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::new();
        
        // Calculate total entries size
        let entries_size: usize = self.entries.iter().map(|e| e.size()).sum();
        
        // Write entries length (2 bytes)
        write_u16(&mut buffer, entries_size as u16);
        
        // Write entries
        for entry in &self.entries {
            buffer.extend_from_slice(&entry.serialize());
        }
        
        buffer
    }
    
    /// Convert to extension
    pub fn to_extension(&self) -> Result<Extension, ZkTlsError> {
        let data = self.serialize();
        Extension::new(ExtensionType::KeyShare, data)
    }
    
    /// Find entry by group
    pub fn find_entry(&self, group: u16) -> Option<&KeyShareEntry> {
        self.entries.iter().find(|e| e.group == group)
    }
}

/// Signature Algorithms extension (RFC 8446, Section 4.2.3)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureAlgorithms {
    pub supported_signature_algorithms: Vec<u16>,
}

impl SignatureAlgorithms {
    /// Create a new SignatureAlgorithms extension
    pub fn new(algorithms: Vec<u16>) -> Self {
        SignatureAlgorithms {
            supported_signature_algorithms: algorithms,
        }
    }
    
    /// Create a minimal set for zkTLS (ECDSA with P-256 and SHA-256)
    pub fn minimal_set() -> Self {
        SignatureAlgorithms {
            supported_signature_algorithms: vec![
                0x0403,  // ecdsa_secp256r1_sha256
                0x0804,  // rsa_pss_rsae_sha256
                0x0805,  // rsa_pss_rsae_sha384
                0x0806,  // rsa_pss_rsae_sha512
            ],
        }
    }
    
    /// Parse from extension data
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        let mut cursor = 0;
        
        // Parse algorithms length (2 bytes)
        let length = read_u16(data, &mut cursor)? as usize;
        
        if length % 2 != 0 {
            return Err(ZkTlsError::InvalidTlsMessage(
                "SignatureAlgorithms length must be even".into()
            ));
        }
        
        if cursor + length > data.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                "SignatureAlgorithms length exceeds available data".into()
            ));
        }
        
        let mut algorithms = Vec::with_capacity(length / 2);
        for _ in 0..(length / 2) {
            let algorithm = read_u16(data, &mut cursor)?;
            algorithms.push(algorithm);
        }
        
        Ok(SignatureAlgorithms {
            supported_signature_algorithms: algorithms,
        })
    }
    
    /// Serialize to extension data
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::new();
        
        // Write length (2 bytes)
        write_u16(&mut buffer, (self.supported_signature_algorithms.len() * 2) as u16);
        
        // Write algorithms (2 bytes each)
        for algorithm in &self.supported_signature_algorithms {
            write_u16(&mut buffer, *algorithm);
        }
        
        buffer
    }
    
    /// Convert to extension
    pub fn to_extension(&self) -> Result<Extension, ZkTlsError> {
        let data = self.serialize();
        Extension::new(ExtensionType::SignatureAlgorithms, data)
    }
    
    /// Check if a specific signature algorithm is supported
    pub fn supports(&self, algorithm: u16) -> bool {
        self.supported_signature_algorithms.contains(&algorithm)
    }
}

/// Extension list parser and serializer
pub struct ExtensionList {
    extensions: Vec<Extension>,
}

impl ExtensionList {
    /// Create a new empty extension list
    pub fn new() -> Self {
        ExtensionList {
            extensions: Vec::new(),
        }
    }
    
    /// Parse extensions from wire format
    pub fn parse(data: &[u8]) -> Result<Self, ZkTlsError> {
        if data.is_empty() {
            return Ok(ExtensionList::new());
        }
        
        let mut cursor = 0;
        let mut extensions = Vec::new();
        
        while cursor < data.len() {
            let (extension, consumed) = Extension::parse(&data[cursor..])?;
            extensions.push(extension);
            cursor += consumed;
        }
        
        Ok(ExtensionList { extensions })
    }
    
    /// Serialize extensions to wire format
    pub fn serialize(&self) -> TlsBytes {
        let mut buffer = Vec::new();
        
        for extension in &self.extensions {
            buffer.extend_from_slice(&extension.serialize());
        }
        
        buffer
    }
    
    /// Add an extension
    pub fn add(&mut self, extension: Extension) {
        self.extensions.push(extension);
    }
    
    /// Find an extension by type
    pub fn find(&self, ext_type: ExtensionType) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.extension_type == ext_type)
    }
    
    /// Get all extensions
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }
    
    /// Check if an extension type is present
    pub fn has_extension(&self, ext_type: ExtensionType) -> bool {
        self.find(ext_type).is_some()
    }
}

impl Default for ExtensionList {
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
    fn test_extension_type_conversion() {
        assert_eq!(ExtensionType::try_from(43).unwrap(), ExtensionType::SupportedVersions);
        assert_eq!(ExtensionType::try_from(51).unwrap(), ExtensionType::KeyShare);
        assert_eq!(ExtensionType::try_from(13).unwrap(), ExtensionType::SignatureAlgorithms);
        assert!(ExtensionType::try_from(9999).is_err());
    }
    
    #[test]
    fn test_extension_basic_structure() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let extension = Extension::new(ExtensionType::SupportedVersions, data.clone()).unwrap();
        
        assert_eq!(extension.extension_type, ExtensionType::SupportedVersions);
        assert_eq!(extension.extension_data, data);
    }
    
    #[test]
    fn test_extension_serialization_round_trip() {
        let data = vec![0x03, 0x04];  // TLS 1.3 version
        let original = Extension::new(ExtensionType::SupportedVersions, data).unwrap();
        
        let serialized = original.serialize();
        let (parsed, consumed) = Extension::parse(&serialized).unwrap();
        
        assert_eq!(consumed, serialized.len());
        assert_eq!(parsed, original);
    }
    
    #[test]
    fn test_supported_versions_tls13_only() {
        let supported_versions = SupportedVersions::tls13_only();
        
        assert_eq!(supported_versions.versions, vec![0x0304]);
        assert!(supported_versions.supports_tls13());
        
        // Test ClientHello serialization
        let client_hello_data = supported_versions.serialize_client_hello();
        let parsed = SupportedVersions::parse(&client_hello_data).unwrap();
        assert_eq!(parsed, supported_versions);
        
        // Test extension conversion
        let extension = supported_versions.to_extension_client_hello().unwrap();
        assert_eq!(extension.extension_type, ExtensionType::SupportedVersions);
    }
    
    #[test]
    fn test_key_share_x25519() {
        let public_key = [1u8; 32];  // Mock public key
        let key_share = KeyShare::x25519_only(public_key);
        
        assert_eq!(key_share.entries.len(), 1);
        assert_eq!(key_share.entries[0].group, 29);  // X25519
        assert_eq!(key_share.entries[0].key_exchange, public_key.to_vec());
        
        // Test serialization round trip
        let serialized = key_share.serialize();
        let parsed = KeyShare::parse(&serialized).unwrap();
        assert_eq!(parsed, key_share);
        
        // Test extension conversion
        let extension = key_share.to_extension().unwrap();
        assert_eq!(extension.extension_type, ExtensionType::KeyShare);
    }
    
    #[test]
    fn test_signature_algorithms_minimal() {
        let sig_algs = SignatureAlgorithms::minimal_set();
        
        assert!(!sig_algs.supported_signature_algorithms.is_empty());
        assert!(sig_algs.supports(0x0403));  // ecdsa_secp256r1_sha256
        
        // Test serialization round trip
        let serialized = sig_algs.serialize();
        let parsed = SignatureAlgorithms::parse(&serialized).unwrap();
        assert_eq!(parsed.supported_signature_algorithms, sig_algs.supported_signature_algorithms);
        
        // Test extension conversion
        let extension = sig_algs.to_extension().unwrap();
        assert_eq!(extension.extension_type, ExtensionType::SignatureAlgorithms);
    }
    
    #[test]
    fn test_extension_list() {
        let mut ext_list = ExtensionList::new();
        
        // Add supported versions
        let supported_versions = SupportedVersions::tls13_only();
        let sv_ext = supported_versions.to_extension_client_hello().unwrap();
        ext_list.add(sv_ext);
        
        // Add signature algorithms
        let sig_algs = SignatureAlgorithms::minimal_set();
        let sa_ext = sig_algs.to_extension().unwrap();
        ext_list.add(sa_ext);
        
        assert_eq!(ext_list.extensions().len(), 2);
        assert!(ext_list.has_extension(ExtensionType::SupportedVersions));
        assert!(ext_list.has_extension(ExtensionType::SignatureAlgorithms));
        assert!(!ext_list.has_extension(ExtensionType::KeyShare));
        
        // Test serialization round trip
        let serialized = ext_list.serialize();
        let parsed = ExtensionList::parse(&serialized).unwrap();
        assert_eq!(parsed.extensions().len(), 2);
    }
    
    #[test]
    fn test_extension_parsing_known_data() {
        // supported_versions extension with TLS 1.3 (client hello format)
        let data = hex!("002b 0003 020304");
        //           ^^^^ ^^^^ ^^^^^^
        //           |    |    +---- version list: length=2, TLS1.3=0x0304
        //           |    +--------- extension data length=3
        //           +-------------- extension type=43 (supported_versions)
        
        let (extension, consumed) = Extension::parse(&data).unwrap();
        
        assert_eq!(consumed, 7);
        assert_eq!(extension.extension_type, ExtensionType::SupportedVersions);
        
        // Parse the supported versions from the extension data
        let supported_versions = SupportedVersions::parse(&extension.extension_data).unwrap();
        assert!(supported_versions.supports_tls13());
        
        // Validate round trip
        let serialized = extension.serialize();
        assert_eq!(serialized, data.to_vec());
    }
    
    #[test]
    fn test_extension_parsing_errors() {
        // Too short
        let data = hex!("00");
        assert!(Extension::parse(&data).is_err());
        
        // Length exceeds available data
        let data = hex!("002b 0010 0304");  // Claims 16 bytes but only has 2
        assert!(Extension::parse(&data).is_err());
        
        // Empty extension list should parse OK
        let empty_list = ExtensionList::parse(&[]).unwrap();
        assert_eq!(empty_list.extensions().len(), 0);
    }
}