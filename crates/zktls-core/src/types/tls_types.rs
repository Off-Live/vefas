//! TLS-specific types and data structures
//!
//! This module contains all TLS-related types including cipher suites,
//! handshake data, message types, and protocol-specific structures.

use crate::{errors::ZkTlsError, FixedVec};
use core::fmt;
use heapless::Vec as HeaplessVec;
use serde::{Deserialize, Serialize};

/// TLS 1.3 cipher suite identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256
    Aes128GcmSha256 = 0x1301,
    /// TLS_AES_256_GCM_SHA384  
    Aes256GcmSha384 = 0x1302,
}

/// ECDHE group identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NamedGroup {
    /// secp256r1 (P-256)
    Secp256r1 = 0x0017,
    /// x25519
    X25519 = 0x001D,
}

/// Complete TLS 1.3 handshake data for zkVM verification
/// All data is stored as const arrays for efficient zkVM usage
#[derive(Debug, Clone)]
pub struct TlsHandshakeData {
    /// Test case description
    pub name: &'static str,
    /// Target domain
    pub domain: &'static str,
    /// Target port
    pub port: u16,
    /// Cipher suite used
    pub cipher_suite: CipherSuite,
    /// Named group for key exchange
    pub named_group: NamedGroup,
    
    // Client Hello data
    /// Client random (32 bytes)
    pub client_random: [u8; 32],
    /// Client Hello message bytes
    pub client_hello: &'static [u8],
    
    // Server Hello data  
    /// Server random (32 bytes)
    pub server_random: [u8; 32],
    /// Server Hello message bytes
    pub server_hello: &'static [u8],
    /// Server public key for ECDHE (uncompressed P-256 key)
    pub server_public_key: [u8; 65],
    
    // Key exchange data
    /// Client private key for ECDHE (32 bytes for P-256)
    pub client_private_key: [u8; 32],
    /// Client public key for ECDHE (uncompressed P-256 key)
    pub client_public_key: [u8; 65],
    /// Shared secret from ECDHE
    pub shared_secret: [u8; 32],
    
    // Key derivation results
    /// Handshake secret
    pub handshake_secret: [u8; 32],
    /// Client handshake traffic secret
    pub client_hs_traffic_secret: [u8; 32],
    /// Server handshake traffic secret  
    pub server_hs_traffic_secret: [u8; 32],
    /// Master secret
    pub master_secret: [u8; 32],
    /// Client application traffic secret
    pub client_app_traffic_secret: [u8; 32],
    /// Server application traffic secret
    pub server_app_traffic_secret: [u8; 32],
    
    // Certificate data
    /// Server certificate chain (DER encoded) - first cert
    pub server_certificate: &'static [u8],
    /// Certificate signature verification result
    pub cert_valid: bool,
    
    // Application data
    /// HTTP request plaintext
    pub request_plaintext: &'static [u8],
    /// HTTP request ciphertext + tag
    pub request_ciphertext: &'static [u8],
    /// HTTP response plaintext
    pub response_plaintext: &'static [u8],
    /// HTTP response ciphertext + tag
    pub response_ciphertext: &'static [u8],
}

/// TLS protocol message data
#[derive(Debug, Clone)]
pub struct TlsMessageData {
    /// Test case name
    pub name: &'static str,
    /// Message type
    pub message_type: TlsMessageType,
    /// Raw message bytes
    pub raw_bytes: &'static [u8],
    /// Parsed message data
    pub parsed: TlsMessage,
}

/// TLS message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsMessageType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    ApplicationData = 23,
}

/// Parsed TLS message data
#[derive(Debug, Clone)]
pub enum TlsMessage {
    ClientHello {
        version: u16,
        random: [u8; 32],
        session_id: &'static [u8],
        cipher_suites: &'static [u16],
        compression_methods: &'static [u8],
        extensions: &'static [TlsExtension],
    },
    ServerHello {
        version: u16,
        random: [u8; 32],
        session_id: &'static [u8],
        cipher_suite: u16,
        compression_method: u8,
        extensions: &'static [TlsExtension],
    },
    Certificate {
        certificates: &'static [&'static [u8]],
    },
    Finished {
        verify_data: &'static [u8],
    },
    ApplicationData {
        data: &'static [u8],
    },
}

/// TLS extension data
#[derive(Debug, Clone)]
pub struct TlsExtension {
    /// Extension type
    pub extension_type: u16,
    /// Extension data
    pub data: &'static [u8],
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipherSuite::Aes128GcmSha256 => write!(f, "TLS_AES_128_GCM_SHA256"),
            CipherSuite::Aes256GcmSha384 => write!(f, "TLS_AES_256_GCM_SHA384"),
        }
    }
}

impl fmt::Display for NamedGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NamedGroup::Secp256r1 => write!(f, "secp256r1"),
            NamedGroup::X25519 => write!(f, "x25519"),
        }
    }
}

/// Helper functions for creating handshake data
impl TlsHandshakeData {
    /// Create a new empty handshake data structure
    pub const fn new() -> Self {
        Self {
            name: "",
            domain: "",
            port: 443,
            cipher_suite: CipherSuite::Aes128GcmSha256,
            named_group: NamedGroup::Secp256r1,
            client_random: [0u8; 32],
            client_hello: &[],
            server_random: [0u8; 32],
            server_hello: &[],
            server_public_key: [0u8; 65],
            client_private_key: [0u8; 32],
            client_public_key: [0u8; 65],
            shared_secret: [0u8; 32],
            handshake_secret: [0u8; 32],
            client_hs_traffic_secret: [0u8; 32],
            server_hs_traffic_secret: [0u8; 32],
            master_secret: [0u8; 32],
            client_app_traffic_secret: [0u8; 32],
            server_app_traffic_secret: [0u8; 32],
            server_certificate: &[],
            cert_valid: false,
            request_plaintext: &[],
            request_ciphertext: &[],
            response_plaintext: &[],
            response_ciphertext: &[],
        }
    }
    
    /// Convert client_hello bytes to a heapless vector
    pub fn client_hello_vec<const N: usize>(&self) -> Result<FixedVec<u8, N>, ZkTlsError> {
        if self.client_hello.len() > N {
            return Err(ZkTlsError::DataTooLarge);
        }
        let mut vec = FixedVec::new();
        for &byte in self.client_hello {
            vec.push(byte).map_err(|_| ZkTlsError::DataTooLarge)?;
        }
        Ok(vec)
    }
    
    /// Convert server_hello bytes to a heapless vector
    pub fn server_hello_vec<const N: usize>(&self) -> Result<FixedVec<u8, N>, ZkTlsError> {
        if self.server_hello.len() > N {
            return Err(ZkTlsError::DataTooLarge);
        }
        let mut vec = FixedVec::new();
        for &byte in self.server_hello {
            vec.push(byte).map_err(|_| ZkTlsError::DataTooLarge)?;
        }
        Ok(vec)
    }
    
    /// Convert request_plaintext bytes to a heapless vector
    pub fn request_plaintext_vec<const N: usize>(&self) -> Result<FixedVec<u8, N>, ZkTlsError> {
        if self.request_plaintext.len() > N {
            return Err(ZkTlsError::DataTooLarge);
        }
        let mut vec = FixedVec::new();
        for &byte in self.request_plaintext {
            vec.push(byte).map_err(|_| ZkTlsError::DataTooLarge)?;
        }
        Ok(vec)
    }
}

impl Default for TlsHandshakeData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    
    #[test]
    fn test_handshake_data_creation() {
        let handshake = TlsHandshakeData::new();
        assert_eq!(handshake.port, 443);
        assert_eq!(handshake.cipher_suite, CipherSuite::Aes128GcmSha256);
        assert_eq!(handshake.named_group, NamedGroup::Secp256r1);
    }
    
    #[test]
    fn test_cipher_suite_display() {
        assert_eq!(
            CipherSuite::Aes128GcmSha256.to_string(),
            "TLS_AES_128_GCM_SHA256"
        );
    }
    
    #[test]
    fn test_fixed_size_collections() {
        let mut handshake = TlsHandshakeData::new();
        
        // Test that we can work with fixed-size collections
        for i in 0..32 {
            handshake.client_random[i] = i as u8;
        }
        
        assert_eq!(handshake.client_random[0], 0);
        assert_eq!(handshake.client_random[31], 31);
    }
}
