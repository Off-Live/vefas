//! TLS protocol types and structures
//!
//! This module provides comprehensive TLS 1.3 types following RFC 8446 specifications.
//! All types are designed for deterministic serialization in zkVM environments.

use alloc::{vec::Vec, string::ToString, vec};
use serde::{Deserialize, Serialize};
use crate::{VefasError, VefasResult, MAX_CERTIFICATE_CHAIN_LENGTH, MAX_HANDSHAKE_TRANSCRIPT_SIZE};
use crate::utils::{format_hex, format_decimal, format_named_group_debug};

/// TLS protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsVersion {
    /// TLS 1.3 (RFC 8446)
    V1_3,
}

impl TlsVersion {
    /// Get the wire format representation
    pub fn wire_format(&self) -> u16 {
        match self {
            TlsVersion::V1_3 => 0x0304,
        }
    }

    /// Parse from wire format
    pub fn from_wire_format(value: u16) -> VefasResult<Self> {
        match value {
            0x0304 => Ok(TlsVersion::V1_3),
            _ => Err(VefasError::tls_error(
                crate::errors::TlsErrorType::UnsupportedVersion,
                &("Unsupported TLS version: 0x".to_string() + &format_hex(value, 4)),
            )),
        }
    }

    /// Get human-readable string
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::V1_3 => "1.3",
        }
    }
}

/// TLS 1.3 cipher suites (RFC 8446) - Core supported suites
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256 (0x1301)
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (0x1302)
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303)
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    /// Get the wire format representation
    pub fn wire_format(&self) -> u16 {
        match self {
            CipherSuite::Aes128GcmSha256 => 0x1301,
            CipherSuite::Aes256GcmSha384 => 0x1302,
            CipherSuite::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    /// Parse from wire format
    pub fn from_wire_format(value: u16) -> VefasResult<Self> {
        match value {
            0x1301 => Ok(CipherSuite::Aes128GcmSha256),
            0x1302 => Ok(CipherSuite::Aes256GcmSha384),
            0x1303 => Ok(CipherSuite::ChaCha20Poly1305Sha256),
            _ => Err(VefasError::tls_error(
                crate::errors::TlsErrorType::UnsupportedCipherSuite,
                &("Unsupported cipher suite: 0x".to_string() + &format_hex(value, 4)),
            )),
        }
    }

    /// Get human-readable string
    pub fn as_str(&self) -> &'static str {
        match self {
            CipherSuite::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            CipherSuite::ChaCha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
        }
    }

    /// Get the hash algorithm for this cipher suite
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            CipherSuite::Aes128GcmSha256 => HashAlgorithm::Sha256,
            CipherSuite::Aes256GcmSha384 => HashAlgorithm::Sha384,
            CipherSuite::ChaCha20Poly1305Sha256 => HashAlgorithm::Sha256,
        }
    }

    /// Get the AEAD algorithm for this cipher suite
    pub fn aead_algorithm(&self) -> AeadAlgorithm {
        match self {
            CipherSuite::Aes128GcmSha256 => AeadAlgorithm::Aes128Gcm,
            CipherSuite::Aes256GcmSha384 => AeadAlgorithm::Aes256Gcm,
            CipherSuite::ChaCha20Poly1305Sha256 => AeadAlgorithm::ChaCha20Poly1305,
        }
    }

    /// Get the key length in bytes
    pub fn key_length(&self) -> usize {
        match self {
            CipherSuite::Aes128GcmSha256 => 16,
            CipherSuite::Aes256GcmSha384 => 32,
            CipherSuite::ChaCha20Poly1305Sha256 => 32,
        }
    }

    /// Get the IV length in bytes
    pub fn iv_length(&self) -> usize {
        match self {
            CipherSuite::Aes128GcmSha256 => 12,
            CipherSuite::Aes256GcmSha384 => 12,
            CipherSuite::ChaCha20Poly1305Sha256 => 12,
        }
    }

    /// Check if this cipher suite is deprecated
    pub fn is_deprecated(&self) -> bool {
        // None of our core cipher suites are deprecated
        false
    }

    /// Get all supported cipher suites
    pub fn all_supported() -> Vec<Self> {
        vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ]
    }

    /// Get all cipher suites (same as supported for core suites)
    pub fn all() -> Vec<Self> {
        Self::all_supported()
    }
}

/// Hash algorithms used in TLS 1.3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
}

impl HashAlgorithm {
    /// Get output length in bytes
    pub fn output_length(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
        }
    }

    /// Get the algorithm name
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "SHA256",
            HashAlgorithm::Sha384 => "SHA384",
        }
    }
}

/// AEAD algorithms used in TLS 1.3 - Core supported algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AeadAlgorithm {
    /// AES-128-GCM
    Aes128Gcm,
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

/// Named groups for key exchange (RFC 8446)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NamedGroup {
    /// secp256r1 (NIST P-256)
    Secp256r1,
    /// secp384r1 (NIST P-384)
    Secp384r1,
    /// secp521r1 (NIST P-521)
    Secp521r1,
    /// x25519 (Curve25519)
    X25519,
    /// x448 (Curve448)
    X448,
}

impl NamedGroup {
    /// Get the wire format representation
    pub fn wire_format(&self) -> u16 {
        match self {
            NamedGroup::Secp256r1 => 0x0017,
            NamedGroup::Secp384r1 => 0x0018,
            NamedGroup::Secp521r1 => 0x0019,
            NamedGroup::X25519 => 0x001d,
            NamedGroup::X448 => 0x001e,
        }
    }

    /// Parse from wire format
    pub fn from_wire_format(value: u16) -> VefasResult<Self> {
        match value {
            0x0017 => Ok(NamedGroup::Secp256r1),
            0x0018 => Ok(NamedGroup::Secp384r1),
            0x0019 => Ok(NamedGroup::Secp521r1),
            0x001d => Ok(NamedGroup::X25519),
            0x001e => Ok(NamedGroup::X448),
            _ => Err(VefasError::tls_error(
                crate::errors::TlsErrorType::UnsupportedCipherSuite,
                &("Unsupported named group: 0x".to_string() + &format_hex(value, 4)),
            )),
        }
    }

    /// Get the key length in bytes
    pub fn key_length(&self) -> usize {
        match self {
            NamedGroup::Secp256r1 => 32,
            NamedGroup::Secp384r1 => 48,
            NamedGroup::Secp521r1 => 66,
            NamedGroup::X25519 => 32,
            NamedGroup::X448 => 56,
        }
    }

    /// Get the public key length in bytes
    pub fn public_key_length(&self) -> usize {
        match self {
            NamedGroup::Secp256r1 => 65, // Uncompressed point
            NamedGroup::Secp384r1 => 97, // Uncompressed point
            NamedGroup::Secp521r1 => 133, // Uncompressed point
            NamedGroup::X25519 => 32,
            NamedGroup::X448 => 56,
        }
    }
}

/// Session keys derived during TLS handshake
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKeys {
    /// Client application traffic secret
    pub client_application_secret: Vec<u8>,
    /// Server application traffic secret
    pub server_application_secret: Vec<u8>,
    /// Client application traffic key
    pub client_application_key: Vec<u8>,
    /// Server application traffic key
    pub server_application_key: Vec<u8>,
    /// Client application IV
    pub client_application_iv: Vec<u8>,
    /// Server application IV
    pub server_application_iv: Vec<u8>,
    /// Handshake secret (for Finished message verification)
    pub handshake_secret: Vec<u8>,
    /// Master secret
    pub master_secret: Vec<u8>,
    /// Resumption master secret
    pub resumption_master_secret: Vec<u8>,
}

impl SessionKeys {
    /// Create new session keys with specified cipher suite
    pub fn new(cipher_suite: CipherSuite) -> Self {
        let key_len = cipher_suite.key_length();
        let iv_len = cipher_suite.iv_length();
        let hash_len = cipher_suite.hash_algorithm().output_length();

        Self {
            client_application_secret: vec![0u8; hash_len],
            server_application_secret: vec![0u8; hash_len],
            client_application_key: vec![0u8; key_len],
            server_application_key: vec![0u8; key_len],
            client_application_iv: vec![0u8; iv_len],
            server_application_iv: vec![0u8; iv_len],
            handshake_secret: vec![0u8; hash_len],
            master_secret: vec![0u8; hash_len],
            resumption_master_secret: vec![0u8; hash_len],
        }
    }

    /// Validate that all keys are present and have correct lengths
    pub fn validate(&self, cipher_suite: CipherSuite) -> VefasResult<()> {
        let key_len = cipher_suite.key_length();
        let iv_len = cipher_suite.iv_length();
        let _hash_len = cipher_suite.hash_algorithm().output_length();

        if self.client_application_key.len() != key_len {
            return Err(VefasError::crypto_error(
                crate::errors::CryptoErrorType::InvalidKeyLength,
                &("Invalid client application key length: expected ".to_string() + 
                  &format_decimal(key_len) + ", got " + &format_decimal(self.client_application_key.len())),
            ));
        }

        if self.server_application_key.len() != key_len {
            return Err(VefasError::crypto_error(
                crate::errors::CryptoErrorType::InvalidKeyLength,
                &("Invalid server application key length: expected ".to_string() + 
                  &format_decimal(key_len) + ", got " + &format_decimal(self.server_application_key.len())),
            ));
        }

        if self.client_application_iv.len() != iv_len {
            return Err(VefasError::crypto_error(
                crate::errors::CryptoErrorType::InvalidNonceLength,
                &("Invalid client application IV length: expected ".to_string() + 
                  &format_decimal(iv_len) + ", got " + &format_decimal(self.client_application_iv.len())),
            ));
        }

        if self.server_application_iv.len() != iv_len {
            return Err(VefasError::crypto_error(
                crate::errors::CryptoErrorType::InvalidNonceLength,
                &("Invalid server application IV length: expected ".to_string() + 
                  &format_decimal(iv_len) + ", got " + &format_decimal(self.server_application_iv.len())),
            ));
        }

        Ok(())
    }
}

/// TLS handshake data extracted from transcript
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeData {
    /// Complete handshake transcript
    pub transcript: Vec<u8>,
    /// Client random (32 bytes)
    pub client_random: [u8; 32],
    /// Server random (32 bytes)
    pub server_random: [u8; 32],
    /// Selected cipher suite
    pub cipher_suite: CipherSuite,
    /// Selected named group for key exchange
    pub named_group: NamedGroup,
    /// Client key share
    pub client_key_share: Vec<u8>,
    /// Server key share
    pub server_key_share: Vec<u8>,
    /// Extensions present in handshake
    pub extensions: Vec<TlsExtension>,
    /// TLS version
    pub version: TlsVersion,
}

impl HandshakeData {
    /// Validate handshake data consistency
    pub fn validate(&self) -> VefasResult<()> {
        // Check transcript size
        if self.transcript.len() > MAX_HANDSHAKE_TRANSCRIPT_SIZE {
            return Err(VefasError::memory_error(
                self.transcript.len(),
                MAX_HANDSHAKE_TRANSCRIPT_SIZE,
                "handshake transcript",
            ));
        }

        // Check key share lengths
        let expected_key_len = self.named_group.public_key_length();
        if self.client_key_share.len() != expected_key_len {
            return Err(VefasError::crypto_error(
                crate::errors::CryptoErrorType::InvalidKeyLength,
                &("Invalid client key share length for ".to_string() + 
                  &format_named_group_debug(&self.named_group) + ": expected " + 
                  &format_decimal(expected_key_len) + ", got " + 
                  &format_decimal(self.client_key_share.len())),
            ));
        }

        if self.server_key_share.len() != expected_key_len {
            return Err(VefasError::crypto_error(
                crate::errors::CryptoErrorType::InvalidKeyLength,
                &("Invalid server key share length for ".to_string() + 
                  &format_named_group_debug(&self.named_group) + ": expected " + 
                  &format_decimal(expected_key_len) + ", got " + 
                  &format_decimal(self.server_key_share.len())),
            ));
        }

        Ok(())
    }
}

/// TLS extension data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsExtension {
    /// Extension type
    pub extension_type: u16,
    /// Extension data
    pub data: Vec<u8>,
}

/// Certificate chain with validation metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateChain {
    /// DER-encoded certificates (leaf first)
    pub certificates: Vec<Vec<u8>>,
    /// Certificate validation timestamp
    pub validation_time: u64,
    /// Whether the chain was validated
    pub validated: bool,
    /// Root CA fingerprint used for validation
    pub root_ca_fingerprint: Option<[u8; 32]>,
}

impl CertificateChain {
    /// Create a new certificate chain
    pub fn new(certificates: Vec<Vec<u8>>) -> VefasResult<Self> {
        if certificates.is_empty() {
            return Err(VefasError::certificate_error(
                crate::errors::CertificateErrorType::InvalidFormat,
                "Certificate chain cannot be empty",
            ));
        }

        if certificates.len() > MAX_CERTIFICATE_CHAIN_LENGTH {
            return Err(VefasError::certificate_error(
                crate::errors::CertificateErrorType::ChainTooLong,
                &("Certificate chain too long: ".to_string() + 
                  &format_decimal(certificates.len()) + " certificates (max " + 
                  &format_decimal(MAX_CERTIFICATE_CHAIN_LENGTH) + ")"),
            ));
        }

        Ok(Self {
            certificates,
            validation_time: 0,
            validated: false,
            root_ca_fingerprint: None,
        })
    }

    /// Get the leaf certificate
    pub fn leaf_certificate(&self) -> &[u8] {
        &self.certificates[0]
    }

    /// Get intermediate certificates
    pub fn intermediate_certificates(&self) -> &[Vec<u8>] {
        if self.certificates.len() > 1 {
            &self.certificates[1..]
        } else {
            &[]
        }
    }

    /// Mark chain as validated
    pub fn mark_validated(&mut self, validation_time: u64, root_ca_fingerprint: [u8; 32]) {
        self.validated = true;
        self.validation_time = validation_time;
        self.root_ca_fingerprint = Some(root_ca_fingerprint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_wire_format() {
        assert_eq!(TlsVersion::V1_3.wire_format(), 0x0304);
        assert_eq!(TlsVersion::from_wire_format(0x0304).unwrap(), TlsVersion::V1_3);
    }

    #[test]
    fn test_cipher_suite_properties() {
        let cs = CipherSuite::Aes256GcmSha384;
        assert_eq!(cs.wire_format(), 0x1302);
        assert_eq!(cs.hash_algorithm(), HashAlgorithm::Sha384);
        assert_eq!(cs.key_length(), 32);
        assert_eq!(cs.iv_length(), 12);
    }

    #[test]
    fn test_session_keys_validation() {
        let cipher_suite = CipherSuite::Aes128GcmSha256;
        let keys = SessionKeys::new(cipher_suite);
        assert!(keys.validate(cipher_suite).is_ok());
    }

    #[test]
    fn test_certificate_chain_creation() {
        let certs = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let chain = CertificateChain::new(certs.clone()).unwrap();
        assert_eq!(chain.certificates, certs);
        assert_eq!(chain.leaf_certificate(), &[1, 2, 3]);
        assert_eq!(chain.intermediate_certificates(), &[vec![4, 5, 6]]);
    }

    #[test]
    fn test_handshake_data_validation() {
        let handshake = HandshakeData {
            transcript: vec![0u8; 100],
            client_random: [0u8; 32],
            server_random: [1u8; 32],
            cipher_suite: CipherSuite::Aes128GcmSha256,
            named_group: NamedGroup::X25519,
            client_key_share: vec![0u8; 32],
            server_key_share: vec![1u8; 32],
            extensions: vec![],
            version: TlsVersion::V1_3,
        };
        assert!(handshake.validate().is_ok());
    }
}