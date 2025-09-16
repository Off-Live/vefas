//! Error types for zkTLS operations
//! 
//! This module defines all error types used throughout the zkTLS implementation,
//! providing clear error handling for different failure scenarios.

use core::fmt;
use serde::{Deserialize, Serialize};

/// Result type for zkTLS operations
pub type ZkTlsResult<T> = core::result::Result<T, ZkTlsError>;

/// Main error type for zkTLS operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZkTlsError {
    /// Data too large for fixed-size container
    DataTooLarge,
    /// Invalid format or encoding
    InvalidFormat,
    /// Missing required field
    MissingField,
    /// Invalid TLS message format
    InvalidTlsMessage(alloc::string::String),
    /// Cryptographic operation failed
    CryptoError(CryptoError),
    /// TLS protocol error
    ProtocolError(ProtocolError),
    /// Certificate validation error
    CertificateError(CertificateError),
    /// zkVM platform specific error
    PlatformError(PlatformError),
}

/// Cryptographic operation errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoError {
    /// Invalid key size
    InvalidKeySize,
    /// Invalid signature
    InvalidSignature,
    /// Invalid hash
    InvalidHash,
    /// HKDF derivation failed
    HkdfFailed,
    /// AES-GCM operation failed
    AesGcmFailed,
    /// ECDSA operation failed
    EcdsaFailed,
    /// Random number generation failed
    RngFailed,
}

/// TLS protocol errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolError {
    /// Unsupported TLS version
    UnsupportedVersion,
    /// Unsupported cipher suite
    UnsupportedCipherSuite,
    /// Invalid handshake message
    InvalidHandshake,
    /// Invalid record format
    InvalidRecord,
    /// Handshake verification failed
    HandshakeVerificationFailed,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Invalid handshake state transition
    InvalidStateTransition(alloc::string::String),
    /// Invalid Finished message HMAC
    InvalidFinishedMessage,
}

/// Certificate validation errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateError {
    /// Invalid certificate format
    InvalidFormat,
    /// Certificate chain validation failed
    ChainValidationFailed,
    /// Certificate expired
    Expired,
    /// Certificate not yet valid
    NotYetValid,
    /// Hostname mismatch
    HostnameMismatch,
    /// Untrusted root
    UntrustedRoot,
}

/// zkVM platform specific errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformError {
    /// SP1 specific error
    #[cfg(feature = "sp1")]
    Sp1Error(Sp1Error),
    /// RISC0 specific error
    #[cfg(feature = "risc0")]
    Risc0Error(Risc0Error),
    /// Unsupported platform
    UnsupportedPlatform,
    /// Precompile not available
    PrecompileUnavailable,
}

/// SP1 specific errors
#[cfg(feature = "sp1")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sp1Error {
    /// Proof generation failed
    ProofGenerationFailed,
    /// Proof verification failed
    ProofVerificationFailed,
    /// Precompile error
    PrecompileError,
}

/// RISC0 specific errors
#[cfg(feature = "risc0")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Risc0Error {
    /// Proof generation failed
    ProofGenerationFailed,
    /// Proof verification failed
    ProofVerificationFailed,
    /// Guest execution failed
    GuestExecutionFailed,
}

impl fmt::Display for ZkTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZkTlsError::DataTooLarge => write!(f, "Data exceeds maximum size"),
            ZkTlsError::InvalidFormat => write!(f, "Invalid data format"),
            ZkTlsError::MissingField => write!(f, "Missing required field"),
            ZkTlsError::InvalidTlsMessage(msg) => write!(f, "Invalid TLS message: {}", msg),
            ZkTlsError::CryptoError(e) => write!(f, "Cryptographic error: {}", e),
            ZkTlsError::ProtocolError(e) => write!(f, "TLS protocol error: {}", e),
            ZkTlsError::CertificateError(e) => write!(f, "Certificate error: {}", e),
            ZkTlsError::PlatformError(e) => write!(f, "Platform error: {}", e),
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeySize => write!(f, "Invalid key size"),
            CryptoError::InvalidSignature => write!(f, "Invalid signature"),
            CryptoError::InvalidHash => write!(f, "Invalid hash"),
            CryptoError::HkdfFailed => write!(f, "HKDF derivation failed"),
            CryptoError::AesGcmFailed => write!(f, "AES-GCM operation failed"),
            CryptoError::EcdsaFailed => write!(f, "ECDSA operation failed"),
            CryptoError::RngFailed => write!(f, "Random number generation failed"),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::UnsupportedVersion => write!(f, "Unsupported TLS version"),
            ProtocolError::UnsupportedCipherSuite => write!(f, "Unsupported cipher suite"),
            ProtocolError::InvalidHandshake => write!(f, "Invalid handshake message"),
            ProtocolError::InvalidRecord => write!(f, "Invalid record format"),
            ProtocolError::HandshakeVerificationFailed => write!(f, "Handshake verification failed"),
            ProtocolError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            ProtocolError::InvalidStateTransition(msg) => write!(f, "Invalid state transition: {}", msg),
            ProtocolError::InvalidFinishedMessage => write!(f, "Invalid Finished message HMAC"),
        }
    }
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertificateError::InvalidFormat => write!(f, "Invalid certificate format"),
            CertificateError::ChainValidationFailed => write!(f, "Certificate chain validation failed"),
            CertificateError::Expired => write!(f, "Certificate expired"),
            CertificateError::NotYetValid => write!(f, "Certificate not yet valid"),
            CertificateError::HostnameMismatch => write!(f, "Hostname mismatch"),
            CertificateError::UntrustedRoot => write!(f, "Untrusted root certificate"),
        }
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "sp1")]
            PlatformError::Sp1Error(e) => write!(f, "SP1 error: {}", e),
            #[cfg(feature = "risc0")]
            PlatformError::Risc0Error(e) => write!(f, "RISC0 error: {}", e),
            PlatformError::UnsupportedPlatform => write!(f, "Unsupported platform"),
            PlatformError::PrecompileUnavailable => write!(f, "Precompile not available"),
        }
    }
}

#[cfg(feature = "sp1")]
impl fmt::Display for Sp1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sp1Error::ProofGenerationFailed => write!(f, "Proof generation failed"),
            Sp1Error::ProofVerificationFailed => write!(f, "Proof verification failed"),
            Sp1Error::PrecompileError => write!(f, "Precompile error"),
        }
    }
}

#[cfg(feature = "risc0")]
impl fmt::Display for Risc0Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Risc0Error::ProofGenerationFailed => write!(f, "Proof generation failed"),
            Risc0Error::ProofVerificationFailed => write!(f, "Proof verification failed"),
            Risc0Error::GuestExecutionFailed => write!(f, "Guest execution failed"),
        }
    }
}

// Convert from legacy FixtureError to ZkTlsError for backwards compatibility
impl From<CryptoError> for ZkTlsError {
    fn from(err: CryptoError) -> Self {
        ZkTlsError::CryptoError(err)
    }
}

impl From<ProtocolError> for ZkTlsError {
    fn from(err: ProtocolError) -> Self {
        ZkTlsError::ProtocolError(err)
    }
}

impl From<CertificateError> for ZkTlsError {
    fn from(err: CertificateError) -> Self {
        ZkTlsError::CertificateError(err)
    }
}

impl From<PlatformError> for ZkTlsError {
    fn from(err: PlatformError) -> Self {
        ZkTlsError::PlatformError(err)
    }
}

impl ZkTlsError {
    /// Create an InvalidStateTransition error with a message
    pub fn invalid_state_transition(message: impl Into<alloc::string::String>) -> Self {
        ZkTlsError::ProtocolError(ProtocolError::InvalidStateTransition(message.into()))
    }
}

impl From<zktls_crypto::CryptoError> for ZkTlsError {
    fn from(error: zktls_crypto::CryptoError) -> Self {
        ZkTlsError::CryptoError(CryptoError::from(error))
    }
}

impl From<zktls_crypto::CryptoError> for CryptoError {
    fn from(error: zktls_crypto::CryptoError) -> Self {
        match error {
            zktls_crypto::CryptoError::InvalidKeySize(_) => CryptoError::InvalidKeySize,
            zktls_crypto::CryptoError::InvalidSignature => CryptoError::InvalidSignature,
            zktls_crypto::CryptoError::VerificationFailed => CryptoError::InvalidSignature,
            zktls_crypto::CryptoError::DecryptionFailed => CryptoError::AesGcmFailed,
            zktls_crypto::CryptoError::InvalidPublicKey => CryptoError::InvalidSignature,
            zktls_crypto::CryptoError::InvalidPrivateKey => CryptoError::InvalidSignature,
            zktls_crypto::CryptoError::KeyGenerationFailed => CryptoError::RngFailed,
            zktls_crypto::CryptoError::UnsupportedOperation(_) => CryptoError::EcdsaFailed,
            zktls_crypto::CryptoError::PlatformNotSupported => CryptoError::EcdsaFailed,
            zktls_crypto::CryptoError::InvalidHkdfOutputLength { .. } => CryptoError::HkdfFailed,
            zktls_crypto::CryptoError::InvalidHkdfPrk { .. } => CryptoError::HkdfFailed,
            zktls_crypto::CryptoError::PrecompileError(_) => CryptoError::EcdsaFailed,
            zktls_crypto::CryptoError::InvalidNonceSize { .. } => CryptoError::AesGcmFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    
    #[test]
    fn test_error_display() {
        let error = ZkTlsError::DataTooLarge;
        assert_eq!(error.to_string(), "Data exceeds maximum size");
        
        let crypto_error = ZkTlsError::CryptoError(CryptoError::InvalidKeySize);
        assert!(crypto_error.to_string().contains("Invalid key size"));
    }
    
    #[test]
    fn test_error_conversion() {
        let crypto_error = CryptoError::InvalidSignature;
        let zktls_error: ZkTlsError = crypto_error.into();
        
        match zktls_error {
            ZkTlsError::CryptoError(CryptoError::InvalidSignature) => {},
            _ => panic!("Conversion failed"),
        }
    }
}