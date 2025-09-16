//! X.509 certificate parsing errors
//!
//! This module defines error types specific to X.509 certificate parsing
//! and validation, building upon the ASN.1 parsing errors.

extern crate alloc;
use alloc::string::String;
use core::fmt;
use crate::asn1::Asn1Error;

/// Result type for X.509 operations
pub type X509Result<T> = core::result::Result<T, X509Error>;

/// Result type for certificate chain validation operations
pub type ValidationResult<T> = core::result::Result<T, ValidationError>;

/// X.509 certificate parsing and validation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X509Error {
    /// ASN.1 parsing error
    Asn1(Asn1Error),
    
    /// Invalid certificate structure
    InvalidCertificateStructure,
    
    /// Unsupported certificate version
    UnsupportedVersion(u8),
    
    /// Invalid or missing required field
    MissingRequiredField(&'static str),
    
    /// Invalid Distinguished Name structure
    InvalidDistinguishedName,
    
    /// Unsupported public key algorithm
    UnsupportedPublicKeyAlgorithm(alloc::string::String),
    
    /// Invalid public key data
    InvalidPublicKey,
    
    /// Invalid validity period
    InvalidValidity,
    
    /// Invalid extension structure
    InvalidExtension,
    
    /// Unsupported critical extension
    UnsupportedCriticalExtension(alloc::string::String),
    
    /// Invalid signature algorithm
    InvalidSignatureAlgorithm,
    
    /// Certificate validation failed
    ValidationFailed(&'static str),
}

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            X509Error::Asn1(e) => write!(f, "ASN.1 parsing error: {}", e),
            X509Error::InvalidCertificateStructure => write!(f, "Invalid certificate structure"),
            X509Error::UnsupportedVersion(v) => write!(f, "Unsupported certificate version: {}", v),
            X509Error::MissingRequiredField(field) => write!(f, "Missing required field: {}", field),
            X509Error::InvalidDistinguishedName => write!(f, "Invalid Distinguished Name"),
            X509Error::UnsupportedPublicKeyAlgorithm(alg) => write!(f, "Unsupported public key algorithm: {}", alg),
            X509Error::InvalidPublicKey => write!(f, "Invalid public key data"),
            X509Error::InvalidValidity => write!(f, "Invalid validity period"),
            X509Error::InvalidExtension => write!(f, "Invalid extension"),
            X509Error::UnsupportedCriticalExtension(oid) => write!(f, "Unsupported critical extension: {}", oid),
            X509Error::InvalidSignatureAlgorithm => write!(f, "Invalid signature algorithm"),
            X509Error::ValidationFailed(reason) => write!(f, "Certificate validation failed: {}", reason),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for X509Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            X509Error::Asn1(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Asn1Error> for X509Error {
    fn from(e: Asn1Error) -> Self {
        X509Error::Asn1(e)
    }
}

/// Certificate chain validation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Failed to parse certificate
    CertificateParsingError(X509Error),
    
    /// Missing intermediate certificate in the chain
    MissingIntermediateCertificate(String),
    
    /// Circular reference detected in certificate chain
    CircularChainReference,
    
    /// Invalid signature on certificate
    InvalidSignature(String),
    
    /// Certificate is expired
    CertificateExpired(String),
    
    /// Certificate is not yet valid
    CertificateNotYetValid(String),
    
    /// Chain does not terminate at a trusted root
    UntrustedChain,
    
    /// Invalid certificate structure or content
    InvalidCertificate(String),
    
    /// Key usage constraint violation
    KeyUsageViolation(String),
    
    /// Extended key usage constraint violation
    ExtendedKeyUsageViolation(String),
    
    /// Name constraint violation
    NameConstraintViolation(String),
    
    /// Path length constraint violation
    PathLengthConstraintViolation(String),
    
    /// Cryptographic operation failed
    CryptographicError(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::CertificateParsingError(e) => write!(f, "Certificate parsing error: {}", e),
            ValidationError::MissingIntermediateCertificate(issuer) => write!(f, "Missing intermediate certificate for issuer: {}", issuer),
            ValidationError::CircularChainReference => write!(f, "Circular reference detected in certificate chain"),
            ValidationError::InvalidSignature(cert) => write!(f, "Invalid signature on certificate: {}", cert),
            ValidationError::CertificateExpired(cert) => write!(f, "Certificate expired: {}", cert),
            ValidationError::CertificateNotYetValid(cert) => write!(f, "Certificate not yet valid: {}", cert),
            ValidationError::UntrustedChain => write!(f, "Certificate chain does not terminate at a trusted root"),
            ValidationError::InvalidCertificate(msg) => write!(f, "Invalid certificate: {}", msg),
            ValidationError::KeyUsageViolation(msg) => write!(f, "Key usage constraint violation: {}", msg),
            ValidationError::ExtendedKeyUsageViolation(msg) => write!(f, "Extended key usage constraint violation: {}", msg),
            ValidationError::NameConstraintViolation(msg) => write!(f, "Name constraint violation: {}", msg),
            ValidationError::PathLengthConstraintViolation(msg) => write!(f, "Path length constraint violation: {}", msg),
            ValidationError::CryptographicError(msg) => write!(f, "Cryptographic operation failed: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ValidationError::CertificateParsingError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<X509Error> for ValidationError {
    fn from(e: X509Error) -> Self {
        ValidationError::CertificateParsingError(e)
    }
}