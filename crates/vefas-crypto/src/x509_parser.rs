//! X.509 Certificate Parsing Utilities
//!
//! This module provides platform-agnostic X.509 DER certificate parsing
//! using the x509-parser crate from the Rusticata project.
//!
//! ## Architecture
//!
//! This module contains **parsing only** - no cryptographic verification.
//! Verification (signature checking, chain validation) should be done by
//! platform-specific crypto providers (vefas-crypto-{native,risc0,sp1}).
//!
//! ## Usage
//!
//! ```ignore
//! use vefas_crypto::x509_parser::*;
//!
//! let cert_info = parse_certificate_der(cert_bytes)?;
//! println!("Server: {}", cert_info.server_name);
//! println!("Algorithm: {:?}", cert_info.signature_algorithm);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{vec::Vec, string::{String, ToString}, format};
use x509_parser::prelude::*;
use x509_parser::oid_registry::Oid;
use vefas_types::{VefasError, VefasResult};

// Re-export x509-parser types for use in guest programs
pub use x509_parser::certificate::X509Certificate;
pub use x509_parser::oid_registry::Oid as X509Oid;
pub use x509_parser::prelude::{FromDer, ParsedExtension, GeneralName};

/// Signature algorithm used in X.509 certificates and TLS CertificateVerify
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509SignatureAlgorithm {
    /// RSA PKCS#1 v1.5 with SHA-256
    RsaPkcs1Sha256,
    /// RSA PSS with SHA-256
    RsaPssSha256,
    /// ECDSA with P-256 curve and SHA-256
    EcdsaP256Sha256,
    /// ECDSA with P-384 curve and SHA-384
    EcdsaP384Sha384,
}

impl X509SignatureAlgorithm {
    /// Parse from TLS SignatureScheme value (RFC 8446)
    pub fn from_tls_signature_scheme(scheme: u16) -> VefasResult<Self> {
        match scheme {
            0x0401 => Ok(X509SignatureAlgorithm::RsaPkcs1Sha256),
            0x0804 => Ok(X509SignatureAlgorithm::RsaPssSha256),
            0x0403 => Ok(X509SignatureAlgorithm::EcdsaP256Sha256),
            0x0503 => Ok(X509SignatureAlgorithm::EcdsaP384Sha384),
            _ => Err(VefasError::invalid_input(
                "signature_algorithm",
                &format!("Unsupported TLS signature scheme: 0x{:04x}", scheme),
            )),
        }
    }

    /// Convert to TLS SignatureScheme value (RFC 8446)
    pub fn to_tls_signature_scheme(self) -> u16 {
        match self {
            X509SignatureAlgorithm::RsaPkcs1Sha256 => 0x0401,
            X509SignatureAlgorithm::RsaPssSha256 => 0x0804,
            X509SignatureAlgorithm::EcdsaP256Sha256 => 0x0403,
            X509SignatureAlgorithm::EcdsaP384Sha384 => 0x0503,
        }
    }
}

/// Parsed X.509 certificate information
#[derive(Debug, Clone)]
pub struct X509CertificateInfo {
    /// Server identity from Subject CN or Subject Alternative Name
    pub server_name: String,
    /// Public key bytes (format depends on algorithm)
    pub public_key: Vec<u8>,
    /// Signature algorithm used in the certificate
    pub signature_algorithm: X509SignatureAlgorithm,
    /// Raw DER-encoded certificate
    pub raw_der: Vec<u8>,
}

/// Parse X.509 certificate from DER format
///
/// Extracts essential information for TLS verification:
/// - Server identity (CN or SAN DNS name)
/// - Public key
/// - Signature algorithm
///
/// This function only **parses** the certificate. Cryptographic verification
/// (signature checking, chain validation) must be done separately using
/// platform-specific crypto providers.
pub fn parse_certificate_der(cert_der: &[u8]) -> VefasResult<X509CertificateInfo> {
    // Parse X.509 certificate using x509-parser
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| VefasError::invalid_input("certificate", &format!("X.509 parsing failed: {}", e)))?;
    
    // Extract public key from SubjectPublicKeyInfo
    let public_key = cert.public_key().subject_public_key.data.to_vec();
    
    // Map signature algorithm OID to our enum
    let signature_algorithm = map_signature_algorithm_from_oid(&cert.signature_algorithm.algorithm)?;
    
    // Extract server name from Subject CN or SAN
    let server_name = extract_server_name(&cert)?;
    
    Ok(X509CertificateInfo {
        server_name,
        public_key,
        signature_algorithm,
        raw_der: cert_der.to_vec(),
    })
}

/// Extract server name from X.509 certificate
///
/// Priority order:
/// 1. Subject Alternative Name (SAN) DNS name extension (most common for TLS)
/// 2. Subject Common Name (CN) - fallback for older certificates
pub fn extract_server_name<'a>(cert: &X509Certificate<'a>) -> VefasResult<String> {
    // Try to extract from Subject Alternative Name (SAN) extension first
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for general_name in &san_ext.value.general_names {
            if let GeneralName::DNSName(dns_name) = general_name {
                return Ok(dns_name.to_string());
            }
        }
    }
    
    // Fallback to Common Name (CN) in Subject
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            // OID for Common Name: 2.5.4.3
            if attr.attr_type().to_string() == "2.5.4.3" {
                if let Ok(cn) = attr.as_str() {
                    return Ok(cn.to_string());
                }
            }
        }
    }
    
    Err(VefasError::invalid_input(
        "certificate",
        "No DNS name in SAN and no CN in Subject",
    ))
}

/// Map X.509 signature algorithm OID to SignatureAlgorithm enum
///
/// Common OIDs from RFC 5480 (ECDSA) and RFC 8017 (RSA):
/// - RSA PKCS#1 v1.5 SHA-256: 1.2.840.113549.1.1.11
/// - RSA PSS: 1.2.840.113549.1.1.10
/// - ECDSA SHA-256: 1.2.840.10045.4.3.2
/// - ECDSA SHA-384: 1.2.840.10045.4.3.3
pub fn map_signature_algorithm_from_oid<'a>(oid: &Oid<'a>) -> VefasResult<X509SignatureAlgorithm> {
    match oid.to_string().as_str() {
        // RSA PKCS#1 v1.5 with SHA-256
        "1.2.840.113549.1.1.11" => Ok(X509SignatureAlgorithm::RsaPkcs1Sha256),
        
        // RSA PSS
        "1.2.840.113549.1.1.10" => Ok(X509SignatureAlgorithm::RsaPssSha256),
        
        // ECDSA with SHA-256
        "1.2.840.10045.4.3.2" => Ok(X509SignatureAlgorithm::EcdsaP256Sha256),
        
        // ECDSA with SHA-384
        "1.2.840.10045.4.3.3" => Ok(X509SignatureAlgorithm::EcdsaP384Sha384),
        
        _ => Err(VefasError::invalid_input(
            "signature_algorithm",
            &format!("Unsupported signature algorithm OID: {}", oid),
        )),
    }
}

/// Check if a domain matches a certificate's server name
///
/// Supports:
/// - Exact match: "example.com" matches "example.com"
/// - Wildcard match: "*.example.com" matches "www.example.com"
pub fn domain_matches_cert(domain: &str, cert_server_name: &str) -> bool {
    // Exact match
    if domain == cert_server_name {
        return true;
    }
    
    // Wildcard match (e.g., *.example.com)
    if cert_server_name.starts_with("*.") {
        let cert_base = &cert_server_name[2..]; // Remove "*."
        if let Some(domain_base) = domain.split_once('.') {
            return domain_base.1 == cert_base;
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_exact_match() {
        assert!(domain_matches_cert("example.com", "example.com"));
        assert!(!domain_matches_cert("example.com", "other.com"));
    }

    #[test]
    fn test_domain_wildcard_match() {
        assert!(domain_matches_cert("www.example.com", "*.example.com"));
        assert!(domain_matches_cert("api.example.com", "*.example.com"));
        assert!(!domain_matches_cert("example.com", "*.example.com")); // No subdomain
        assert!(!domain_matches_cert("www.other.com", "*.example.com"));
    }

    #[test]
    fn test_signature_algorithm_conversion() {
        let alg = X509SignatureAlgorithm::EcdsaP256Sha256;
        assert_eq!(alg.to_tls_signature_scheme(), 0x0403);
        assert_eq!(
            X509SignatureAlgorithm::from_tls_signature_scheme(0x0403).unwrap(),
            alg
        );
    }
}

