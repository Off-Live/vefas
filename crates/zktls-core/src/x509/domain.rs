//! Domain name validation for X.509 certificates
//!
//! This module implements server identity verification according to RFC 6125.
//! It validates that a given domain name matches the identities present in a
//! certificate's Subject Alternative Name (SAN) extension or Common Name (CN).
//!
//! # Security Implementation
//! - SAN extension takes precedence over CN (RFC 6125 Section 6.4.4)
//! - Wildcard matching follows strict constraints (RFC 6125 Section 6.4.3)
//! - Case-insensitive DNS name matching (RFC 1035)
//! - Prevents wildcard bypass attacks
//!
//! # Supported Features
//! - Exact domain name matching
//! - Single-label wildcard matching (*.example.com)
//! - SAN vs CN precedence handling
//! - Input validation and security checks
//!
//! # Limitations (MVP)
//! - No International Domain Name (IDN) support
//! - No public suffix list validation
//! - ASCII-only domain names

extern crate alloc;
use alloc::{string::{String, ToString}, vec::Vec};
use super::{X509Certificate, X509Error, ExtensionType, GeneralName};

/// Domain validation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainValidationResult {
    /// Exact domain name match (api.example.com matches api.example.com)
    ExactMatch,
    
    /// Wildcard certificate match (*.example.com matches api.example.com)
    WildcardMatch,
}

/// Domain validation error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainValidationError {
    /// No matching identity found in certificate
    NoMatch,
    
    /// Invalid domain name format
    InvalidDomain(String),
    
    /// Wildcard constraint violation (*.example.com cannot match sub.api.example.com)
    WildcardConstraintViolation,
    
    /// Wildcard cannot match apex domain (*.example.com cannot match example.com)
    WildcardApexMismatch,
    
    /// Certificate parsing error
    CertificateError(X509Error),
    
    /// IP address provided where domain name expected
    IpAddressNotSupported,
}

/// Validate that a domain name matches the certificate's identity
/// 
/// Implements RFC 6125 server identity verification:
/// 1. Extract identities from certificate (SAN DNS names, then CN if no SAN)
/// 2. Perform case-insensitive matching
/// 3. Handle wildcard certificates with proper security constraints
/// 
/// # Arguments
/// * `certificate` - The X.509 certificate to validate against
/// * `domain` - The domain name to validate
/// 
/// # Returns
/// * `Ok(DomainValidationResult)` - Validation succeeded with match type
/// * `Err(DomainValidationError)` - Validation failed
/// 
/// # Example
/// ```rust
/// use zktls_core::x509::{X509Certificate, domain_validation::validate_domain};
/// 
/// let cert = X509Certificate::parse(cert_der)?;
/// let result = validate_domain(&cert, "api.example.com")?;
/// ```
pub fn validate_domain(
    certificate: &X509Certificate,
    domain: &str,
) -> Result<DomainValidationResult, DomainValidationError> {
    // Step 1: Validate input domain format
    validate_domain_format(domain)?;
    
    // Step 2: Extract certificate identities following RFC 6125 precedence
    let identities = extract_certificate_identities(certificate)?;
    
    // Step 3: Perform domain matching
    match_domain_against_identities(domain, &identities)
}

/// Certificate identity sources
#[derive(Debug, Clone)]
enum CertificateIdentity {
    /// DNS name from Subject Alternative Name
    SanDnsName(String),
    
    /// Common Name from Subject DN (only used if no SAN present)
    CommonName(String),
}

/// Validate domain name format
fn validate_domain_format(domain: &str) -> Result<(), DomainValidationError> {
    if domain.is_empty() {
        return Err(DomainValidationError::InvalidDomain("Empty domain".into()));
    }
    
    // Check for IP addresses (basic detection)
    if is_ip_address(domain) {
        return Err(DomainValidationError::IpAddressNotSupported);
    }
    
    // Check for invalid characters and format
    if domain.contains(' ') || domain.contains('\n') || domain.contains('\t') {
        return Err(DomainValidationError::InvalidDomain(
            "Domain contains invalid characters".into()
        ));
    }
    
    // Check for malformed dots
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err(DomainValidationError::InvalidDomain(
            "Domain has malformed dot notation".into()
        ));
    }
    
    Ok(())
}

/// Basic IP address detection
fn is_ip_address(domain: &str) -> bool {
    // IPv4 simple check (contains only digits and dots)
    if domain.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() == 4 {
            return parts.iter().all(|part| {
                part.parse::<u8>().is_ok() && !part.is_empty()
            });
        }
    }
    
    // IPv6 simple check (contains colons)
    if domain.contains(':') {
        return true;
    }
    
    false
}

/// Extract certificate identities following RFC 6125 precedence rules
fn extract_certificate_identities(
    certificate: &X509Certificate,
) -> Result<Vec<CertificateIdentity>, DomainValidationError> {
    let mut identities = Vec::new();
    
    // Step 1: Check for Subject Alternative Name extension (takes precedence)
    let has_san_dns = extract_san_dns_names(certificate, &mut identities)?;
    
    // Step 2: If no SAN DNS names, fall back to Common Name
    if !has_san_dns {
        extract_common_name(certificate, &mut identities)?;
    }
    
    Ok(identities)
}

/// Extract DNS names from Subject Alternative Name extension
fn extract_san_dns_names(
    certificate: &X509Certificate,
    identities: &mut Vec<CertificateIdentity>,
) -> Result<bool, DomainValidationError> {
    let extensions = certificate.extensions();
    
    for extension in extensions {
        if let ExtensionType::SubjectAltName(san) = extension.extension_type() {
            for name in san.names() {
                if let GeneralName::DnsName(dns_name) = name {
                    identities.push(CertificateIdentity::SanDnsName(dns_name.to_string()));
                }
            }
            return Ok(!identities.is_empty());
        }
    }
    
    Ok(false)
}

/// Extract Common Name from Subject Distinguished Name
fn extract_common_name(
    certificate: &X509Certificate,
    identities: &mut Vec<CertificateIdentity>,
) -> Result<(), DomainValidationError> {
    let subject = certificate.subject();
    
    if let Some(cn) = subject.common_name() {
        identities.push(CertificateIdentity::CommonName(cn.to_string()));
    }
    
    Ok(())
}

/// Match domain against certificate identities
fn match_domain_against_identities(
    domain: &str,
    identities: &[CertificateIdentity],
) -> Result<DomainValidationResult, DomainValidationError> {
    let domain_lower = domain.to_lowercase();
    
    for identity in identities {
        let identity_name = match identity {
            CertificateIdentity::SanDnsName(name) => name,
            CertificateIdentity::CommonName(name) => name,
        };
        
        let identity_lower = identity_name.to_lowercase();
        
        // Try exact match first
        if domain_lower == identity_lower {
            return Ok(DomainValidationResult::ExactMatch);
        }
        
        // Try wildcard match
        if let Ok(result) = match_wildcard(&domain_lower, &identity_lower) {
            return Ok(result);
        }
    }
    
    Err(DomainValidationError::NoMatch)
}

/// Match domain against wildcard certificate identity
fn match_wildcard(
    domain: &str,
    wildcard_identity: &str,
) -> Result<DomainValidationResult, DomainValidationError> {
    // Check if identity is a wildcard (starts with "*.")
    if !wildcard_identity.starts_with("*.") {
        return Err(DomainValidationError::NoMatch);
    }
    
    let wildcard_base = &wildcard_identity[2..]; // Remove "*."
    
    // Wildcard cannot match apex domain
    // *.example.com should not match example.com
    if domain == wildcard_base {
        return Err(DomainValidationError::WildcardApexMismatch);
    }
    
    // Check if domain ends with the wildcard base
    if domain.ends_with(wildcard_base) {
        // Ensure domain has exactly one more label than wildcard base
        let domain_prefix = &domain[..domain.len() - wildcard_base.len()];
        
        // Must end with dot and contain no additional dots (single label constraint)
        if domain_prefix.ends_with('.') && !domain_prefix[..domain_prefix.len() - 1].contains('.') {
            return Ok(DomainValidationResult::WildcardMatch);
        }
        
        return Err(DomainValidationError::WildcardConstraintViolation);
    }
    
    Err(DomainValidationError::NoMatch)
}

impl From<X509Error> for DomainValidationError {
    fn from(error: X509Error) -> Self {
        DomainValidationError::CertificateError(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_domain_format_valid() {
        assert!(validate_domain_format("example.com").is_ok());
        assert!(validate_domain_format("api.example.com").is_ok());
        assert!(validate_domain_format("sub.domain.example.com").is_ok());
    }

    #[test]
    fn test_validate_domain_format_invalid() {
        assert!(validate_domain_format("").is_err());
        assert!(validate_domain_format(".example.com").is_err());
        assert!(validate_domain_format("example.com.").is_err());
        assert!(validate_domain_format("exam..ple.com").is_err());
        assert!(validate_domain_format("exam ple.com").is_err());
    }

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("::1"));
        assert!(is_ip_address("2001:db8::1"));
        assert!(!is_ip_address("example.com"));
        assert!(!is_ip_address("192.168.1.256")); // Invalid IPv4
    }

    #[test]
    fn test_match_wildcard_valid() {
        assert_eq!(
            match_wildcard("api.example.com", "*.example.com").unwrap(),
            DomainValidationResult::WildcardMatch
        );
    }

    #[test]
    fn test_match_wildcard_invalid() {
        // Apex domain should not match
        assert!(match_wildcard("example.com", "*.example.com").is_err());
        
        // Multi-label should not match  
        assert!(match_wildcard("sub.api.example.com", "*.example.com").is_err());
        
        // Non-wildcard should not match
        assert!(match_wildcard("api.example.com", "different.com").is_err());
    }
}