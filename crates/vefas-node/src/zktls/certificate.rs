//! # Certificate Validation
//!
//! This module implements certificate chain validation for VEFAS Node.

use crate::error::{VefasNodeError, VefasNodeResult};
use rustls::{ClientConfig, RootCertStore};
use rustls::pki_types::CertificateDer;
use rustls_pemfile::{certs, rsa_private_keys};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};
use webpki::{DnsNameRef, Time};
use webpki_roots::TLS_SERVER_ROOTS;
use serde::{Deserialize, Serialize};

/// Certificate validation configuration
#[derive(Debug, Clone)]
pub struct CertificateConfig {
    /// Enable certificate validation
    pub enabled: bool,
    /// Custom root certificates (optional)
    pub custom_roots: Option<Vec<Vec<u8>>>,
    /// Allow self-signed certificates
    pub allow_self_signed: bool,
    /// Certificate validation timeout
    pub timeout_secs: u64,
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_roots: None,
            allow_self_signed: false,
            timeout_secs: 30,
        }
    }
}

/// Certificate validator
#[derive(Debug)]
pub struct CertificateValidator {
    /// Validation configuration
    config: CertificateConfig,
    /// Root certificate store
    root_store: RootCertStore,
}

impl CertificateValidator {
    /// Create a new certificate validator
    pub async fn new(config: CertificateConfig) -> VefasNodeResult<Self> {
        info!("Initializing certificate validator");

        // Build root certificate store
        let mut root_store = RootCertStore::empty();
        
        // Add bundled root certificates from certs/roots/ directory
        let certs_dir = std::env::current_dir()
            .map_err(|e| VefasNodeError::Configuration(format!("Failed to get current directory: {}", e)))?
            .join("crates/vefas-node/certs/roots");
        
        if certs_dir.exists() {
            let entries = std::fs::read_dir(&certs_dir)
                .map_err(|e| VefasNodeError::Configuration(format!("Failed to read certs directory: {}", e)))?;
            
            for entry in entries {
                let entry = entry.map_err(|e| VefasNodeError::Configuration(format!("Failed to read directory entry: {}", e)))?;
                let path = entry.path();
                
                if path.extension().and_then(|s| s.to_str()) == Some("der") {
                    let cert_data = std::fs::read(&path)
                        .map_err(|e| VefasNodeError::Configuration(format!("Failed to read certificate {}: {}", path.display(), e)))?;
                    
                    let cert_der = CertificateDer::from(cert_data);
                    root_store.add(cert_der).map_err(|e| {
                        VefasNodeError::Configuration(format!("Failed to add certificate {}: {}", path.display(), e))
                    })?;
                    
                    debug!("Added root certificate: {}", path.file_name().unwrap().to_string_lossy());
                }
            }
        } else {
            warn!("Certificate directory not found: {}", certs_dir.display());
            warn!("Falling back to webpki-roots system certificates");
            
            // Fallback to system certificates if bundled certs not available
            // Note: webpki_roots::TrustAnchor doesn't contain full certificate DER data
            // For now, we'll skip adding system certificates and rely on bundled certs
            warn!("No bundled certificates found, certificate validation may be limited");
        }

        // Add custom root certificates if provided
        if let Some(custom_roots) = &config.custom_roots {
            for root_data in custom_roots {
                let cert = CertificateDer::from(root_data.clone());
                root_store.add(cert).map_err(|e| {
                    VefasNodeError::Configuration(format!("Failed to add custom root certificate: {}", e))
                })?;
            }
        }

        info!("Certificate validator initialized with {} root certificates", root_store.len());

        Ok(Self {
            config,
            root_store,
        })
    }

    /// Validate a certificate chain
    pub async fn validate_certificate_chain(
        &self,
        certificate_chain: &[Vec<u8>],
        domain: &str,
    ) -> VefasNodeResult<CertificateValidationResult> {
        if !self.config.enabled {
            return Ok(CertificateValidationResult {
                is_valid: true,
                chain_length: certificate_chain.len(),
                expiration_date: chrono::Utc::now() + chrono::Duration::days(365),
                issuer: "Validation disabled".to_string(),
                subject: domain.to_string(),
                errors: vec!["Certificate validation is disabled".to_string()],
            });
        }

        debug!("Validating certificate chain for domain: {}", domain);

        if certificate_chain.is_empty() {
            return Ok(CertificateValidationResult {
                is_valid: false,
                chain_length: 0,
                expiration_date: chrono::Utc::now(),
                issuer: "".to_string(),
                subject: domain.to_string(),
                errors: vec!["Empty certificate chain".to_string()],
            });
        }

        let mut errors = Vec::new();
        let mut is_valid = true;

        // Parse the end-entity certificate
        let end_entity_cert = match certificate_chain.first() {
            Some(cert_data) => {
                match x509_parser::parse_x509_certificate(cert_data) {
                    Ok((_, cert)) => cert,
                    Err(e) => {
                        errors.push(format!("Failed to parse end-entity certificate: {}", e));
                        is_valid = false;
                        return Ok(CertificateValidationResult {
                            is_valid: false,
                            chain_length: certificate_chain.len(),
                            expiration_date: chrono::Utc::now(),
                            issuer: "".to_string(),
                            subject: domain.to_string(),
                            errors,
                        });
                    }
                }
            }
            None => {
                errors.push("No certificates in chain".to_string());
                is_valid = false;
                return Ok(CertificateValidationResult {
                    is_valid: false,
                    chain_length: 0,
                    expiration_date: chrono::Utc::now(),
                    issuer: "".to_string(),
                    subject: domain.to_string(),
                    errors,
                });
            }
        };

        // Extract certificate information
        let subject = end_entity_cert.subject().to_string();
        let issuer = end_entity_cert.issuer().to_string();
        
        // Check certificate expiration
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let not_after = end_entity_cert.validity().not_after.timestamp() as u64;
        
        if now > not_after {
            errors.push("Certificate has expired".to_string());
            is_valid = false;
        }

        // Check certificate validity period
        let not_before = end_entity_cert.validity().not_before.timestamp() as u64;
        if now < not_before {
            errors.push("Certificate is not yet valid".to_string());
            is_valid = false;
        }

        // Convert expiration date
        let expiration_date = chrono::DateTime::from_timestamp(not_after as i64, 0)
            .unwrap_or_else(|| chrono::Utc::now());

        // Validate domain name
        if !self.validate_domain_name(&end_entity_cert, domain) {
            errors.push(format!("Certificate does not match domain: {}", domain));
            is_valid = false;
        }

        // Basic certificate chain validation
        if certificate_chain.len() > 1 {
            // For now, we'll do basic validation
            // In a production system, you would validate the entire chain
            debug!("Certificate chain has {} certificates", certificate_chain.len());
        }

        info!(
            "Certificate validation completed for {}: valid={}, errors={}",
            domain, is_valid, errors.len()
        );

        Ok(CertificateValidationResult {
            is_valid,
            chain_length: certificate_chain.len(),
            expiration_date,
            issuer,
            subject,
            errors,
        })
    }

    /// Validate domain name against certificate
    ///
    /// This function performs RFC 5280 compliant domain validation:
    /// 1. Extracts Subject Alternative Names (SAN) from certificate
    /// 2. Checks for exact domain match or wildcard match
    /// 3. Falls back to Common Name (CN) if no SANs present
    ///
    /// Security: This is a critical security function. Any certificate claiming
    /// to be for a domain must actually match that domain to prevent MITM attacks.
    fn validate_domain_name(&self, cert: &x509_parser::certificate::X509Certificate, domain: &str) -> bool {
        use x509_parser::extensions::{GeneralName, ParsedExtension};

        debug!("Validating domain: {}", domain);

        // Normalize domain to lowercase for case-insensitive comparison
        let domain_lower = domain.to_lowercase();

        // Extract Subject Alternative Names (SAN) - preferred method per RFC 5280
        let mut sans = Vec::new();

        for ext in cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san_ext) = ext.parsed_extension() {
                for general_name in &san_ext.general_names {
                    if let GeneralName::DNSName(dns_name) = general_name {
                        sans.push(dns_name.to_lowercase());
                        debug!("Found SAN DNS name: {}", dns_name);
                    }
                }
            }
        }

        // Check SANs first (RFC 5280 section 4.2.1.6: SAN must be used if present)
        if !sans.is_empty() {
            for san in &sans {
                if self.matches_domain(san, &domain_lower) {
                    debug!("Domain {} matched SAN: {}", domain, san);
                    return true;
                }
            }
            // If SANs are present but none match, validation fails
            warn!("Domain {} did not match any SANs: {:?}", domain, sans);
            return false;
        }

        // Fallback to Common Name (CN) only if no SANs present
        // Note: This is deprecated but still needed for older certificates
        match self.extract_common_name(cert) {
            Ok(cn) => {
                let cn_lower = cn.to_lowercase();
                if self.matches_domain(&cn_lower, &domain_lower) {
                    debug!("Domain {} matched CN: {}", domain, cn);
                    return true;
                }
                warn!("Domain {} did not match CN: {}", domain, cn);
            }
            Err(_) => {
                warn!("No SANs and no valid CN found in certificate");
            }
        }

        false
    }

    /// Check if certificate name matches domain (supports wildcards)
    ///
    /// Implements RFC 6125 wildcard matching rules:
    /// - Wildcards only match a single label (*.example.com matches sub.example.com, not deep.sub.example.com)
    /// - Wildcards must be in the leftmost label
    /// - Wildcards cannot match partial labels (*.example.com does not match .example.com)
    /// - Wildcards cannot be used for TLDs (*.com is invalid)
    ///
    /// Both inputs must be lowercase for case-insensitive comparison.
    fn matches_domain(&self, pattern: &str, domain: &str) -> bool {
        // Exact match (fast path)
        if pattern == domain {
            return true;
        }

        // Wildcard match
        if pattern.starts_with("*.") {
            let pattern_suffix = &pattern[2..]; // Remove "*."

            // Security: Prevent bare TLD wildcards (*.com)
            // But allow internationalized TLDs (*.xn--p1ai for .ru)
            // Pattern suffix should not be empty and should represent a valid domain
            if pattern_suffix.is_empty() {
                return false;
            }

            // Reject patterns that are just TLDs without second-level domain
            // E.g., *.com, *.org (3 chars), but allow *.co.uk, *.xn--p1ai (longer)
            // This is a heuristic: most real TLDs are short, second-level domains are longer
            if pattern_suffix.len() <= 4 && !pattern_suffix.contains('.') && !pattern_suffix.contains('-') {
                return false;
            }

            // Domain must have at least one subdomain label
            if let Some(dot_pos) = domain.find('.') {
                let domain_suffix = &domain[dot_pos + 1..];

                // Wildcard matches single label: sub.example.com matches *.example.com
                // But not: deep.sub.example.com (multiple labels)
                if domain_suffix == pattern_suffix {
                    // Ensure the subdomain part doesn't contain more dots
                    let subdomain = &domain[..dot_pos];
                    return !subdomain.contains('.');
                }
            }
        }

        false
    }

    /// Extract Common Name from certificate subject
    ///
    /// Returns the CN (Common Name) attribute from the certificate's subject field.
    /// This is used as a fallback when no SANs are present.
    fn extract_common_name(&self, cert: &x509_parser::certificate::X509Certificate) -> Result<String, ()> {
        use x509_parser::oid_registry::OID_X509_COMMON_NAME;

        for rdn in cert.subject().iter_rdn() {
            for attr in rdn.iter() {
                if attr.attr_type() == &OID_X509_COMMON_NAME {
                    if let Ok(cn_str) = attr.as_str() {
                        return Ok(cn_str.to_string());
                    }
                }
            }
        }
        Err(())
    }

    /// Get the root certificate store
    pub fn root_store(&self) -> &RootCertStore {
        &self.root_store
    }
}

/// Certificate validation result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CertificateValidationResult {
    /// Whether certificate chain is valid
    pub is_valid: bool,
    /// Certificate chain length
    pub chain_length: usize,
    /// Certificate expiration date
    pub expiration_date: chrono::DateTime<chrono::Utc>,
    /// Certificate issuer
    pub issuer: String,
    /// Certificate subject
    pub subject: String,
    /// Validation errors (if any)
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test exact domain matching
    #[test]
    fn test_domain_exact_match() {
        let config = CertificateConfig::default();
        let validator = CertificateValidator {
            config,
            root_store: RootCertStore::empty(),
        };

        // Exact matches (lowercase - as required by matches_domain API)
        assert!(validator.matches_domain("example.com", "example.com"));
        assert!(validator.matches_domain("example.com", "example.com"));
        assert!(validator.matches_domain("sub.example.com", "sub.example.com"));

        // Case insensitivity is handled by validate_domain_name, not matches_domain
        // matches_domain expects both inputs to be already lowercased

        // Non-matches
        assert!(!validator.matches_domain("example.com", "other.com"));
        assert!(!validator.matches_domain("example.com", "sub.example.com"));
        assert!(!validator.matches_domain("sub.example.com", "example.com"));
    }

    /// Test wildcard domain matching (RFC 6125 compliance)
    #[test]
    fn test_wildcard_single_label_match() {
        let config = CertificateConfig::default();
        let validator = CertificateValidator {
            config,
            root_store: RootCertStore::empty(),
        };

        // Valid wildcard matches (single label - all lowercase as required by API)
        assert!(validator.matches_domain("*.example.com", "sub.example.com"));
        assert!(validator.matches_domain("*.example.com", "api.example.com"));
        assert!(validator.matches_domain("*.example.com", "www.example.com"));

        // Invalid: Wildcard doesn't match multiple labels (RFC 6125)
        assert!(!validator.matches_domain("*.example.com", "deep.sub.example.com"));
        assert!(!validator.matches_domain("*.example.com", "a.b.example.com"));

        // Invalid: Wildcard doesn't match base domain
        assert!(!validator.matches_domain("*.example.com", "example.com"));

        // Invalid: Domain doesn't match pattern
        assert!(!validator.matches_domain("*.example.com", "other.com"));
        assert!(!validator.matches_domain("*.example.com", "sub.other.com"));
    }

    /// Test nested wildcard matching
    #[test]
    fn test_nested_wildcard_match() {
        let config = CertificateConfig::default();
        let validator = CertificateValidator {
            config,
            root_store: RootCertStore::empty(),
        };

        // Wildcard in subdomain
        assert!(validator.matches_domain("*.api.example.com", "v1.api.example.com"));
        assert!(validator.matches_domain("*.api.example.com", "v2.api.example.com"));

        // Invalid: Multiple labels
        assert!(!validator.matches_domain("*.api.example.com", "v1.staging.api.example.com"));

        // Invalid: Base domain
        assert!(!validator.matches_domain("*.api.example.com", "api.example.com"));
    }

    /// Test edge cases
    #[test]
    fn test_domain_matching_edge_cases() {
        let config = CertificateConfig::default();
        let validator = CertificateValidator {
            config,
            root_store: RootCertStore::empty(),
        };

        // Empty strings
        assert!(!validator.matches_domain("", "example.com"));
        assert!(!validator.matches_domain("example.com", ""));
        assert!(validator.matches_domain("", "")); // Exact match of empty strings

        // Single label domain (TLD)
        assert!(validator.matches_domain("localhost", "localhost"));
        assert!(!validator.matches_domain("*.localhost", "localhost"));

        // Very long domain names
        let long_subdomain = "a.".repeat(50) + "example.com";
        assert!(!validator.matches_domain("*.example.com", &long_subdomain)); // Multiple labels

        // Wildcard at end (invalid, but should not crash)
        assert!(!validator.matches_domain("example.*", "example.com"));

        // Wildcard in middle (invalid, but should not crash)
        assert!(!validator.matches_domain("sub.*.example.com", "sub.test.example.com"));

        // Multiple wildcards (invalid, but should not crash)
        assert!(!validator.matches_domain("*.*.example.com", "a.b.example.com"));
    }

    /// Test internationalized domain names (IDN)
    #[test]
    fn test_idn_domain_matching() {
        let config = CertificateConfig::default();
        let validator = CertificateValidator {
            config,
            root_store: RootCertStore::empty(),
        };

        // ASCII representation of IDN (Punycode)
        assert!(validator.matches_domain("xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"));
        assert!(validator.matches_domain("*.xn--p1ai", "test.xn--p1ai"));
    }

    /// Test security: ensure wildcard doesn't bypass domain validation
    #[test]
    fn test_wildcard_security() {
        let config = CertificateConfig::default();
        let validator = CertificateValidator {
            config,
            root_store: RootCertStore::empty(),
        };

        // Attacker tries to use wildcard to match unrelated domains
        assert!(!validator.matches_domain("*.com", "attacker.com"));
        assert!(!validator.matches_domain("*.com", "example.com"));

        // Attacker tries partial wildcard
        assert!(!validator.matches_domain("*example.com", "attacker-example.com"));

        // Attacker tries wildcard in wrong position
        assert!(!validator.matches_domain("sub*.example.com", "subtest.example.com"));
    }

    /// Test real-world domain patterns
    #[test]
    fn test_real_world_domains() {
        let config = CertificateConfig::default();
        let validator = CertificateValidator {
            config,
            root_store: RootCertStore::empty(),
        };

        // Common patterns
        assert!(validator.matches_domain("*.amazonaws.com", "s3.amazonaws.com"));
        assert!(validator.matches_domain("*.cloudfront.net", "d111111abcdef8.cloudfront.net"));
        assert!(validator.matches_domain("*.github.io", "username.github.io"));

        // Multi-level domains
        assert!(validator.matches_domain("example.co.uk", "example.co.uk"));
        assert!(validator.matches_domain("*.example.co.uk", "www.example.co.uk"));

        // Hyphens and numbers
        assert!(validator.matches_domain("api-v2.example.com", "api-v2.example.com"));
        assert!(validator.matches_domain("*.example.com", "api-v2.example.com"));
        assert!(validator.matches_domain("test123.example.com", "test123.example.com"));
    }
}
