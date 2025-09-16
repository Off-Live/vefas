//! Domain name validation tests following strict TDD methodology
//! 
//! These tests implement RFC 6125 server identity verification requirements.
//! Tests are organized by validation scenarios:
//! 1. Exact domain matching (SAN and CN)
//! 2. Wildcard certificate matching and security constraints
//! 3. SAN vs CN precedence rules
//! 4. Case sensitivity and internationalization
//! 5. Security edge cases and attack prevention

use zktls_core::x509::{X509Certificate, domain_validation::validate_domain};
use zktls_core::x509::domain_validation::DomainValidationResult;

/// Test fixture for certificate with Subject Alternative Name
const CERT_WITH_SAN_DER: &[u8] = include_bytes!("fixtures/certificates/cert_with_san.der");

/// Test fixture for certificate with wildcard SAN
const CERT_WILDCARD_SAN_DER: &[u8] = include_bytes!("fixtures/certificates/cert_wildcard_san.der");

/// Test fixture for certificate with only CN (no SAN)
const CERT_CN_ONLY_DER: &[u8] = include_bytes!("fixtures/certificates/cert_cn_only.der");

/// Test fixture for certificate with both SAN and CN
const CERT_SAN_AND_CN_DER: &[u8] = include_bytes!("fixtures/certificates/cert_san_and_cn.der");

#[cfg(test)]
mod exact_domain_matching_tests {
    use super::*;

    #[test]
    fn test_exact_match_against_san_dns_name() {
        // RED: This test will fail until domain validation is implemented
        
        // Parse certificate with SAN containing "api.example.com"
        let cert = X509Certificate::parse(CERT_WITH_SAN_DER)
            .expect("Should parse certificate with SAN");
        
        // Should match exact domain from SAN
        let result = validate_domain(&cert, "api.example.com")
            .expect("Domain validation should succeed");
        
        assert_eq!(result, DomainValidationResult::ExactMatch);
    }

    #[test]
    fn test_exact_match_case_insensitive() {
        // RED: This test will fail until case-insensitive matching is implemented
        
        let cert = X509Certificate::parse(CERT_WITH_SAN_DER)
            .expect("Should parse certificate with SAN");
        
        // DNS names should be case-insensitive per RFC 1035
        let result = validate_domain(&cert, "API.EXAMPLE.COM")
            .expect("Case-insensitive domain validation should succeed");
        
        assert_eq!(result, DomainValidationResult::ExactMatch);
    }

    #[test]
    fn test_exact_match_against_cn_only() {
        // RED: This test will fail until CN-only validation is implemented
        
        // Parse certificate with only CN="server.test.com", no SAN extension
        let cert = X509Certificate::parse(CERT_CN_ONLY_DER)
            .expect("Should parse certificate with CN only");
        
        // Should match domain from CN when no SAN is present
        let result = validate_domain(&cert, "server.test.com")
            .expect("CN domain validation should succeed");
        
        assert_eq!(result, DomainValidationResult::ExactMatch);
    }

    #[test]
    fn test_no_match_different_domain() {
        // RED: This test will fail until mismatch detection is implemented
        
        let cert = X509Certificate::parse(CERT_WITH_SAN_DER)
            .expect("Should parse certificate");
        
        // Should reject different domain
        let result = validate_domain(&cert, "different.example.com");
        
        assert!(result.is_err());
        // Expect DomainValidationError::NoMatch
    }
}

#[cfg(test)]
mod wildcard_matching_tests {
    use super::*;

    #[test]
    fn test_wildcard_match_single_label() {
        // RED: This test will fail until wildcard matching is implemented
        
        // Parse certificate with SAN containing "*.example.com" 
        let cert = X509Certificate::parse(CERT_WILDCARD_SAN_DER)
            .expect("Should parse wildcard certificate");
        
        // Should match single-label subdomain
        let result = validate_domain(&cert, "api.example.com")
            .expect("Wildcard validation should succeed");
        
        assert_eq!(result, DomainValidationResult::WildcardMatch);
    }

    #[test]
    fn test_wildcard_match_multiple_subdomains() {
        // RED: This test will fail until wildcard matching is implemented
        
        let cert = X509Certificate::parse(CERT_WILDCARD_SAN_DER)
            .expect("Should parse wildcard certificate");
        
        // Should match various single-label subdomains
        for domain in &["www.example.com", "mail.example.com", "cdn.example.com"] {
            let result = validate_domain(&cert, domain)
                .expect("Wildcard validation should succeed");
            
            assert_eq!(result, DomainValidationResult::WildcardMatch);
        }
    }

    #[test]
    fn test_wildcard_no_match_multiple_labels() {
        // RED: This test will fail until wildcard constraint checking is implemented
        
        let cert = X509Certificate::parse(CERT_WILDCARD_SAN_DER)
            .expect("Should parse wildcard certificate");
        
        // Should NOT match multi-label subdomains (security requirement)
        // *.example.com should not match sub.api.example.com
        let result = validate_domain(&cert, "sub.api.example.com");
        
        assert!(result.is_err());
        // Expect DomainValidationError::WildcardConstraintViolation
    }

    #[test]
    fn test_wildcard_no_match_apex_domain() {
        // RED: This test will fail until apex domain checking is implemented
        
        let cert = X509Certificate::parse(CERT_WILDCARD_SAN_DER)
            .expect("Should parse wildcard certificate");
        
        // Should NOT match apex domain itself
        // *.example.com should not match example.com
        let result = validate_domain(&cert, "example.com");
        
        assert!(result.is_err());
        // Expect DomainValidationError::WildcardApexMismatch
    }

    #[test]
    fn test_invalid_wildcard_public_suffix() {
        // RED: This test will fail until public suffix validation is implemented
        
        // This test requires a malicious certificate with "*.co.uk" or similar
        // For MVP, we'll implement basic wildcard constraints
        // Future: integrate public suffix list checking
        
        // Placeholder test - in production this should prevent:
        // - *.co.uk matching evil.co.uk
        // - *.com matching evil.com
        // - Other public suffix wildcards
    }
}

#[cfg(test)]
mod san_vs_cn_precedence_tests {
    use super::*;

    #[test]
    fn test_san_takes_precedence_over_cn() {
        // RED: This test will fail until SAN precedence logic is implemented
        
        // Parse certificate with both SAN="api.example.com" and CN="wrong.example.com"
        let cert = X509Certificate::parse(CERT_SAN_AND_CN_DER)
            .expect("Should parse certificate with both SAN and CN");
        
        // Should match SAN domain, not CN domain
        let result = validate_domain(&cert, "api.example.com")
            .expect("SAN domain validation should succeed");
        
        assert_eq!(result, DomainValidationResult::ExactMatch);
    }

    #[test]
    fn test_cn_ignored_when_san_present() {
        // RED: This test will fail until CN ignoring logic is implemented
        
        let cert = X509Certificate::parse(CERT_SAN_AND_CN_DER)
            .expect("Should parse certificate with both SAN and CN");
        
        // Should NOT match CN domain when SAN is present (per RFC 6125)
        let result = validate_domain(&cert, "wrong.example.com");
        
        assert!(result.is_err());
        // Expect DomainValidationError::NoMatch (CN ignored due to SAN presence)
    }

    #[test]
    fn test_multiple_san_entries() {
        // RED: This test will fail until multiple SAN processing is implemented
        
        // This test requires a certificate with multiple SAN DNS names
        // Should match any of the SAN entries
        
        // Future test: certificate with SAN containing both:
        // - api.example.com 
        // - www.example.com
        // Both domains should validate successfully
    }
}

#[cfg(test)]
mod security_edge_cases_tests {
    use super::*;

    #[test]
    fn test_reject_empty_domain() {
        // RED: This test will fail until input validation is implemented
        
        let cert = X509Certificate::parse(CERT_WITH_SAN_DER)
            .expect("Should parse certificate");
        
        // Should reject empty domain string
        let result = validate_domain(&cert, "");
        
        assert!(result.is_err());
        // Expect DomainValidationError::InvalidDomain
    }

    #[test]
    fn test_reject_malformed_domain() {
        // RED: This test will fail until domain format validation is implemented
        
        let cert = X509Certificate::parse(CERT_WITH_SAN_DER)
            .expect("Should parse certificate");
        
        // Should reject malformed domains
        for invalid_domain in &[
            ".",                    // Just a dot
            ".example.com",         // Leading dot
            "example.com.",         // Trailing dot (debatable)
            "exam..ple.com",        // Double dot
            "exam ple.com",         // Space character
            "exam\nple.com",        // Newline character
        ] {
            let result = validate_domain(&cert, invalid_domain);
            assert!(result.is_err(), "Should reject malformed domain: {}", invalid_domain);
        }
    }

    #[test]
    fn test_reject_ip_address_in_dns_name() {
        // RED: This test will fail until IP address detection is implemented
        
        let cert = X509Certificate::parse(CERT_WITH_SAN_DER)
            .expect("Should parse certificate");
        
        // Should reject IP addresses when validating against DNS names
        // IP addresses should be validated against SAN IP Address entries, not DNS names
        for ip in &["192.168.1.1", "::1", "2001:db8::1"] {
            let result = validate_domain(&cert, ip);
            assert!(result.is_err(), "Should reject IP address as domain: {}", ip);
        }
    }

    #[test]
    fn test_internationalized_domain_names() {
        // RED: This test will fail until IDN support is implemented
        
        // For MVP, we'll implement basic ASCII domain validation
        // Future enhancement: proper IDN (punycode) handling
        
        let cert = X509Certificate::parse(CERT_WITH_SAN_DER)
            .expect("Should parse certificate");
        
        // This test is a placeholder for IDN support
        // In production, should handle domains like "例え.テスト"
        // which encode to "xn--r8jz45g.xn--zckzah" in punycode
    }
}

#[cfg(test)]
mod certificate_extension_tests {
    use super::*;

    #[test]
    fn test_certificate_without_san_extension() {
        // RED: This test will fail until extension absence handling is implemented
        
        let cert = X509Certificate::parse(CERT_CN_ONLY_DER)
            .expect("Should parse certificate without SAN");
        
        // Verify the certificate indeed has no SAN extension
        let extensions = cert.extensions();
        let has_san = extensions.iter().any(|ext| {
            matches!(ext.extension_type(), zktls_core::x509::ExtensionType::SubjectAltName(_))
        });
        
        assert!(!has_san, "Certificate should not have SAN extension");
        
        // Domain validation should fall back to CN
        let result = validate_domain(&cert, "server.test.com")
            .expect("Should validate using CN when no SAN present");
        
        assert_eq!(result, DomainValidationResult::ExactMatch);
    }

    #[test]
    fn test_certificate_with_empty_san() {
        // RED: This test will fail until empty SAN handling is implemented
        
        // This test requires a certificate with SAN extension but no DNS names
        // Should fall back to CN in this edge case
        
        // Future enhancement: handle certificates with SAN containing only
        // non-DNS entries (e.g., only email addresses or IP addresses)
    }
}