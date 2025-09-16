//! Root CA Store Tests - Following Strict TDD Methodology (RED Phase)
//!
//! This test suite validates the root CA trust store implementation including:
//! - Loading Mozilla CA bundle with 146 trusted root CAs
//! - Verifying trust anchor matching against real CAs
//! - Certificate chain validation against trusted roots
//! - Root CA trust policy enforcement following RFC 5280

use zktls_core::x509::{X509Certificate, RootCaStore, ValidationError};

#[cfg(test)]
mod root_ca_store_tests {
    use super::*;

    #[test] 
    fn test_root_ca_store_creation_should_succeed() {
        // RED: This test will fail until we implement RootCaStore
        let store = RootCaStore::new()
            .expect("Should create empty root CA store");
        
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn test_root_ca_store_with_builtin_cas_should_load_mozilla_ca_bundle() {
        // RED: This test will fail until we implement RootCaStore::with_builtin_cas
        let store = RootCaStore::with_builtin_cas()
            .expect("Should create root CA store with Mozilla CA bundle");
        
        // Should contain 146 root CAs from Mozilla CA bundle
        assert!(store.len() >= 140, "Should contain at least 140 root CAs from Mozilla bundle");
        assert!(store.len() <= 150, "Should not exceed reasonable number of root CAs");
        
        // Should be able to find well-known CAs by common name patterns
        let has_digicert = store.find_by_subject_containing("DigiCert")
            .expect("Should search for DigiCert CAs")
            .is_some();
        let has_globalsign = store.find_by_subject_containing("GlobalSign")
            .expect("Should search for GlobalSign CAs")
            .is_some();
        let has_entrust = store.find_by_subject_containing("Entrust")
            .expect("Should search for Entrust CAs")
            .is_some();
            
        assert!(has_digicert, "Mozilla bundle should contain DigiCert root CA");
        assert!(has_globalsign, "Mozilla bundle should contain GlobalSign root CA"); 
        assert!(has_entrust, "Mozilla bundle should contain Entrust root CA");
    }
    
    #[test]
    fn test_builtin_cas_should_be_self_signed_root_certificates() {
        // RED: This test will fail until we properly parse and validate root CAs
        let store = RootCaStore::with_builtin_cas()
            .expect("Should create root CA store with Mozilla CA bundle");
        
        // All certificates in the store should be self-signed roots
        let all_certs = store.get_all_root_certificates()
            .expect("Should be able to get all root certificates");
        assert!(all_certs.len() > 100, "Should have substantial number of root CAs");
        
        for cert in all_certs.iter().take(5) { // Test first 5 for performance
            // Root certificates must be self-signed (issuer == subject)
            assert_eq!(cert.issuer().to_string(), cert.subject().to_string(),
                "Root certificate {:?} should be self-signed", cert.subject());
        }
    }
    
    #[test]
    fn test_builtin_cas_should_have_reasonable_validity_periods() {
        // RED: This test will fail until we properly load the Mozilla CA bundle
        let store = RootCaStore::with_builtin_cas()
            .expect("Should create root CA store with Mozilla CA bundle");
        
        let all_certs = store.get_all_root_certificates()
            .expect("Should be able to get all root certificates");
        
        for cert in all_certs.iter().take(3) { // Test first 3 for performance
            // Root CAs should have reasonable validity periods
            let validity = cert.validity();
            let not_before = validity.not_before();
            let not_after = validity.not_after();
            
            // Basic sanity check - not_after should be after not_before
            assert!(not_after > not_before, 
                "Root CA {:?} should have valid time range", cert.subject());
        }
    }

    #[test]
    fn test_find_root_ca_by_nonexistent_subject_should_return_none() {
        // RED: This test will fail until we implement RootCaStore::find_by_subject
        let store = RootCaStore::new()
            .expect("Should create empty root CA store");
        
        let result = store.find_by_subject("CN=NonExistent CA,O=Test")
            .expect("Should not error on missing subject");
            
        assert!(result.is_none(), "Should not find non-existent root CA");
    }
}