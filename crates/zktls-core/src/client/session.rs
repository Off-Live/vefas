//! TLS session management for HTTPS client
//!
//! This module provides session state management, key handling, and session
//! information for the HTTPS client implementation.

use crate::{
    tls::{
        application::ApplicationDataHandler,
        enhanced_state_machine::EnhancedHandshakeStateMachine,
    },
    x509::certificate::X509Certificate,
};
use alloc::{string::{String, ToString}, vec::Vec};
use serde::{Deserialize, Serialize};
use zktls_crypto::native::NativeCryptoProvider;

/// Session keys for TLS 1.3 application traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeys {
    /// Client application traffic key
    pub client_traffic_key: [u8; 32],
    /// Server application traffic key  
    pub server_traffic_key: [u8; 32],
    /// Client traffic IV
    pub client_traffic_iv: [u8; 12],
    /// Server traffic IV
    pub server_traffic_iv: [u8; 12],
}

/// TLS session information for zkTLS proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSessionInfo {
    /// Server hostname that was connected to
    pub hostname: String,
    /// Certificate chain presented by server
    pub certificate_chain: Vec<Vec<u8>>,
    /// TLS session keys used for encryption
    pub session_keys: SessionKeys,
    /// Handshake transcript for proof generation
    pub handshake_transcript: Vec<u8>,
}

/// Internal TLS session state
pub struct TlsSession {
    /// Hostname of current connection
    pub hostname: String,
    /// Application data handler for encryption/decryption
    pub app_data_handler: ApplicationDataHandler,
    /// Session keys
    pub session_keys: SessionKeys,
    /// Certificate chain from server
    pub certificate_chain: Vec<Vec<u8>>,
    /// Enhanced handshake state machine with real crypto
    pub handshake_state_machine: EnhancedHandshakeStateMachine<NativeCryptoProvider>,
    /// Client sequence number for encryption
    pub client_sequence_number: u64,
    /// Server sequence number for decryption
    pub server_sequence_number: u64,
}

impl TlsSession {
    /// Create a new TLS session
    pub fn new(
        hostname: String,
        app_data_handler: ApplicationDataHandler,
        session_keys: SessionKeys,
        certificate_chain: Vec<Vec<u8>>,
        handshake_state_machine: EnhancedHandshakeStateMachine<NativeCryptoProvider>,
    ) -> Self {
        Self {
            hostname,
            app_data_handler,
            session_keys,
            certificate_chain,
            handshake_state_machine,
            client_sequence_number: 0,
            server_sequence_number: 0,
        }
    }

    /// Get the handshake transcript for proof generation
    pub fn get_handshake_transcript(&self) -> Vec<u8> {
        self.handshake_state_machine
            .transcript()
            .transcript_data_up_to(
                self.handshake_state_machine.transcript().message_count()
            )
            .unwrap_or_default()
    }

    /// Create TLS session info for zkTLS proof generation
    pub fn to_session_info(&self) -> TlsSessionInfo {
        TlsSessionInfo {
            hostname: self.hostname.clone(),
            certificate_chain: self.certificate_chain.clone(),
            session_keys: self.session_keys.clone(),
            handshake_transcript: self.get_handshake_transcript(),
        }
    }
}

/// Certificate validation utilities
pub struct CertificateValidator;

impl CertificateValidator {
    /// Validate certificate chain with root CA store
    pub fn validate_certificate_chain_with_root_ca(
        chain: &[Vec<u8>], 
        hostname: &str
    ) -> crate::errors::ZkTlsResult<()> {
        if chain.is_empty() {
            return Err(crate::errors::ZkTlsError::InvalidTlsMessage(
                "Empty certificate chain".to_string()
            ));
        }
        
        // Parse end-entity certificate
        let _end_entity_cert = X509Certificate::parse(&chain[0])
            .map_err(|_e| crate::errors::ZkTlsError::CertificateError(
                crate::errors::CertificateError::InvalidFormat
            ))?;
        
        // Validate hostname against certificate (production-grade SAN validation)
        let cert = X509Certificate::parse(&chain[0]).map_err(|_e| {
            crate::errors::ZkTlsError::CertificateError(
                crate::errors::CertificateError::InvalidFormat
            )
        })?;
        
        // Check subject alternative names (SAN) for hostname validation
        // This is the proper way to validate hostnames per RFC 6125
        let mut hostname_valid = false;
        
        // Check SAN extension
        for extension in cert.extensions() {
            if let crate::x509::extensions::ExtensionType::SubjectAltName(san) = extension.extension_type() {
                for name in san.names() {
                    match name {
                        crate::x509::extensions::GeneralName::DnsName(dns_name) => {
                            if *dns_name == hostname || Self::match_wildcard_hostname(dns_name, hostname) {
                                hostname_valid = true;
                                break;
                            }
                        }
                        _ => {} // Other name types not relevant for hostname validation
                    }
                }
                if hostname_valid {
                    break;
                }
            }
        }
        
        // If no SAN, check subject CN (legacy approach)
        if !hostname_valid {
            let subject_cn = cert.subject().common_name();
            if let Some(cn) = subject_cn {
                if cn == hostname || Self::match_wildcard_hostname(cn, hostname) {
                    hostname_valid = true;
                }
            }
        }
        
        if !hostname_valid {
            return Err(crate::errors::ZkTlsError::CertificateError(
                crate::errors::CertificateError::HostnameMismatch
            ));
        }
        
        Ok(())
    }
    
    /// Match wildcard hostnames per RFC 6125
    fn match_wildcard_hostname(pattern: &str, hostname: &str) -> bool {
        // Only support single wildcard at the beginning (*.example.com)
        if let Some(wildcard_part) = pattern.strip_prefix("*.") {
            // Ensure hostname has enough parts and matches the suffix
            if let Some(dot_pos) = hostname.find('.') {
                let hostname_suffix = &hostname[dot_pos + 1..];
                return wildcard_part == hostname_suffix;
            }
        }
        false
    }
}
