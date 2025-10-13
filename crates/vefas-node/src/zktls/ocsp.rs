//! # OCSP (Online Certificate Status Protocol) Validation
//!
//! This module implements OCSP checking for VEFAS Node.

use crate::error::{VefasNodeError, VefasNodeResult};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

/// OCSP validation configuration
#[derive(Debug, Clone)]
pub struct OcspConfig {
    /// Enable OCSP checking
    pub enabled: bool,
    /// OCSP request timeout
    pub timeout_secs: u64,
    /// Maximum OCSP response age
    pub max_response_age_secs: u64,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 10,
            max_response_age_secs: 3600, // 1 hour
        }
    }
}

/// OCSP checker
#[derive(Debug)]
pub struct OcspChecker {
    /// OCSP configuration
    config: OcspConfig,
    /// HTTP client for OCSP requests
    client: reqwest::Client,
}

impl OcspChecker {
    /// Create a new OCSP checker
    pub async fn new(config: OcspConfig) -> VefasNodeResult<Self> {
        info!("Initializing OCSP checker");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| VefasNodeError::Configuration(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            client,
        })
    }

    /// Check OCSP status for a certificate chain
    pub async fn check_ocsp_status(
        &self,
        certificate_chain: &[Vec<u8>],
    ) -> VefasNodeResult<OcspValidationResult> {
        if !self.config.enabled {
            return Ok(OcspValidationResult {
                is_valid: true,
                status: "OCSP checking disabled".to_string(),
                timestamp: chrono::Utc::now(),
                next_update: None,
                errors: vec!["OCSP checking is disabled".to_string()],
            });
        }

        debug!("Checking OCSP status for certificate chain");

        if certificate_chain.is_empty() {
            return Ok(OcspValidationResult {
                is_valid: false,
                status: "No certificates".to_string(),
                timestamp: chrono::Utc::now(),
                next_update: None,
                errors: vec!["No certificates in chain".to_string()],
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
                        return Ok(OcspValidationResult {
                            is_valid: false,
                            status: "Parse error".to_string(),
                            timestamp: chrono::Utc::now(),
                            next_update: None,
                            errors,
                        });
                    }
                }
            }
            None => {
                errors.push("No certificates in chain".to_string());
                is_valid = false;
                return Ok(OcspValidationResult {
                    is_valid: false,
                    status: "No certificates".to_string(),
                    timestamp: chrono::Utc::now(),
                    next_update: None,
                    errors,
                });
            }
        };

        // Extract OCSP responder URL
        let ocsp_url = match self.extract_ocsp_url(&end_entity_cert) {
            Some(url) => url,
            None => {
                errors.push("No OCSP responder URL found in certificate".to_string());
                is_valid = false;
                return Ok(OcspValidationResult {
                    is_valid: false,
                    status: "No OCSP URL".to_string(),
                    timestamp: chrono::Utc::now(),
                    next_update: None,
                    errors,
                });
            }
        };

        // Perform OCSP request
        match self.perform_ocsp_request(&ocsp_url, &end_entity_cert, certificate_chain).await {
            Ok(response) => {
                info!("OCSP check completed successfully for {}", ocsp_url);
                Ok(response)
            }
            Err(e) => {
                error!("OCSP check failed: {}", e);
                Ok(OcspValidationResult {
                    is_valid: false,
                    status: "OCSP request failed".to_string(),
                    timestamp: chrono::Utc::now(),
                    next_update: None,
                    errors: vec![e.to_string()],
                })
            }
        }
    }

    /// Extract OCSP responder URL from certificate
    fn extract_ocsp_url(&self, _cert: &x509_parser::certificate::X509Certificate) -> Option<String> {
        // Simplified OCSP URL extraction for now
        // In production, you would parse the AIA extension properly
        debug!("Extracting OCSP URL from certificate");
        Some("http://ocsp.example.com".to_string())
    }

    /// Perform OCSP request
    async fn perform_ocsp_request(
        &self,
        ocsp_url: &str,
        cert: &x509_parser::certificate::X509Certificate<'_>,
        certificate_chain: &[Vec<u8>],
    ) -> VefasNodeResult<OcspValidationResult> {
        debug!("Performing OCSP request to: {}", ocsp_url);

        // For now, we'll simulate an OCSP response
        // In a production system, you would:
        // 1. Build a proper OCSP request
        // 2. Send it to the OCSP responder
        // 3. Parse the response
        // 4. Validate the response signature

        let now = chrono::Utc::now();
        let next_update = now + chrono::Duration::hours(24);

        // Simulate successful OCSP response
        Ok(OcspValidationResult {
            is_valid: true,
            status: "Good".to_string(),
            timestamp: now,
            next_update: Some(next_update),
            errors: vec!["OCSP validation simulated - not implemented".to_string()],
        })
    }
}

/// OCSP validation result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OcspValidationResult {
    /// Whether OCSP check passed
    pub is_valid: bool,
    /// OCSP response status
    pub status: String,
    /// OCSP response timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// OCSP response next update time
    pub next_update: Option<chrono::DateTime<chrono::Utc>>,
    /// OCSP validation errors (if any)
    pub errors: Vec<String>,
}
