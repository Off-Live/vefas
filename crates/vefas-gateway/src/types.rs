//! API request and response types for VEFAS Gateway

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use vefas_types::{VefasCanonicalBundle, VefasProofClaim};

/// HTTP methods supported by the gateway
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Patch => write!(f, "PATCH"),
        }
    }
}

impl std::str::FromStr for HttpMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "DELETE" => Ok(HttpMethod::Delete),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            "PATCH" => Ok(HttpMethod::Patch),
            _ => Err(format!("Invalid HTTP method: {}", s)),
        }
    }
}

/// Proof platform options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProofPlatform {
    Sp1,
    Risc0,
}

impl std::fmt::Display for ProofPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofPlatform::Sp1 => write!(f, "sp1"),
            ProofPlatform::Risc0 => write!(f, "risc0"),
        }
    }
}

impl Default for ProofPlatform {
    fn default() -> Self {
        ProofPlatform::Sp1
    }
}

/// Request payload for POST /requests endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequestPayload {
    /// HTTP method
    pub method: HttpMethod,
    /// Target URL (must be HTTPS)
    pub url: String,
    /// Optional HTTP headers
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Optional request body (base64 encoded)
    pub body: Option<String>,
    /// Proof platform preference
    #[serde(default)]
    pub proof_platform: ProofPlatform,
    /// Request timeout in milliseconds
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_timeout() -> u64 {
    30000 // 30 seconds
}

/// HTTP response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseData {
    /// HTTP status code
    pub status_code: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body (base64 encoded)
    pub body: String,
}

/// Cryptographic proof claim (unified type from vefas-types)
pub type ProofClaim = VefasProofClaim;

/// Execution metadata from zkVM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMetadata {
    /// Number of zkVM cycles consumed
    pub cycles: u64,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Total execution time in milliseconds
    pub execution_time_ms: u64,
    /// Proof generation time in milliseconds
    pub proof_time_ms: u64,
    /// Platform used for proof generation
    pub platform: String,
}

/// Cryptographic proof data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofData {
    /// Proof platform used
    pub platform: String,
    /// Base64 encoded proof data
    pub proof_data: String,
    /// Verified claim extracted from proof
    pub claim: ProofClaim,
    /// Execution metadata
    pub execution_metadata: ExecutionMetadata,
}

/// Merkle tree information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeInfo {
    /// Merkle tree root hash
    pub root: String, // hex encoded
    /// Number of leaves in the tree
    pub leaf_count: usize,
    /// Available field proofs
    pub available_proofs: Vec<String>, // FieldId names
}

/// Response payload for POST /requests endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequestResponse {
    /// Request success status
    pub success: bool,
    /// HTTP response data from target server
    pub http_response: HttpResponseData,
    /// Cryptographic proof of the TLS session
    pub proof: ProofData,
    /// Merkle tree information for integrity verification
    pub merkle_tree: MerkleTreeInfo,
    /// Unique session identifier
    pub session_id: String,
}

/// Request payload for POST /verify endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyProofPayload {
    /// Proof to verify
    pub proof: ProofData,
    /// Optional expected claim for validation
    pub expected_claim: Option<ProofClaim>,
}

/// Verification metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMetadata {
    /// Time taken to verify proof in milliseconds
    pub verification_time_ms: u64,
    /// Version of the verifier
    pub verifier_version: String,
    /// Timestamp when verification was performed
    pub verified_at: u64,
}

/// Verification result details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof is cryptographically valid
    pub valid: bool,
    /// Platform used for the proof
    pub platform: String,
    /// Verified claim from the proof
    pub verified_claim: ProofClaim,
    /// Verification metadata
    pub verification_metadata: VerificationMetadata,
}

/// Response payload for POST /verify endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyProofResponse {
    /// Verification success status
    pub success: bool,
    /// Detailed verification result
    pub verification_result: VerificationResult,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Current timestamp
    pub timestamp: DateTime<Utc>,
    /// Service version
    pub version: String,
    /// Available proof platforms
    pub platforms: Vec<String>,
}

/// Root endpoint response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootResponse {
    /// Service name
    pub service: String,
    /// Service version
    pub version: String,
    /// API version
    pub api_version: String,
    /// Available endpoints
    pub endpoints: Vec<String>,
    /// Service documentation URL
    pub documentation: String,
}

impl ExecuteRequestPayload {
    /// Validate the request payload
    pub fn validate(&self) -> Result<(), String> {
        // Validate URL
        if !self.url.starts_with("https://") {
            return Err("URL must use HTTPS protocol".to_string());
        }

        // Parse URL to ensure it's valid
        url::Url::parse(&self.url).map_err(|e| format!("Invalid URL format: {}", e))?;

        // Validate timeout
        if self.timeout_ms < 1000 || self.timeout_ms > 300000 {
            return Err("Timeout must be between 1 and 300 seconds".to_string());
        }

        // Validate body if present
        if let Some(ref body) = self.body {
            use base64::{engine::general_purpose, Engine as _};
            general_purpose::STANDARD
                .decode(body)
                .map_err(|_| "Request body must be valid base64".to_string())?;

            // Check body size (10MB limit when decoded)
            if body.len() > 13_631_488 {
                // base64 overhead ~37%
                return Err("Request body too large (max 10MB)".to_string());
            }
        }

        // Validate headers
        for (key, value) in &self.headers {
            if key.trim().is_empty() {
                return Err("Header names cannot be empty".to_string());
            }
            if value.len() > 8192 {
                // Reasonable header value limit
                return Err(format!("Header value too long for '{}' (max 8KB)", key));
            }
        }

        Ok(())
    }

    /// Get the decoded request body
    pub fn get_body_bytes(&self) -> Result<Option<Vec<u8>>, String> {
        match &self.body {
            Some(body) => {
                use base64::{engine::general_purpose, Engine as _};
                let bytes = general_purpose::STANDARD
                    .decode(body)
                    .map_err(|_| "Invalid base64 in request body".to_string())?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    /// Convert headers to Vec<(String, String)> for vefas-core
    pub fn get_headers_vec(&self) -> Option<Vec<(String, String)>> {
        if self.headers.is_empty() {
            None
        } else {
            Some(
                self.headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            )
        }
    }
}

impl VerifyProofPayload {
    /// Validate the verify proof payload
    pub fn validate(&self) -> Result<(), String> {
        // Validate proof platform
        match self.proof.platform.as_str() {
            "sp1" | "risc0" => {}
            _ => return Err("Unsupported proof platform".to_string()),
        }

        // Validate proof data is valid base64
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD
            .decode(&self.proof.proof_data)
            .map_err(|_| "Proof data must be valid base64".to_string())?;

        // Basic claim validation
        if self.proof.claim.domain.trim().is_empty() {
            return Err("Claim domain cannot be empty".to_string());
        }

        if self.proof.claim.method.trim().is_empty() {
            return Err("Claim method cannot be empty".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_serialization() {
        let method = HttpMethod::Get;
        let json = serde_json::to_string(&method).unwrap();
        assert_eq!(json, "\"GET\"");

        let deserialized: HttpMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, HttpMethod::Get);
    }

    #[test]
    fn test_execute_request_validation() {
        let mut payload = ExecuteRequestPayload {
            method: HttpMethod::Get,
            url: "https://example.com".to_string(),
            headers: HashMap::new(),
            body: None,
            proof_platform: ProofPlatform::Sp1,
            timeout_ms: 30000,
        };

        // Valid payload
        assert!(payload.validate().is_ok());

        // Invalid URL
        payload.url = "http://example.com".to_string();
        assert!(payload.validate().is_err());

        // Invalid timeout
        payload.url = "https://example.com".to_string();
        payload.timeout_ms = 500;
        assert!(payload.validate().is_err());
    }

    #[test]
    fn test_body_encoding_decoding() {
        use base64::{engine::general_purpose, Engine as _};
        let payload = ExecuteRequestPayload {
            method: HttpMethod::Post,
            url: "https://example.com".to_string(),
            headers: HashMap::new(),
            body: Some(general_purpose::STANDARD.encode("test body")),
            proof_platform: ProofPlatform::Sp1,
            timeout_ms: 30000,
        };

        let decoded = payload.get_body_bytes().unwrap();
        assert_eq!(decoded, Some(b"test body".to_vec()));
    }
}
