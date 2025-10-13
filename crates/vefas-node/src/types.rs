//! API request and response types for VEFAS Node

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use vefas_types::{VefasCanonicalBundle, VefasProofClaim};

/// HTTP methods supported by the node
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
    /// Canonical bundle for Layer 2 verification
    pub bundle: VefasCanonicalBundle,
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
    /// Canonical bundle for Layer 2 verification (Merkle proofs, certificate validation, etc.)
    pub bundle: VefasCanonicalBundle,
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
    /// Layer 2 validation errors (if any)
    pub validation_errors: Vec<String>,
    /// Merkle proofs validated count
    pub merkle_proofs_validated: usize,
    /// Whether claim verification passed
    pub claim_verification_passed: bool,
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

/// VEFAS Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VefasNodeConfig {
    /// Server bind address
    pub bind_address: String,
    /// Enable CORS
    pub enable_cors: bool,
    /// Request timeout in seconds
    pub request_timeout: u64,
    /// Enable RISC0 proof generation
    pub enable_risc0: bool,
    /// Enable SP1 proof generation
    pub enable_sp1: bool,
}

impl Default for VefasNodeConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:8080".to_string(),
            enable_cors: true,
            request_timeout: 300,
            enable_risc0: true,
            enable_sp1: true,
        }
    }
}

/// VEFAS Node state
#[derive(Debug)]
pub struct VefasNodeState {
    /// VEFAS client for HTTP execution
    pub vefas_client: vefas_core::VefasClient,
    /// Prover service for ZK proof generation
    pub prover_service: crate::zktls::ProverService,
    /// Verifier service for ZK proof validation
    pub verifier_service: crate::zktls::VerifierService,
    /// Certificate validator
    pub certificate_validator: crate::zktls::CertificateValidator,
    /// OCSP checker
    pub ocsp_checker: crate::zktls::OcspChecker,
    /// CT log verifier
    pub ct_verifier: crate::zktls::CtLogVerifier,
    /// Attestation signer
    pub attestation_signer: crate::zktls::AttestationSigner,
    /// Node configuration
    pub config: VefasNodeConfig,
}

impl VefasNodeState {
    /// Create a new node state
    pub async fn new(config: VefasNodeConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let vefas_client = vefas_core::VefasClient::new().expect("Failed to create VEFAS client");
        let prover_service = crate::zktls::ProverService::new().await?;

        // Initialize VerifierService with provers for Layer 2 validation
        let mut verifier_service = crate::zktls::VerifierService::new();

        #[cfg(feature = "risc0")]
        {
            let risc0_prover = vefas_risc0::VefasRisc0Prover::new();
            verifier_service = verifier_service.with_risc0_prover(risc0_prover);
        }

        #[cfg(feature = "sp1")]
        {
            let sp1_prover = vefas_sp1::VefasSp1Prover::new();
            verifier_service = verifier_service.with_sp1_prover(sp1_prover);
        }

        // Initialize verifier components
        let certificate_validator = crate::zktls::CertificateValidator::new(
            crate::zktls::CertificateConfig::default()
        ).await?;

        let ocsp_checker = crate::zktls::OcspChecker::new(
            crate::zktls::OcspConfig::default()
        ).await?;

        let ct_verifier = crate::zktls::CtLogVerifier::new(
            crate::zktls::CtConfig::default()
        ).await?;

        let attestation_signer = crate::zktls::AttestationSigner::new(
            crate::zktls::AttestationConfig::default()
        ).await?;
        
        Ok(Self {
            vefas_client,
            prover_service,
            verifier_service,
            certificate_validator,
            ocsp_checker,
            ct_verifier,
            attestation_signer,
            config,
        })
    }
}

/// VEFAS Node server
#[derive(Debug)]
pub struct VefasNode {
    /// Node state
    pub state: std::sync::Arc<VefasNodeState>,
    /// Server configuration
    pub config: VefasNodeConfig,
}

impl VefasNode {
    /// Create a new VEFAS node
    pub async fn new(config: VefasNodeConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let state = std::sync::Arc::new(VefasNodeState::new(config.clone()).await?);
        
        Ok(Self {
            state,
            config,
        })
    }
    
    /// Build the router (useful for testing)
    pub fn router(&self) -> axum::Router {
        use axum::{routing::{get, post}, Router};
        use tower_http::cors::CorsLayer;

        // API routes with /api/v1 prefix
        let api_routes = Router::new()
            .route("/requests", post(crate::handlers::execute_request))
            .route("/verify", post(crate::handlers::verify_proof))
            .route("/health", get(crate::handlers::health_check))
            .with_state(self.state.clone());

        // Root routes
        Router::new()
            .route("/", get(crate::handlers::service_info))
            .nest("/api/v1", api_routes)
            .layer(if self.config.enable_cors {
                CorsLayer::permissive()
            } else {
                CorsLayer::new()
            })
    }

    /// Start the server
    pub async fn serve(&self) -> Result<(), Box<dyn std::error::Error>> {
        let app = self.router();

        // Start the server
        let listener = tokio::net::TcpListener::bind(&self.config.bind_address).await?;
        tracing::info!("VEFAS Node server listening on {}", self.config.bind_address);

        axum::serve(listener, app).await?;

        Ok(())
    }
}
