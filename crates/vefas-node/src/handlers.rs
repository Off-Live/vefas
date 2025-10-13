//! HTTP request handlers for VEFAS Node endpoints

use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::Json as ResponseJson,
};
use chrono::Utc;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::{error::*, types::*, VefasNodeState};
use vefas_types::VefasCanonicalBundle;
use vefas_crypto::{FieldId, MerkleError};

/// Handle POST /requests endpoint - Execute TLS request and generate proof
#[axum::debug_handler]
#[instrument(skip(state, payload), fields(session_id, method, url = %payload.url))]
pub async fn execute_request(
    State(state): State<Arc<VefasNodeState>>,
    Json(payload): Json<ExecuteRequestPayload>,
) -> Result<ResponseJson<ExecuteRequestResponse>, VefasNodeError> {
    // Generate unique session ID for tracking
    let session_id = Uuid::new_v4().to_string();
    tracing::Span::current().record("session_id", &session_id);
    tracing::Span::current().record("method", &payload.method.to_string());

    info!("Processing execute request for {}", payload.url);

    // Basic request validation (minimal checks for safety)
    if !payload.url.starts_with("https://") {
        return Err(VefasNodeError::InvalidRequest("URL must use HTTPS protocol".to_string()));
    }

    if payload.timeout_ms < 1000 || payload.timeout_ms > 300000 {
        return Err(VefasNodeError::InvalidRequest("Timeout must be between 1 and 300 seconds".to_string()));
    }

    debug!("Basic request validation passed for session {}", session_id);

    // Execute the HTTPS request using vefas-core - returns bundle, HTTP data, and transcript bundle
    let (mut bundle, http_data, mut transcript_bundle) = {
        let headers = payload.get_headers_vec();
        let body = payload
            .get_body_bytes()
            .map_err(|e| VefasNodeError::InvalidRequest(e))?;

        // Convert headers to the format expected by vefas-core
        let headers_str_refs: Option<Vec<(&str, &str)>> = headers
            .as_ref()
            .map(|h| h.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect());

        debug!("Executing HTTPS request via vefas-core");
        state
            .vefas_client
            .execute_request(
                &payload.method.to_string(),
                &payload.url,
                headers_str_refs.as_ref().map(|h| h.as_slice()),
                body.as_deref(),
            )
            .await
            .map_err(|e| {
                error!("Failed to execute HTTPS request: {}", e);
                VefasNodeError::VefasCore(e)
            })?
    };

    info!("Successfully captured TLS session data for {}", payload.url);

    // Build Merkle tree with 6 fields for selective disclosure + performance
    // User-verifiable (4): HttpRequest, HttpResponse, Domain, Timestamp
    // Internal (2): HandshakeProof, TlsVersion
    // This achieves ~25% cycle reduction while enabling privacy-preserving selective disclosure
    let required_fields = vec![
        // User-verifiable fields (can be shared independently)
        FieldId::HttpRequest,      // Users can prove just the request
        FieldId::HttpResponse,     // Users can prove just the response
        FieldId::Domain,           // Users can prove which domain
        FieldId::Timestamp,        // Users can prove when
        // Internal fields (for zkVM verification)
        FieldId::HandshakeProof,   // TLS handshake validity (composite: client_hello + server_hello + cert_fingerprint + server_random + cipher_suite)
        FieldId::TlsVersion,       // TLS protocol version metadata
    ];

    debug!("Building Merkle tree with {} required fields", required_fields.len());
    transcript_bundle.build_merkle_tree(&required_fields).map_err(|e| {
        error!("Failed to build Merkle tree: {}", e);
        VefasNodeError::VefasCore(vefas_core::VefasCoreError::tls_error(&format!("Merkle tree construction failed: {}", e)))
    })?;

    info!("Successfully built Merkle tree with root: {:02x?}", 
          transcript_bundle.merkle_root.unwrap_or([0u8; 32]));
    
    // Debug: Check if Merkle data is actually available
    debug!("Transcript bundle Merkle root: {:?}", transcript_bundle.merkle_root);
    debug!("Transcript bundle Merkle proofs count: {}", transcript_bundle.merkle_proofs.len());
    
    // Debug: Check bundle domain and verify it's valid UTF-8
    eprintln!("Bundle domain: {}", bundle.domain);
    eprintln!("Bundle domain bytes: {:?}", bundle.domain.as_bytes());
    
    // Apply Merkle proofs directly to the original bundle
    if let Some(merkle_root) = transcript_bundle.merkle_root {
        let mut merkle_proofs = Vec::new();
        for (field_id, proof) in &transcript_bundle.merkle_proofs {
            let proof_bytes = bincode::serialize(proof).map_err(|e| {
                error!("Failed to serialize Merkle proof: {}", e);
                VefasNodeError::VefasCore(vefas_core::VefasCoreError::tls_error(&format!("Merkle proof serialization failed: {}", e)))
            })?;
            merkle_proofs.push((*field_id as u8, proof_bytes));
        }
        bundle.set_merkle_proofs(merkle_root, merkle_proofs);
        debug!("Applied Merkle proofs to bundle: root={:?}, proofs_count={}", bundle.merkle_root, bundle.merkle_proofs.len());
    } else {
        error!("No Merkle root available after build_merkle_tree - this should not happen");
    }

    // Extract HTTP response data from the HttpData returned by vefas-core
    let http_response = HttpResponseData {
        status_code: http_data.status_code,
        headers: http_data
            .headers
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>(),
        body: String::from_utf8_lossy(&http_data.response_body).to_string(),
    };

    debug!(
        "HTTP response extracted: status={}, body_size={}",
        http_response.status_code,
        http_response.body.len()
    );

    // Generate cryptographic proof with the bundle that now has Merkle proofs
    let proof_data = state
        .prover_service
        .generate_proof(&bundle, &payload.proof_platform)
        .await
        .map_err(|e| {
            error!("Proof generation failed for platform {:?}: {}", payload.proof_platform, e);
            e
        })?;

    info!(
        "Successfully generated proof using {} platform",
        proof_data.platform
    );

    // Create Merkle tree information for the response
    let merkle_tree_info = MerkleTreeInfo {
        root: hex::encode(transcript_bundle.merkle_root.unwrap_or([0u8; 32])),
        leaf_count: transcript_bundle.merkle_proofs.len(),
        available_proofs: transcript_bundle.merkle_proofs
            .iter()
            .map(|(field_id, _)| format!("{:?}", field_id))
            .collect(),
    };

    // Create response including the bundle for Layer 2 verification
    let response = ExecuteRequestResponse {
        success: true,
        http_response,
        proof: proof_data,
        merkle_tree: merkle_tree_info,
        bundle: bundle.clone(),
        session_id: session_id.clone(),
    };

    info!("Request processing completed for session {}", session_id);

    Ok(ResponseJson(response))
}

/// Handle POST /verify endpoint - Verify cryptographic proof
#[axum::debug_handler]
#[instrument(skip(state, payload), fields(platform = %payload.proof.platform))]
pub async fn verify_proof(
    State(state): State<Arc<VefasNodeState>>,
    Json(payload): Json<VerifyProofPayload>,
) -> Result<ResponseJson<VerifyProofResponse>, VefasNodeError> {
    info!(
        "Processing proof verification request for platform: {}",
        payload.proof.platform
    );

    // Basic proof validation (minimal checks for safety)
    if !["sp1", "risc0"].contains(&payload.proof.platform.as_str()) {
        return Err(VefasNodeError::InvalidRequest("Unsupported proof platform".to_string()));
    }

    if payload.proof.proof_data.is_empty() {
        return Err(VefasNodeError::InvalidRequest("Proof data cannot be empty".to_string()));
    }

    debug!("Basic verification request validation passed");

    // ============================================================================
    // 2-LAYER VERIFICATION: VerifierService performs complete validation
    // - Layer 1: zkVM proof verification (RISC0/SP1 Receipt.verify())
    // - Layer 2: Cryptographic validation (Merkle proofs, certificates, claims)
    // ============================================================================
    info!("Starting 2-layer verification using VerifierService");

    // Reconstruct the full proof structure for validation
    use base64::{engine::general_purpose, Engine as _};
    let proof_bytes = general_purpose::STANDARD
        .decode(&payload.proof.proof_data)
        .map_err(|e| VefasNodeError::InvalidRequest(format!("Invalid proof data encoding: {}", e)))?;

    // Reconstruct platform-specific proof structure
    let full_proof_bytes = match payload.proof.platform.as_str() {
        "risc0" => {
            // Reconstruct VefasRisc0Proof
            use vefas_types::VefasExecutionMetadata;
            let risc0_proof = vefas_risc0::VefasRisc0Proof {
                receipt_data: proof_bytes,
                claim: payload.proof.claim.clone(),
                execution_metadata: VefasExecutionMetadata::new(
                    payload.proof.execution_metadata.cycles,
                    payload.proof.execution_metadata.memory_usage as usize,
                    payload.proof.execution_metadata.execution_time_ms,
                    payload.proof.execution_metadata.platform.clone(),
                    payload.proof.execution_metadata.proof_time_ms,
                ).map_err(|e| VefasNodeError::InvalidRequest(format!("Invalid execution metadata: {:?}", e)))?,
            };
            bincode::serialize(&risc0_proof)
                .map_err(|e| VefasNodeError::InvalidRequest(format!("Failed to serialize RISC0 proof: {}", e)))?
        }
        "sp1" => {
            // Reconstruct VefasSp1Proof
            use vefas_types::VefasExecutionMetadata;
            let sp1_proof = vefas_sp1::VefasSp1Proof {
                proof_data: proof_bytes,
                claim: payload.proof.claim.clone(),
                execution_metadata: VefasExecutionMetadata::new(
                    payload.proof.execution_metadata.cycles,
                    payload.proof.execution_metadata.memory_usage as usize,
                    payload.proof.execution_metadata.execution_time_ms,
                    payload.proof.execution_metadata.platform.clone(),
                    payload.proof.execution_metadata.proof_time_ms,
                ).map_err(|e| VefasNodeError::InvalidRequest(format!("Invalid execution metadata: {:?}", e)))?,
            };
            bincode::serialize(&sp1_proof)
                .map_err(|e| VefasNodeError::InvalidRequest(format!("Failed to serialize SP1 proof: {}", e)))?
        }
        _ => {
            return Err(VefasNodeError::InvalidRequest(format!("Unsupported platform: {}", payload.proof.platform)));
        }
    };

    // Run complete 2-layer validation using VerifierService
    let validation_result = state
        .verifier_service
        .validate_zk_proof(
            &full_proof_bytes,
            &payload.proof.platform,
            &payload.bundle,
        )
        .await
        .map_err(|e| {
            error!("Verification failed: {}", e);
            e
        })?;

    if !validation_result.is_valid {
        warn!(
            "Verification failed: {} errors found",
            validation_result.errors.len()
        );
    } else {
        info!(
            "Verification passed: {}/{} Merkle proofs validated, claim verification: {}",
            validation_result.metadata.merkle_proofs_count,
            payload.bundle.merkle_proofs.len(),
            validation_result.metadata.claim_verification_successful
        );
    }

    // Extract verified claim or use default
    let verified_claim = validation_result.claim.unwrap_or_else(|| {
        // If verification failed and no claim was extracted, use the claim from request
        payload.proof.claim.clone()
    });

    // Create verification metadata
    use std::time::{SystemTime, UNIX_EPOCH};
    let verification_metadata = VerificationMetadata {
        verification_time_ms: validation_result.metadata.validation_time_ms,
        verifier_version: env!("CARGO_PKG_VERSION").to_string(),
        verified_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Create verification result
    let verification_result = VerificationResult {
        valid: validation_result.is_valid,
        platform: payload.proof.platform.clone(),
        verified_claim,
        verification_metadata,
        validation_errors: validation_result.errors,
        merkle_proofs_validated: validation_result.metadata.merkle_proofs_count,
        claim_verification_passed: validation_result.metadata.claim_verification_successful,
    };

    info!(
        "2-layer verification completed: valid={}, platform={}",
        validation_result.is_valid, payload.proof.platform
    );

    // Create response
    let response = VerifyProofResponse {
        success: validation_result.is_valid,
        verification_result,
    };

    Ok(ResponseJson(response))
}

/// Handle GET /health endpoint - Health check
#[instrument(skip(state))]
pub async fn health_check(
    State(state): State<Arc<VefasNodeState>>,
) -> ResponseJson<HealthResponse> {
    debug!("Processing health check request");

    let platforms = state.prover_service.available_platforms();

    let response = HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        platforms,
    };

    ResponseJson(response)
}

/// Handle GET / endpoint - Service information
#[instrument]
pub async fn service_info() -> ResponseJson<RootResponse> {
    debug!("Processing service info request");

    let response = RootResponse {
        service: "VEFAS Node".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        api_version: "v1".to_string(),
        endpoints: vec![
            "POST /requests".to_string(),
            "POST /verify".to_string(),
            "GET /health".to_string(),
        ],
        documentation: "https://github.com/vefas/vefas".to_string(),
    };

    ResponseJson(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use std::collections::HashMap;
    use tower::ServiceExt;

    async fn create_test_state() -> Arc<VefasNodeState> {
        use crate::VefasNodeConfig;
        VefasNodeState::new(VefasNodeConfig::default())
            .await
            .unwrap()
            .into()
    }

    #[tokio::test]
    async fn test_health_check_handler() {
        let state = create_test_state().await;
        let response = health_check(State(state)).await;

        assert_eq!(response.0.status, "healthy");
        assert_eq!(response.0.version, env!("CARGO_PKG_VERSION"));
        assert!(!response.0.platforms.is_empty());
    }

    #[tokio::test]
    async fn test_service_info_handler() {
        let response = service_info().await;

        assert_eq!(response.0.service, "VEFAS Node");
        assert_eq!(response.0.api_version, "v1");
        assert!(!response.0.endpoints.is_empty());
    }

    #[test]
    fn test_execute_request_payload_validation() {
        // Valid payload
        let mut payload = ExecuteRequestPayload {
            method: HttpMethod::Get,
            url: "https://example.com".to_string(),
            headers: HashMap::new(),
            body: None,
            proof_platform: ProofPlatform::Sp1,
            timeout_ms: 30000,
        };

        assert!(payload.validate().is_ok());

        // Invalid URL (not HTTPS)
        payload.url = "http://example.com".to_string();
        assert!(payload.validate().is_err());

        // Invalid timeout
        payload.url = "https://example.com".to_string();
        payload.timeout_ms = 500; // Too short
        assert!(payload.validate().is_err());
    }

    #[test]
    fn test_verify_proof_payload_validation() {
        use vefas_types::{VefasExecutionMetadata, VefasPerformanceMetrics};

        let performance = VefasPerformanceMetrics {
            total_cycles: 1000000,
            merkle_verification_cycles: 100000,
            http_parsing_cycles: 60000,
            crypto_operations_cycles: 240000,
            memory_usage: 2048,
        };

        let execution_metadata = VefasExecutionMetadata {
            cycles: 1000000,
            memory_usage: 2048,
            execution_time_ms: 150,
            platform: "sp1".to_string(),
            proof_time_ms: 75,
        };

        let claim = ProofClaim::new(
            "example.com".to_string(),
            "GET".to_string(),
            "/".to_string(),
            [1u8; 32], // request_commitment
            [2u8; 32], // response_commitment
            "hash123".to_string(),
            "hash456".to_string(),
            200,
            "1.3".to_string(),
            "TLS_AES_128_GCM_SHA256".to_string(),
            [3u8; 32], // certificate_chain_hash
            [4u8; 32], // handshake_transcript_hash
            [5u8; 32], // cert_fingerprint
            [6u8; 32], // proof_id
            1234567890,
            performance,
            execution_metadata,
        )
        .unwrap();

        use base64::{engine::general_purpose, Engine as _};
        let proof_data = ProofData {
            platform: "sp1".to_string(),
            proof_data: general_purpose::STANDARD.encode("mock_proof_data"),
            claim: claim.clone(),
            execution_metadata: ExecutionMetadata {
                cycles: 1000000,
                memory_usage: 1024 * 1024,
                execution_time_ms: 1000,
                proof_time_ms: 500,
                platform: "sp1".to_string(),
            },
        };

        // Create a mock bundle for testing
        use vefas_types::VefasCanonicalBundle;
        let bundle = VefasCanonicalBundle::new(
            vec![0x16, 0x03, 0x03, 0x00, 0x30], // Mock ClientHello
            vec![0x16, 0x03, 0x03, 0x00, 0x30], // Mock ServerHello
            vec![0x16, 0x03, 0x03, 0x00, 0x20], // Mock Certificate
            vec![0x16, 0x03, 0x03, 0x00, 0x10], // Mock CertificateVerify
            vec![0x16, 0x03, 0x03, 0x00, 0x10], // Mock ServerFinished
            [1u8; 32],                          // Mock private key
            vec![vec![0x30, 0x82, 0x01, 0x00]], // Mock certificate chain
            vec![0x17, 0x03, 0x03, 0x00, 0x10], // Mock encrypted_request
            vec![0x17, 0x03, 0x03, 0x00, 0x10], // Mock encrypted_response
            "example.com".to_string(),
            1234567890,
            200,
            [5u8; 32], // cert_fingerprint
        )
        .unwrap();

        let payload = VerifyProofPayload {
            proof: proof_data,
            expected_claim: Some(claim),
            bundle,
        };

        assert!(payload.validate().is_ok());
    }
}
