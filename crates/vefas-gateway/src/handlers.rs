//! HTTP request handlers for VEFAS Gateway endpoints

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

use crate::{error::*, types::*, VefasGatewayState};
use vefas_types::VefasCanonicalBundle;
use vefas_crypto::{FieldId, MerkleError};

/// Handle POST /requests endpoint - Execute TLS request and generate proof
#[axum::debug_handler]
#[instrument(skip(state, payload), fields(session_id, method, url = %payload.url))]
pub async fn execute_request(
    State(state): State<Arc<VefasGatewayState>>,
    Json(payload): Json<ExecuteRequestPayload>,
) -> Result<ResponseJson<ExecuteRequestResponse>, VefasGatewayError> {
    // Generate unique session ID for tracking
    let session_id = Uuid::new_v4().to_string();
    tracing::Span::current().record("session_id", &session_id);
    tracing::Span::current().record("method", &payload.method.to_string());

    info!("Processing execute request for {}", payload.url);

    // Basic request validation (minimal checks for safety)
    if !payload.url.starts_with("https://") {
        return Err(VefasGatewayError::InvalidRequest("URL must use HTTPS protocol".to_string()));
    }

    if payload.timeout_ms < 1000 || payload.timeout_ms > 300000 {
        return Err(VefasGatewayError::InvalidRequest("Timeout must be between 1 and 300 seconds".to_string()));
    }

    debug!("Basic request validation passed for session {}", session_id);

    // Execute the HTTPS request using vefas-core - returns bundle, HTTP data, and transcript bundle
    let (mut bundle, http_data, mut transcript_bundle) = {
        let headers = payload.get_headers_vec();
        let body = payload
            .get_body_bytes()
            .map_err(|e| VefasGatewayError::InvalidRequest(e))?;

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
                VefasGatewayError::VefasCore(e)
            })?
    };

    info!("Successfully captured TLS session data for {}", payload.url);

    // Build Merkle tree with 6 fields for selective disclosure + performance
    // User-verifiable (4): HttpRequest, HttpResponse, Domain, Timestamp
    // Internal (2): HandshakeProof, CryptoWitness
    // This achieves ~25% cycle reduction while enabling privacy-preserving selective disclosure
    let required_fields = vec![
        // User-verifiable fields (can be shared independently)
        FieldId::HttpRequest,      // Users can prove just the request
        FieldId::HttpResponse,     // Users can prove just the response
        FieldId::Domain,           // Users can prove which domain
        FieldId::Timestamp,        // Users can prove when
        // Internal fields (for zkVM verification)
        FieldId::HandshakeProof,   // TLS handshake validity (composite)
        FieldId::CryptoWitness,    // Crypto parameters (composite)
    ];

    debug!("Building Merkle tree with {} required fields", required_fields.len());
    transcript_bundle.build_merkle_tree(&required_fields).map_err(|e| {
        error!("Failed to build Merkle tree: {}", e);
        VefasGatewayError::VefasCore(vefas_core::VefasCoreError::tls_error(&format!("Merkle tree construction failed: {}", e)))
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
                VefasGatewayError::VefasCore(vefas_core::VefasCoreError::tls_error(&format!("Merkle proof serialization failed: {}", e)))
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
        .proof_service
        .generate_proof(&bundle, &payload.proof_platform)
        .await
        .map_err(|e| {
            error!("Proof generation failed: {}", e);
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

    // Create response
    let response = ExecuteRequestResponse {
        success: true,
        http_response,
        proof: proof_data,
        merkle_tree: merkle_tree_info,
        session_id: session_id.clone(),
    };

    info!("Request processing completed for session {}", session_id);

    Ok(ResponseJson(response))
}

/// Handle POST /verify endpoint - Verify cryptographic proof
#[axum::debug_handler]
#[instrument(skip(state, payload), fields(platform = %payload.proof.platform))]
pub async fn verify_proof(
    State(state): State<Arc<VefasGatewayState>>,
    Json(payload): Json<VerifyProofPayload>,
) -> Result<ResponseJson<VerifyProofResponse>, VefasGatewayError> {
    info!(
        "Processing proof verification request for platform: {}",
        payload.proof.platform
    );

    // Basic proof validation (minimal checks for safety)
    if !["sp1", "risc0"].contains(&payload.proof.platform.as_str()) {
        return Err(VefasGatewayError::InvalidRequest("Unsupported proof platform".to_string()));
    }

    if payload.proof.proof_data.is_empty() {
        return Err(VefasGatewayError::InvalidRequest("Proof data cannot be empty".to_string()));
    }

    debug!("Basic verification request validation passed");

    // Verify the proof
    let verification_result = state
        .proof_service
        .verify_proof(&payload.proof, payload.expected_claim.as_ref())
        .await
        .map_err(|e| {
            error!("Proof verification failed: {}", e);
            e
        })?;

    if verification_result.valid {
        info!(
            "Proof verification successful for platform: {}",
            payload.proof.platform
        );
    } else {
        warn!(
            "Proof verification failed for platform: {}",
            payload.proof.platform
        );
    }

    // Create response
    let response = VerifyProofResponse {
        success: true,
        verification_result,
    };

    Ok(ResponseJson(response))
}

/// Handle GET /health endpoint - Health check
#[instrument(skip(state))]
pub async fn health_check(
    State(state): State<Arc<VefasGatewayState>>,
) -> ResponseJson<HealthResponse> {
    debug!("Processing health check request");

    let platforms = state.proof_service.available_platforms();

    let response = HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        platforms,
    };

    ResponseJson(response)
}

/// Handle GET / endpoint - Root information
#[instrument]
pub async fn root() -> ResponseJson<RootResponse> {
    debug!("Processing root request");

    let response = RootResponse {
        service: "VEFAS Gateway".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        api_version: "v1".to_string(),
        endpoints: vec![
            "POST /api/v1/requests".to_string(),
            "POST /api/v1/verify".to_string(),
            "GET /api/v1/health".to_string(),
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

    async fn create_test_state() -> Arc<VefasGatewayState> {
        use crate::VefasGatewayConfig;
        VefasGatewayState::new(VefasGatewayConfig::default())
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
    async fn test_root_handler() {
        let response = root().await;

        assert_eq!(response.0.service, "VEFAS Gateway");
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
            decompression_cycles: 50000,
            validation_cycles: 100000,
            handshake_cycles: 200000,
            certificate_validation_cycles: 150000,
            key_derivation_cycles: 80000,
            decryption_cycles: 120000,
            http_parsing_cycles: 60000,
            crypto_operations_cycles: 240000,
            memory_usage: 2048,
            compression_ratio: Some(0.7),
            original_bundle_size: Some(4096),
            decompressed_bundle_size: Some(2867),
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

        let payload = VerifyProofPayload {
            proof: proof_data,
            expected_claim: Some(claim),
        };

        assert!(payload.validate().is_ok());
    }
}
