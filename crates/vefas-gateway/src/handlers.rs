//! HTTP request handlers for VEFAS Gateway endpoints

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use axum::{
    extract::{State, Json},
    http::{StatusCode, HeaderMap},
    response::Json as ResponseJson,
};
use tracing::{info, error, debug, warn, instrument};
use uuid::Uuid;
use chrono::Utc;

use crate::{
    VefasGatewayState,
    types::*,
    error::*,
};
use vefas_types::VefasCanonicalBundle;

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

    // Validate the request payload
    payload.validate()
        .map_err(|e| VefasGatewayError::InvalidRequest(e))?;

    debug!("Request validation passed for session {}", session_id);

    // Execute the HTTPS request using vefas-core - this returns a complete VefasCanonicalBundle
    let bundle = {
        let headers = payload.get_headers_vec();
        let body = payload.get_body_bytes()
            .map_err(|e| VefasGatewayError::InvalidRequest(e))?;

        // Convert headers to the format expected by vefas-core
        let headers_str_refs: Option<Vec<(&str, &str)>> = headers.as_ref().map(|h| {
            h.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
        });

        debug!("Executing HTTPS request via vefas-core");
        state.vefas_client
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

    // Extract HTTP response data from the VefasCanonicalBundle (vefas-core already processed it)
    let http_response = HttpResponseData {
        status_code: bundle.expected_status,
        headers: std::collections::HashMap::new(),
        body: String::new(), // For now, body extraction would require TLS record decryption
    };

    debug!("HTTP response extracted: status={}, body_size={}",
           http_response.status_code, http_response.body.len());

    // Generate cryptographic proof
    let proof_data = state.proof_service
        .generate_proof(&bundle, &payload.proof_platform)
        .await
        .map_err(|e| {
            error!("Proof generation failed: {}", e);
            e
        })?;

    info!("Successfully generated proof using {} platform", proof_data.platform);

    // Create response
    let response = ExecuteRequestResponse {
        success: true,
        http_response,
        proof: proof_data,
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
    info!("Processing proof verification request for platform: {}", payload.proof.platform);

    // Validate the request payload
    payload.validate()
        .map_err(|e| VefasGatewayError::InvalidRequest(e))?;

    debug!("Verification request validation passed");

    // Verify the proof
    let verification_result = state.proof_service
        .verify_proof(&payload.proof, payload.expected_claim.as_ref())
        .await
        .map_err(|e| {
            error!("Proof verification failed: {}", e);
            e
        })?;

    if verification_result.valid {
        info!("Proof verification successful for platform: {}", payload.proof.platform);
    } else {
        warn!("Proof verification failed for platform: {}", payload.proof.platform);
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
    use tower::ServiceExt;
    use axum::http::{Request, Method};
    use std::collections::HashMap;

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
        let claim = ProofClaim {
            domain: "example.com".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            request_hash: "hash123".to_string(),
            response_hash: "hash456".to_string(),
            timestamp: 1234567890,
            status_code: 200,
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            certificate_chain_hash: String::new(),
            handshake_transcript_hash: String::new(),
        };

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