//! HTTP API server implementation
//!
//! This module implements the HTTP server for the zkTLS gateway API,
//! providing REST endpoints for proof generation and verification.

use crate::{GatewayConfig, GatewayError, ZkTlsGateway, error::ErrorResponse};
use axum::{
    extract::State,
    http::{StatusCode, HeaderMap, HeaderValue},
    response::{Json, Response},
    routing::{get, post},
    Router, middleware,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
    compression::CompressionLayer,
    limit::RequestBodyLimitLayer,
};
use tracing::{info, error, warn};
use uuid::Uuid;

/// API server state
pub struct ApiState {
    pub gateway: Arc<ZkTlsGateway>,
    pub config: GatewayConfig,
}

/// HTTP API server
pub struct ApiServer {
    state: Arc<ApiState>,
    router: Router,
}

impl ApiServer {
    /// Create a new API server
    pub fn new(gateway: Arc<ZkTlsGateway>, config: GatewayConfig) -> Self {
        let state = Arc::new(ApiState {
            gateway: gateway.clone(),
            config: config.clone(),
        });
        
        let router = Self::create_router(state.clone());
        
        Self { state, router }
    }
    
    /// Create the API router
    fn create_router(state: Arc<ApiState>) -> Router {
        Router::new()
            // Health and status endpoints
            .route("/health", get(health_handler))
            .route("/status", get(status_handler))
            .route("/api/v1/platforms", get(platforms_handler))
            
            // Core API endpoints
            .route("/api/v1/prove", post(prove_handler))
            .route("/api/v1/verify", post(verify_handler))
            
            // Middleware stack
            .layer(TraceLayer::new_for_http())
            .layer(RequestBodyLimitLayer::new(state.config.server.max_request_size_bytes))
            .layer(CompressionLayer::new())
            .layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods(Any)
                    .allow_headers(Any)
                    .max_age(std::time::Duration::from_secs(3600)),
            )
            .layer(middleware::from_fn(error_handler_middleware))
            .with_state(state)
    }
    
    /// Start the API server
    pub async fn start(&self, host: &str, port: u16) -> Result<(), GatewayError> {
        let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port))
            .await
            .map_err(|e| GatewayError::http_server(format!("Failed to bind to {}:{}: {}", host, port, e)))?;
        
        info!("🚀 zkTLS Gateway API server starting on {}:{}", host, port);
        info!("📋 Available endpoints:");
        info!("  GET  /health           - Health check");
        info!("  GET  /status          - Gateway status");
        info!("  GET  /api/v1/platforms - Available platforms");
        info!("  POST /api/v1/prove     - Generate proof");
        info!("  POST /api/v1/verify    - Verify proof");
        
        axum::serve(listener, self.router.clone())
            .await
            .map_err(|e| GatewayError::http_server(format!("Server error: {}", e)))?;
        
        Ok(())
    }
    
    /// Get the router for testing
    pub fn router(&self) -> Router {
        self.router.clone()
    }
}

/// Error handling middleware
async fn error_handler_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, StatusCode> {
    let request_id = Uuid::new_v4().to_string();
    
    // Add request ID to headers
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());
    
    // Process request
    let response = next.run(request).await;
    
    // Log request completion
    info!("Request {} completed with status: {}", request_id, response.status());
    
    Ok(response)
}

/// Health check handler
async fn health_handler(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<crate::types::HealthResponse>, StatusCode> {
    let request_id = Uuid::new_v4().to_string();
    
    let health = state.gateway.get_health().await;
    info!("Health check completed successfully (request: {})", request_id);
    Ok(Json(health))
}

/// Status handler
async fn status_handler(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<crate::types::GatewayStatus>, StatusCode> {
    let request_id = Uuid::new_v4().to_string();
    
    let status = state.gateway.get_status().await;
    info!("Status check completed successfully (request: {})", request_id);
    Ok(Json(status))
}

/// Platforms handler
async fn platforms_handler(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<Vec<crate::types::Platform>>, StatusCode> {
    let request_id = Uuid::new_v4().to_string();
    let platforms = state.config.get_available_platforms();
    
    info!("Platforms list requested (request: {}): {:?}", request_id, platforms);
    Ok(Json(platforms))
}

/// Prove handler
async fn prove_handler(
    State(state): State<Arc<ApiState>>,
    Json(request): Json<crate::types::ProveRequest>,
) -> Result<Json<crate::types::ProveResponse>, StatusCode> {
    let request_id = Uuid::new_v4().to_string();
    
    info!("Proof generation requested (request: {}, platform: {})", request_id, request.platform);
    
    match state.gateway.prove(request).await {
        Ok(response) => {
            info!("Proof generation completed successfully (request: {}, size: {} bytes)", 
                  request_id, response.metadata.size_bytes);
            Ok(Json(response))
        },
        Err(e) => {
            error!("Proof generation failed (request: {}): {}", request_id, e);
            
            // Return appropriate error response
            let error_response = ErrorResponse::new(
                "PROOF_GENERATION_ERROR",
                e.to_string()
            ).with_request_id(request_id);
            
            Err(StatusCode::from_u16(e.http_status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// Verify handler
async fn verify_handler(
    State(state): State<Arc<ApiState>>,
    Json(request): Json<crate::types::VerifyRequest>,
) -> Result<Json<crate::types::VerifyResponse>, StatusCode> {
    let request_id = Uuid::new_v4().to_string();
    
    info!("Proof verification requested (request: {}, platform: {}, proof_size: {} bytes)", 
          request_id, request.platform, request.proof.len());
    
    match state.gateway.verify(request).await {
        Ok(response) => {
            info!("Proof verification completed successfully (request: {}, verified: {})", 
                  request_id, response.verified);
            Ok(Json(response))
        },
        Err(e) => {
            error!("Proof verification failed (request: {}): {}", request_id, e);
            
            // Return appropriate error response
            let error_response = ErrorResponse::new(
                "PROOF_VERIFICATION_ERROR",
                e.to_string()
            ).with_request_id(request_id);
            
            Err(StatusCode::from_u16(e.http_status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GatewayConfig, ZkTlsGateway};

    #[tokio::test]
    async fn test_api_server_creation() {
        let config = GatewayConfig::default();
        let gateway = Arc::new(ZkTlsGateway::new(config.clone()).await.unwrap());
        let server = ApiServer::new(gateway, config);
        
        // Test that router is created successfully
        let _router = server.router();
    }
}
