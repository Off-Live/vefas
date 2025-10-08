//! VEFAS Gateway - Production-grade HTTP API for zkTLS verification
//!
//! This crate provides a high-performance HTTP gateway with two core endpoints:
//! - POST /requests: Execute TLS request and generate cryptographic proof
//! - POST /verify: Verify proof authenticity
//!
//! Built on axum for production-grade performance, observability, and reliability.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Json, State},
    response::Json as ResponseJson,
    routing::{get, post},
    Router,
};
use tower_http::cors::CorsLayer;
use tracing::{info, instrument};

use vefas_core::{VefasClient, VefasCoreError};
use vefas_types::VefasCanonicalBundle;

pub mod error;
pub mod handlers;
pub mod proof;
pub mod types;

pub use error::*;
pub use handlers::*;
pub use proof::*;
pub use types::*;

/// VEFAS Gateway configuration
#[derive(Debug, Clone)]
pub struct VefasGatewayConfig {
    /// Maximum request body size in bytes (default: 10MB)
    pub max_request_size: usize,
    /// Request timeout in seconds (default: 30)
    pub request_timeout: u64,
    /// Enable CORS (default: true)
    pub enable_cors: bool,
    /// Maximum requests per minute per IP (default: 10)
    pub rate_limit: u64,
    /// Server bind address (default: "0.0.0.0:3000")
    pub bind_address: String,
}

impl Default for VefasGatewayConfig {
    fn default() -> Self {
        Self {
            max_request_size: 10 * 1024 * 1024, // 10MB
            request_timeout: 30,
            enable_cors: true,
            rate_limit: 10,
            bind_address: "0.0.0.0:3000".to_string(),
        }
    }
}

/// VEFAS Gateway application state
#[derive(Debug)]
pub struct VefasGatewayState {
    pub config: VefasGatewayConfig,
    pub vefas_client: Arc<VefasClient>,
    pub proof_service: Arc<ProofService>,
}

impl VefasGatewayState {
    /// Create new gateway state
    pub async fn new(config: VefasGatewayConfig) -> Result<Self, VefasGatewayError> {
        // Use real client for production with real servers
        // The client ephemeral private key will be captured during the TLS handshake
        let vefas_client = VefasClient::new().map_err(|e| {
            VefasGatewayError::Initialization(format!("Failed to create VEFAS client: {}", e))
        })?;

        let proof_service = ProofService::new().await.map_err(|e| {
            VefasGatewayError::Initialization(format!("Failed to create proof service: {}", e))
        })?;

        Ok(Self {
            config,
            vefas_client: Arc::new(vefas_client),
            proof_service: Arc::new(proof_service),
        })
    }
}

/// VEFAS Gateway server
pub struct VefasGateway {
    state: Arc<VefasGatewayState>,
}

impl VefasGateway {
    /// Create a new VEFAS gateway
    pub async fn new(config: VefasGatewayConfig) -> Result<Self, VefasGatewayError> {
        let state = VefasGatewayState::new(config).await?;

        Ok(Self {
            state: Arc::new(state),
        })
    }

    /// Create a new VEFAS gateway with default configuration
    pub async fn with_defaults() -> Result<Self, VefasGatewayError> {
        Self::new(VefasGatewayConfig::default()).await
    }

    /// Build the axum router with all routes and middleware
    pub fn router(&self) -> Router {
        // Create the main API router
        let api_router = Router::new()
            .route("/requests", post(handlers::execute_request))
            .route("/verify", post(handlers::verify_proof))
            .route("/health", get(handlers::health_check))
            .with_state(self.state.clone());

        // Build the main router with minimal middleware
        Router::new()
            .nest("/api/v1", api_router)
            .route("/", get(handlers::root))
            .layer(if self.state.config.enable_cors {
                CorsLayer::very_permissive()
            } else {
                CorsLayer::new()
            })
    }

    /// Start the HTTP server
    #[instrument(skip(self))]
    pub async fn serve(&self) -> Result<(), VefasGatewayError> {
        let addr: SocketAddr = self.state.config.bind_address.parse().map_err(|e| {
            VefasGatewayError::Configuration(format!("Invalid bind address: {}", e))
        })?;

        let router = self.router();

        info!("Starting VEFAS Gateway server on {}", addr);
        info!("Configuration: {:?}", self.state.config);

        let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
            VefasGatewayError::Network(format!("Failed to bind to {}: {}", addr, e))
        })?;

        info!("VEFAS Gateway listening on {}", addr);

        axum::serve(listener, router)
            .await
            .map_err(|e| VefasGatewayError::Network(format!("Server error: {}", e)))?;

        Ok(())
    }

    /// Get the gateway state (for testing)
    pub fn state(&self) -> &Arc<VefasGatewayState> {
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_gateway_creation() {
        let config = VefasGatewayConfig::default();
        let gateway = VefasGateway::new(config).await;
        assert!(gateway.is_ok(), "Gateway should be created successfully");
    }

    #[tokio::test]
    async fn test_router_health_check() {
        let gateway = VefasGateway::with_defaults().await.unwrap();
        let router = gateway.router();

        let request = Request::builder()
            .uri("/api/v1/health")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_router_root() {
        let gateway = VefasGateway::with_defaults().await.unwrap();
        let router = gateway.router();

        let request = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
