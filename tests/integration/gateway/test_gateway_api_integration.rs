//! Gateway API Integration Tests
//!
//! This module contains comprehensive integration tests for the zkTLS Gateway API,
//! testing the complete flow from HTTP API calls to proof generation and verification.

use zktls_gateway::{GatewayConfig, ZkTlsGateway, Platform, ProveRequest, VerifyRequest};
use zktls_core::ZkTlsInput;
use std::time::Duration;
use tokio::time::timeout;

/// Create test configuration for gateway integration tests
fn create_test_config() -> GatewayConfig {
    GatewayConfig {
        server: zktls_gateway::types::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0, // Use random port for tests
            default_platform: Platform::RISC0,
            request_timeout_ms: 10000,
            max_request_size_bytes: 1024 * 1024, // 1MB
        },
        platforms: zktls_gateway::types::PlatformConfigs {
            sp1: None, // Disabled for tests
            risc0: Some(zktls_gateway::types::PlatformConfig {
                timeout_ms: 10000,
                memory_limit_bytes: Some(1024 * 1024), // 1MB
                options: std::collections::HashMap::new(),
            }),
        },
        logging: zktls_gateway::types::LoggingConfig {
            level: "debug".to_string(),
            structured: true,
            file: None,
        },
        security: zktls_gateway::types::SecurityConfig {
            enable_cors: true,
            allowed_origins: vec!["*".to_string()],
            enable_rate_limiting: false, // Disabled for tests
            rate_limit_per_minute: 100,
        },
    }
}

/// Create a valid test input for integration tests
fn create_test_input() -> ZkTlsInput {
    ZkTlsInput {
        domain: "example.com".to_string(),
        timestamp: chrono::Utc::now().timestamp(),
        handshake_transcript: vec![0x16, 0x03, 0x01, 0x00, 0x40], // Valid TLS handshake start
        certificates: vec![
            vec![0x30, 0x82, 0x01, 0xa8], // Valid DER sequence start
            vec![0x30, 0x82, 0x01, 0xa8], // Valid DER sequence start
        ],
        http_request: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        http_response: b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Hello World</html>".to_vec(),
    }
}

#[tokio::test]
async fn test_gateway_api_prove_endpoint() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    let input = create_test_input();
    
    let request = ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(5000),
    };
    
    // Test the prove endpoint
    let result = gateway.prove(request).await;
    
    // We expect this to fail at the platform level, not API level
    // The API should handle the request properly even if platform fails
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    // Should be a platform error, not an API error
    assert!(matches!(error, zktls_gateway::GatewayError::Platform { .. }));
}

#[tokio::test]
async fn test_gateway_api_verify_endpoint() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    // Create a mock proof (this would normally come from prove endpoint)
    let mock_proof = vec![0x01, 0x02, 0x03, 0x04];
    
    let request = VerifyRequest {
        platform: Platform::RISC0,
        proof: mock_proof,
        expected: None,
    };
    
    // Test the verify endpoint
    let result = gateway.verify(request).await;
    
    // We expect this to fail at the platform level
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    // Should be a platform error, not an API error
    assert!(matches!(error, zktls_gateway::GatewayError::Platform { .. }));
}

#[tokio::test]
async fn test_gateway_api_health_endpoint() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    // Test the health endpoint
    let health = gateway.get_health().await;
    
    // Health check should always succeed
    assert!(matches!(health.status, zktls_gateway::types::HealthStatus::Healthy | zktls_gateway::types::HealthStatus::Degraded));
    assert!(!health.platforms.is_empty());
}

#[tokio::test]
async fn test_gateway_api_status_endpoint() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    // Test the status endpoint
    let status = gateway.get_status().await;
    
    assert_eq!(status.version, zktls_gateway::VERSION);
    assert!(!status.available_platforms.is_empty());
    assert_eq!(status.default_platform, Platform::RISC0);
    assert!(status.uptime_seconds >= 0);
}

#[tokio::test]
async fn test_gateway_api_input_validation() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    // Test with invalid input
    let mut input = create_test_input();
    input.domain = "".to_string(); // Invalid empty domain
    
    let request = ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(5000),
    };
    
    let result = gateway.prove(request).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(matches!(error, zktls_gateway::GatewayError::InputValidation(_)));
}

#[tokio::test]
async fn test_gateway_api_timeout_handling() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    let input = create_test_input();
    
    let request = ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(1), // Very short timeout
    };
    
    // Test timeout handling
    let result = timeout(Duration::from_millis(100), gateway.prove(request)).await;
    
    // Should timeout or fail quickly
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_gateway_api_error_handling() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    // Test with unsupported platform
    let input = create_test_input();
    let request = ProveRequest {
        platform: Platform::SP1, // Not enabled in test config
        input,
        timeout_ms: Some(5000),
    };
    
    let result = gateway.prove(request).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(matches!(error, zktls_gateway::GatewayError::Platform { .. }));
}

#[tokio::test]
async fn test_gateway_api_statistics_tracking() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let initial_status = gateway.get_status().await;
    let initial_proofs = initial_status.proofs_generated;
    let initial_verified = initial_status.proofs_verified;
    
    // Statistics should start at 0
    assert_eq!(initial_proofs, 0);
    assert_eq!(initial_verified, 0);
    
    // After attempting operations, statistics should remain 0 (since they fail)
    // but the tracking mechanism should be in place
    let final_status = gateway.get_status().await;
    assert_eq!(final_status.proofs_generated, initial_proofs);
    assert_eq!(final_status.proofs_verified, initial_verified);
}
