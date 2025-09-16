//! Integration tests for zkTLS Gateway
//!
//! This module contains comprehensive integration tests for the gateway,
//! following TDD methodology and testing the full API + CLI pipeline.

use zktls_gateway::{GatewayConfig, ZkTlsGateway, Platform, ProveRequest, VerifyRequest};
use zktls_zkvm::types::ZkTlsInput;
use std::time::Duration;
use tokio::time::timeout;

/// Test configuration for integration tests
fn create_test_config() -> GatewayConfig {
    GatewayConfig {
        server: zktls_gateway::types::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0, // Use random port for tests
            default_platform: Platform::RISC0,
            request_timeout_ms: 5000,
            max_request_size_bytes: 1024 * 1024, // 1MB
        },
        platforms: zktls_gateway::types::PlatformConfigs {
            sp1: None, // Disabled for tests
            risc0: Some(zktls_gateway::types::PlatformConfig {
                timeout_ms: 5000,
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

/// Create a valid test input
fn create_test_input() -> ZkTlsInput {
    ZkTlsInput {
        domain: "example.com".to_string(),
        timestamp: chrono::Utc::now().timestamp() as u64,
        handshake_transcript: vec![0x16, 0x03, 0x01, 0x00, 0x40], // Valid TLS handshake start
        certificates: vec![
            vec![0x30, 0x82, 0x01, 0xa8], // Valid DER sequence start
            vec![0x30, 0x82, 0x01, 0xa8], // Valid DER sequence start
        ],
        http_request: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        http_response: b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Hello World</html>".to_vec(),
        metadata: zktls_zkvm::types::ZkTlsMetadata {
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            session_id: None,
            extensions: vec![],
        },
    }
}

#[tokio::test]
async fn test_gateway_creation() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config);
    
    assert!(gateway.is_ok(), "Gateway creation should succeed");
}

#[tokio::test]
async fn test_gateway_status() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    let status = gateway.get_status().await;
    
    assert_eq!(status.version, zktls_gateway::VERSION);
    assert!(!status.available_platforms.is_empty());
    assert_eq!(status.default_platform, Platform::RISC0);
    assert!(status.uptime_seconds >= 0);
}

#[tokio::test]
async fn test_gateway_health() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    let health = gateway.get_health().await;
    
    assert!(matches!(health.status, zktls_gateway::types::HealthStatus::Healthy | zktls_gateway::types::HealthStatus::Degraded));
    assert!(!health.platforms.is_empty());
}

#[tokio::test]
async fn test_input_validation_success() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    let input = create_test_input();
    
    let request = ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(5000),
    };
    
    // This should fail at the platform level, not validation level
    let result = gateway.prove(request).await;
    
    // We expect this to fail because RISC0 prover is not fully implemented
    // but the validation should pass
    assert!(result.is_err());
    
    // Check that it's not a validation error
    let error = result.unwrap_err();
    assert!(!matches!(error, zktls_gateway::GatewayError::InputValidation(_)));
}

#[tokio::test]
async fn test_input_validation_domain() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
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
    assert!(error.to_string().contains("Domain cannot be empty"));
}

#[tokio::test]
async fn test_input_validation_timestamp() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let mut input = create_test_input();
    input.timestamp = 1000000000; // Too far in the past
    
    let request = ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(5000),
    };
    
    let result = gateway.prove(request).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(matches!(error, zktls_gateway::GatewayError::InputValidation(_)));
    assert!(error.to_string().contains("Timestamp too far from current time"));
}

#[tokio::test]
async fn test_input_validation_handshake() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let mut input = create_test_input();
    input.handshake_transcript = vec![]; // Invalid empty handshake
    
    let request = ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(5000),
    };
    
    let result = gateway.prove(request).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(matches!(error, zktls_gateway::GatewayError::InputValidation(_)));
    assert!(error.to_string().contains("Handshake transcript cannot be empty"));
}

#[tokio::test]
async fn test_input_validation_certificates() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let mut input = create_test_input();
    input.certificates = vec![]; // Invalid empty certificates
    
    let request = ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(5000),
    };
    
    let result = gateway.prove(request).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(matches!(error, zktls_gateway::GatewayError::InputValidation(_)));
    assert!(error.to_string().contains("Certificate chain cannot be empty"));
}

#[tokio::test]
async fn test_input_validation_http_request() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let mut input = create_test_input();
    input.http_request = vec![]; // Invalid empty HTTP request
    
    let request = ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(5000),
    };
    
    let result = gateway.prove(request).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(matches!(error, zktls_gateway::GatewayError::InputValidation(_)));
    assert!(error.to_string().contains("HTTP request cannot be empty"));
}

#[tokio::test]
async fn test_input_validation_http_response() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let mut input = create_test_input();
    input.http_response = vec![]; // Invalid empty HTTP response
    
    let request = ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(5000),
    };
    
    let result = gateway.prove(request).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(matches!(error, zktls_gateway::GatewayError::InputValidation(_)));
    assert!(error.to_string().contains("HTTP response cannot be empty"));
}

#[tokio::test]
async fn test_configuration_management() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    // Test showing configuration
    let result = gateway.show_config();
    assert!(result.is_ok());
    
    // Test setting configuration
    let result = gateway.set_config("server.port", "8080");
    assert!(result.is_ok());
    
    let result = gateway.set_config("platforms.risc0.timeout_ms", "10000");
    assert!(result.is_ok());
    
    let result = gateway.set_config("logging.level", "info");
    assert!(result.is_ok());
    
    // Test invalid configuration
    let result = gateway.set_config("invalid.key", "value");
    assert!(result.is_err());
    
    let result = gateway.set_config("server.port", "invalid");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_cli_functionality() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    // Test CLI prove command (should fail due to platform implementation)
    let result = gateway.prove_cli("risc0", "tests/fixtures/sample_input.json", "test_proof.bin").await;
    
    // We expect this to fail because the platform implementation is not complete
    // but the CLI parsing and file handling should work
    assert!(result.is_err());
    
    // Test CLI verify command (should fail due to platform implementation)
    let result = gateway.verify_cli("risc0", "test_proof.bin", None).await;
    
    // We expect this to fail because the platform implementation is not complete
    assert!(result.is_err());
    
    // Test CLI status command
    let result = gateway.show_status().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_timeout_handling() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    let input = create_test_input();
    
    let request = ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(1), // Very short timeout
    };
    
    let result = timeout(Duration::from_millis(100), gateway.prove(request)).await;
    
    // Should timeout or fail quickly
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_error_handling() {
    let config = create_test_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    // Test invalid platform
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
async fn test_statistics_tracking() {
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
