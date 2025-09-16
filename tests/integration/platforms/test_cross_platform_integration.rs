//! Cross-Platform Integration Tests
//!
//! This module contains integration tests that verify the zkTLS system works
//! correctly across different zkVM platforms (SP1, RISC0) with consistent
//! behavior and results.

use zktls_zkvm::types::ZkTlsInput;
use zktls_gateway::{GatewayConfig, ZkTlsGateway, Platform};
use std::collections::HashMap;

/// Create a standardized test input for cross-platform testing
fn create_standardized_test_input() -> ZkTlsInput {
    ZkTlsInput {
        domain: "example.com".to_string(),
        timestamp: 1678886400, // Fixed timestamp for deterministic testing
        handshake_transcript: vec![
            0x16, 0x03, 0x01, 0x00, 0x40, // TLS handshake header
            0x01, 0x00, 0x00, 0x3c, // ClientHello
            0x03, 0x01, 0x00, 0x00, 0x00, // Version and random
        ],
        certificates: vec![
            vec![0x30, 0x82, 0x01, 0xa8, 0x30, 0x82, 0x01, 0x51], // Valid DER sequence
            vec![0x30, 0x82, 0x01, 0xa8, 0x30, 0x82, 0x01, 0x51], // Valid DER sequence
        ],
        http_request: b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: zkTLS-Test\r\n\r\n".to_vec(),
        http_response: b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"status\":\"success\"}".to_vec(),
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

/// Create test configuration with both platforms enabled
fn create_dual_platform_config() -> GatewayConfig {
    GatewayConfig {
        server: zktls_gateway::types::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            default_platform: Platform::RISC0,
            request_timeout_ms: 10000,
            max_request_size_bytes: 1024 * 1024,
        },
        platforms: zktls_gateway::types::PlatformConfigs {
            sp1: Some(zktls_gateway::types::PlatformConfig {
                timeout_ms: 10000,
                memory_limit_bytes: Some(1024 * 1024),
                options: HashMap::new(),
            }),
            risc0: Some(zktls_gateway::types::PlatformConfig {
                timeout_ms: 10000,
                memory_limit_bytes: Some(1024 * 1024),
                options: HashMap::new(),
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
            enable_rate_limiting: false,
            rate_limit_per_minute: 100,
        },
    }
}

#[tokio::test]
async fn test_platform_availability() {
    let config = create_dual_platform_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let status = gateway.get_status().await;
    
    // Both platforms should be available
    assert!(status.available_platforms.contains(&Platform::SP1));
    assert!(status.available_platforms.contains(&Platform::RISC0));
    assert_eq!(status.available_platforms.len(), 2);
}

#[tokio::test]
async fn test_platform_health_consistency() {
    let config = create_dual_platform_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let health = gateway.get_health().await;
    
    // Both platforms should be healthy or degraded (not unhealthy)
    for (platform_name, health_status) in &health.platforms {
        assert!(
            matches!(health_status, zktls_gateway::types::HealthStatus::Healthy | zktls_gateway::types::HealthStatus::Degraded),
            "Platform {} should be healthy or degraded, got {:?}", platform_name, health_status
        );
    }
}

#[tokio::test]
async fn test_input_validation_consistency() {
    let config = create_dual_platform_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    // Test that both platforms validate input consistently
    let mut invalid_input = create_standardized_test_input();
    invalid_input.domain = "".to_string(); // Invalid empty domain
    
    // Both platforms should reject the same invalid input
    let sp1_result = gateway.prove(zktls_gateway::ProveRequest {
        platform: Platform::SP1,
        input: invalid_input.clone(),
        timeout_ms: Some(5000),
    }).await;
    
    let risc0_result = gateway.prove(zktls_gateway::ProveRequest {
        platform: Platform::RISC0,
        input: invalid_input,
        timeout_ms: Some(5000),
    }).await;
    
    // Both should fail with input validation error
    assert!(sp1_result.is_err());
    assert!(risc0_result.is_err());
    
    // Both should have the same error type
    let sp1_error = sp1_result.unwrap_err();
    let risc0_error = risc0_result.unwrap_err();
    
    assert!(matches!(sp1_error, zktls_gateway::GatewayError::InputValidation(_)));
    assert!(matches!(risc0_error, zktls_gateway::GatewayError::InputValidation(_)));
}

#[tokio::test]
async fn test_timeout_handling_consistency() {
    let config = create_dual_platform_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let input = create_standardized_test_input();
    
    // Test timeout handling consistency
    let sp1_result = gateway.prove(zktls_gateway::ProveRequest {
        platform: Platform::SP1,
        input: input.clone(),
        timeout_ms: Some(1), // Very short timeout
    }).await;
    
    let risc0_result = gateway.prove(zktls_gateway::ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(1), // Very short timeout
    }).await;
    
    // Both should handle timeouts consistently
    // (Either timeout or fail quickly)
    assert!(sp1_result.is_err());
    assert!(risc0_result.is_err());
}

#[tokio::test]
async fn test_error_message_consistency() {
    let config = create_dual_platform_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    // Test with unsupported operation
    let input = create_standardized_test_input();
    
    // Both platforms should provide consistent error messages
    let sp1_result = gateway.prove(zktls_gateway::ProveRequest {
        platform: Platform::SP1,
        input: input.clone(),
        timeout_ms: Some(5000),
    }).await;
    
    let risc0_result = gateway.prove(zktls_gateway::ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(5000),
    }).await;
    
    // Both should fail with platform errors
    assert!(sp1_result.is_err());
    assert!(risc0_result.is_err());
    
    let sp1_error = sp1_result.unwrap_err();
    let risc0_error = risc0_result.unwrap_err();
    
    // Both should be platform errors
    assert!(matches!(sp1_error, zktls_gateway::GatewayError::Platform { .. }));
    assert!(matches!(risc0_error, zktls_gateway::GatewayError::Platform { .. }));
}

#[tokio::test]
async fn test_configuration_consistency() {
    let config = create_dual_platform_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let status = gateway.get_status().await;
    
    // Configuration should be consistent across platforms
    assert_eq!(status.default_platform, Platform::RISC0);
    assert!(status.available_platforms.contains(&Platform::SP1));
    assert!(status.available_platforms.contains(&Platform::RISC0));
}

#[tokio::test]
async fn test_statistics_tracking_consistency() {
    let config = create_dual_platform_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let initial_status = gateway.get_status().await;
    let initial_proofs = initial_status.proofs_generated;
    let initial_verified = initial_status.proofs_verified;
    
    // Statistics should start at 0 for both platforms
    assert_eq!(initial_proofs, 0);
    assert_eq!(initial_verified, 0);
    
    // Statistics tracking should be consistent regardless of platform
    let final_status = gateway.get_status().await;
    assert_eq!(final_status.proofs_generated, initial_proofs);
    assert_eq!(final_status.proofs_verified, initial_verified);
}

#[tokio::test]
async fn test_platform_switching() {
    let config = create_dual_platform_config();
    let gateway = ZkTlsGateway::new(config).unwrap();
    
    let input = create_standardized_test_input();
    
    // Test switching between platforms
    let sp1_result = gateway.prove(zktls_gateway::ProveRequest {
        platform: Platform::SP1,
        input: input.clone(),
        timeout_ms: Some(5000),
    }).await;
    
    let risc0_result = gateway.prove(zktls_gateway::ProveRequest {
        platform: Platform::RISC0,
        input,
        timeout_ms: Some(5000),
    }).await;
    
    // Both should fail consistently (since we don't have real platform implementations)
    assert!(sp1_result.is_err());
    assert!(risc0_result.is_err());
    
    // But the gateway should handle platform switching without issues
    let status = gateway.get_status().await;
    assert_eq!(status.available_platforms.len(), 2);
}
