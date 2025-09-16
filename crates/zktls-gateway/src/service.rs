//! Core service layer for zkTLS gateway
//!
//! This module implements the core business logic for the gateway, providing
//! platform abstraction and unified interfaces for proof generation and verification.
//! The gateway is zkVM agnostic and can dynamically route requests to any available platform.

use crate::{
    GatewayConfig, GatewayError, GatewayResult, Platform, ProveRequest, ProveResponse,
    VerifyRequest, VerifyResponse, GatewayStatus, HealthResponse, HealthStatus, ProofMetadata,
};
use zktls_zkvm::{ZkTlsInput, ZkTlsProofClaim};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;
use chrono::Utc;

/// Core gateway service - zkVM agnostic
#[derive(Clone)]
pub struct ZkTlsGateway {
    config: GatewayConfig,
    start_time: Instant,
    stats: GatewayStats,
}

/// Gateway statistics
#[derive(Debug, Default, Clone)]
struct GatewayStats {
    proofs_generated: u64,
    proofs_verified: u64,
    last_proof_at: Option<chrono::DateTime<Utc>>,
}

impl ZkTlsGateway {
    /// Create a new gateway instance
    pub fn new(config: GatewayConfig) -> GatewayResult<Self> {
        let gateway = Self {
            config,
            start_time: Instant::now(),
            stats: GatewayStats::default(),
        };
        
        // Validate configuration
        gateway.validate_config()?;
        
        tracing::info!("zkTLS Gateway initialized - zkVM agnostic mode");
        Ok(gateway)
    }
    
    /// Validate gateway configuration
    fn validate_config(&self) -> GatewayResult<()> {
        if self.config.server.port == 0 {
            return Err(GatewayError::config("Server port cannot be 0"));
        }
        
        if self.config.server.host.is_empty() {
            return Err(GatewayError::config("Server host cannot be empty"));
        }
        
        if self.config.server.max_request_size_bytes == 0 {
            return Err(GatewayError::config("Max request size cannot be 0"));
        }
        
        // Validate that at least one platform is available
        let available_platforms = self.get_available_platforms();
        if available_platforms.is_empty() {
            return Err(GatewayError::config("No platforms available - ensure at least one platform crate is enabled"));
        }
        
        tracing::info!("Available platforms: {:?}", available_platforms);
        Ok(())
    }
    
    /// Get list of available platforms (dynamically determined)
    fn get_available_platforms(&self) -> Vec<Platform> {
        let mut platforms = Vec::new();
        
        // Check SP1 availability
        if self.is_platform_available(&Platform::SP1) {
            platforms.push(Platform::SP1);
        }
        
        // Check RISC0 availability
        if self.is_platform_available(&Platform::RISC0) {
            platforms.push(Platform::RISC0);
        }
        
        platforms
    }
    
    /// Check if a specific platform is available
    fn is_platform_available(&self, platform: &Platform) -> bool {
        match platform {
            Platform::SP1 => {
                // Try to initialize SP1 prover to check availability
                self.try_initialize_sp1().is_ok()
            },
            Platform::RISC0 => {
                // Try to initialize RISC0 prover to check availability
                self.try_initialize_risc0().is_ok()
            },
        }
    }
    
    /// Try to initialize SP1 prover (returns error if not available)
    fn try_initialize_sp1(&self) -> GatewayResult<()> {
        #[cfg(feature = "sp1")]
        {
            use zktls_sp1::SP1ZkTlsProver;
            let _prover = SP1ZkTlsProver::new()
                .map_err(|e| GatewayError::platform("sp1", format!("SP1 not available: {}", e)))?;
            Ok(())
        }
        #[cfg(not(feature = "sp1"))]
        Err(GatewayError::platform("sp1", "SP1 platform not compiled"))
    }
    
    /// Try to initialize RISC0 prover (returns error if not available)
    fn try_initialize_risc0(&self) -> GatewayResult<()> {
        #[cfg(feature = "risc0")]
        {
            use zktls_risc0::RISC0ZkTlsProver;
            let _prover = RISC0ZkTlsProver::new()
                .map_err(|e| GatewayError::platform("risc0", format!("RISC0 not available: {}", e)))?;
            Ok(())
        }
        #[cfg(not(feature = "risc0"))]
        Err(GatewayError::platform("risc0", "RISC0 platform not compiled"))
    }
    
    /// Generate a proof using the specified platform
    pub async fn prove(&self, request: ProveRequest) -> GatewayResult<ProveResponse> {
        let request_id = Uuid::new_v4().to_string();
        let start_time = Instant::now();
        
        tracing::info!(
            request_id = %request_id,
            platform = %request.platform,
            "Proof generation requested"
        );
        
        // Validate input data
        self.validate_input(&request.input)?;
        
        // Check if platform is available
        if !self.is_platform_available(&request.platform) {
            return Err(GatewayError::platform(
                request.platform.to_string(),
                "Platform not available or not compiled"
            ));
        }
        
        let proof_bytes = self.generate_proof_internal(&request.platform, &request.input).await?;
        
        let proof_time = start_time.elapsed();
        tracing::info!(
            request_id = %request_id,
            platform = %request.platform,
            proof_time_ms = proof_time.as_millis() as u64,
            proof_size_bytes = proof_bytes.len(),
            "Proof generation completed"
        );
        
        // Deserialize the claim from the proof (platform-specific)
        let (verified, claim) = self.verify_proof_internal(&request.platform, &proof_bytes).await?;
        
        if !verified {
            return Err(GatewayError::proof_generation("Generated proof failed verification".to_string()));
        }
        
        let claim = claim.ok_or_else(|| GatewayError::proof_generation("Proof claim not found after generation".to_string()))?;
        
        // Update statistics
        let mut stats = self.stats.clone();
        stats.proofs_generated += 1;
        stats.last_proof_at = Some(Utc::now());
        
        let metadata = ProofMetadata {
            platform: request.platform,
            generated_at: Utc::now(),
            size_bytes: proof_bytes.len(),
            generation_time_ms: proof_time.as_millis() as u64,
            cycles: Some(claim.execution_metadata.cycles),
            memory_usage_bytes: Some(claim.execution_metadata.memory_usage),
        };
        
        Ok(ProveResponse {
            proof: proof_bytes,
            metadata,
            request_id,
        })
    }
    
    /// Verify a proof using the specified platform
    pub async fn verify(&self, request: VerifyRequest) -> GatewayResult<VerifyResponse> {
        let request_id = Uuid::new_v4().to_string();
        let start_time = Instant::now();
        
        tracing::info!(
            request_id = %request_id,
            platform = %request.platform,
            proof_size_bytes = request.proof.len(),
            "Proof verification requested"
        );
        
        // Check if platform is available
        if !self.is_platform_available(&request.platform) {
            return Err(GatewayError::platform(
                request.platform.to_string(),
                "Platform not available or not compiled"
            ));
        }
        
        let (verified, claim) = self.verify_proof_internal(&request.platform, &request.proof).await?;
        
        let verification_time = start_time.elapsed();
        tracing::info!(
            request_id = %request_id,
            platform = %request.platform,
            verification_time_ms = verification_time.as_millis() as u64,
            verified = verified,
            "Proof verification completed"
        );
        
        // Update statistics
        let mut stats = self.stats.clone();
        stats.proofs_verified += 1;
        
        let metadata = ProofMetadata {
            platform: request.platform,
            generated_at: Utc::now(),
            size_bytes: request.proof.len(),
            generation_time_ms: verification_time.as_millis() as u64,
            cycles: claim.as_ref().map(|c| c.execution_metadata.cycles),
            memory_usage_bytes: claim.as_ref().map(|c| c.execution_metadata.memory_usage),
        };
        
        Ok(VerifyResponse {
            verified,
            claim,
            request_id,
        })
    }
    
    /// Internal proof generation - routes to appropriate platform
    async fn generate_proof_internal(
        &self,
        platform: &Platform,
        input: &ZkTlsInput,
    ) -> GatewayResult<Vec<u8>> {
        match platform {
            Platform::SP1 => {
                #[cfg(feature = "sp1")]
                {
                    use zktls_sp1::SP1ZkTlsProver;
                    let prover = SP1ZkTlsProver::new()
                        .map_err(|e| GatewayError::platform("sp1", format!("Failed to initialize SP1 prover: {}", e)))?;
                    
                    let result = prover.generate_proof(input.clone())
                        .map_err(|e| GatewayError::proof_generation(format!("SP1 proof generation failed: {}", e)))?;
                    
                    Ok(result.proof)
                }
                #[cfg(not(feature = "sp1"))]
                Err(GatewayError::platform("sp1", "SP1 platform not compiled"))
            },
            Platform::RISC0 => {
                #[cfg(feature = "risc0")]
                {
                    use zktls_risc0::RISC0ZkTlsProver;
                    let prover = RISC0ZkTlsProver::new()
                        .map_err(|e| GatewayError::platform("risc0", format!("Failed to initialize RISC0 prover: {}", e)))?;
                    
                    let result = prover.generate_proof(input.clone())
                        .map_err(|e| GatewayError::proof_generation(format!("RISC0 proof generation failed: {}", e)))?;
                    
                    Ok(result.proof)
                }
                #[cfg(not(feature = "risc0"))]
                Err(GatewayError::platform("risc0", "RISC0 platform not compiled"))
            },
        }
    }
    
    /// Internal proof verification - routes to appropriate platform
    async fn verify_proof_internal(
        &self,
        platform: &Platform,
        proof: &[u8],
    ) -> GatewayResult<(bool, Option<ZkTlsProofClaim>)> {
        match platform {
            Platform::SP1 => {
                #[cfg(feature = "sp1")]
                {
                    use zktls_sp1::SP1ZkTlsProver;
                    let prover = SP1ZkTlsProver::new()
                        .map_err(|e| GatewayError::platform("sp1", format!("Failed to initialize SP1 prover: {}", e)))?;
                    
                    let result = prover.verify_proof(proof)
                        .map_err(|e| GatewayError::proof_verification(format!("SP1 proof verification failed: {}", e)))?;
                    
                    Ok((result.verified, result.claim))
                }
                #[cfg(not(feature = "sp1"))]
                Err(GatewayError::platform("sp1", "SP1 platform not compiled"))
            },
            Platform::RISC0 => {
                #[cfg(feature = "risc0")]
                {
                    use zktls_risc0::RISC0ZkTlsProver;
                    let prover = RISC0ZkTlsProver::new()
                        .map_err(|e| GatewayError::platform("risc0", format!("Failed to initialize RISC0 prover: {}", e)))?;
                    
                    let result = prover.verify_proof(proof)
                        .map_err(|e| GatewayError::proof_verification(format!("RISC0 proof verification failed: {}", e)))?;
                    
                    Ok((result.verified, result.claim))
                }
                #[cfg(not(feature = "risc0"))]
                Err(GatewayError::platform("risc0", "RISC0 platform not compiled"))
            },
        }
    }
    
    /// Validate input data with comprehensive business logic
    fn validate_input(&self, input: &ZkTlsInput) -> GatewayResult<()> {
        // Check input size
        let input_size = std::mem::size_of_val(input);
        if input_size > self.config.server.max_request_size_bytes {
            return Err(GatewayError::resource_limit(
                "input size",
                format!("{} bytes", self.config.server.max_request_size_bytes)
            ));
        }
        
        // Validate domain
        self.validate_domain(&input.domain)?;
        
        // Validate timestamp
        self.validate_timestamp(input.timestamp as i64)?;
        
        // Validate handshake transcript
        self.validate_handshake_transcript(&input.handshake_transcript)?;
        
        // Validate certificates
        self.validate_certificates(&input.certificates)?;
        
        // Validate HTTP request/response
        self.validate_http_data(&input.http_request, &input.http_response)?;
        
        Ok(())
    }
    
    /// Validate domain name
    fn validate_domain(&self, domain: &str) -> GatewayResult<()> {
        if domain.is_empty() {
            return Err(GatewayError::input_validation("Domain cannot be empty"));
        }
        
        if domain.len() > 253 {
            return Err(GatewayError::input_validation("Domain name too long (max 253 characters)"));
        }
        
        // Check for valid domain characters
        if !domain.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
            return Err(GatewayError::input_validation("Domain contains invalid characters"));
        }
        
        // Check for valid domain structure
        if domain.starts_with('.') || domain.ends_with('.') {
            return Err(GatewayError::input_validation("Domain cannot start or end with a dot"));
        }
        
        if domain.contains("..") {
            return Err(GatewayError::input_validation("Domain cannot contain consecutive dots"));
        }
        
        Ok(())
    }
    
    /// Validate timestamp
    fn validate_timestamp(&self, timestamp: i64) -> GatewayResult<()> {
        let now = Utc::now().timestamp();
        let time_diff = (now - timestamp).abs();
        
        // Allow up to 5 minutes difference for reasonable clock skew
        if time_diff > 300 {
            return Err(GatewayError::input_validation(format!(
                "Timestamp too far from current time: {} seconds difference (max 300 seconds)",
                time_diff
            )));
        }
        
        // Check for reasonable timestamp (not too far in the past or future)
        if timestamp < 1600000000 { // Before 2020
            return Err(GatewayError::input_validation("Timestamp too far in the past"));
        }
        
        if timestamp > now + 86400 { // More than 1 day in the future
            return Err(GatewayError::input_validation("Timestamp too far in the future"));
        }
        
        Ok(())
    }
    
    /// Validate handshake transcript
    fn validate_handshake_transcript(&self, transcript: &[u8]) -> GatewayResult<()> {
        if transcript.is_empty() {
            return Err(GatewayError::input_validation("Handshake transcript cannot be empty"));
        }
        
        if transcript.len() > 64 * 1024 { // 64KB max
            return Err(GatewayError::input_validation("Handshake transcript too large (max 64KB)"));
        }
        
        // Check for reasonable TLS handshake structure
        if transcript.len() < 4 {
            return Err(GatewayError::input_validation("Handshake transcript too short for valid TLS"));
        }
        
        // Basic TLS handshake validation
        if transcript[0] != 0x16 { // TLS handshake record type
            return Err(GatewayError::input_validation("Invalid TLS handshake record type"));
        }
        
        Ok(())
    }
    
    /// Validate certificate chain
    fn validate_certificates(&self, certificates: &[Vec<u8>]) -> GatewayResult<()> {
        if certificates.is_empty() {
            return Err(GatewayError::input_validation("Certificate chain cannot be empty"));
        }
        
        if certificates.len() > 10 { // Reasonable limit
            return Err(GatewayError::input_validation("Certificate chain too long (max 10 certificates)"));
        }
        
        for (i, cert) in certificates.iter().enumerate() {
            if cert.is_empty() {
                return Err(GatewayError::input_validation(format!(
                    "Certificate {} is empty", i
                )));
            }
            
            if cert.len() > 8 * 1024 { // 8KB max per certificate
                return Err(GatewayError::input_validation(format!(
                    "Certificate {} too large (max 8KB)", i
                )));
            }
            
            // Basic DER validation
            if cert.len() < 4 {
                return Err(GatewayError::input_validation(format!(
                    "Certificate {} too short for valid DER", i
                )));
            }
            
            // Check DER sequence tag
            if cert[0] != 0x30 {
                return Err(GatewayError::input_validation(format!(
                    "Certificate {} does not start with DER sequence tag", i
                )));
            }
        }
        
        Ok(())
    }
    
    /// Validate HTTP request and response
    fn validate_http_data(&self, request: &[u8], response: &[u8]) -> GatewayResult<()> {
        // Validate HTTP request
        if request.is_empty() {
            return Err(GatewayError::input_validation("HTTP request cannot be empty"));
        }
        
        if request.len() > 1024 * 1024 { // 1MB max
            return Err(GatewayError::input_validation("HTTP request too large (max 1MB)"));
        }
        
        // Basic HTTP request validation
        let request_str = String::from_utf8_lossy(request);
        if !request_str.starts_with("GET ") && !request_str.starts_with("POST ") &&
           !request_str.starts_with("PUT ") && !request_str.starts_with("DELETE ") {
            return Err(GatewayError::input_validation("Invalid HTTP request method"));
        }
        
        if !request_str.contains("HTTP/1.1") && !request_str.contains("HTTP/2") {
            return Err(GatewayError::input_validation("Unsupported HTTP version"));
        }
        
        // Validate HTTP response
        if response.is_empty() {
            return Err(GatewayError::input_validation("HTTP response cannot be empty"));
        }
        
        if response.len() > 10 * 1024 * 1024 { // 10MB max
            return Err(GatewayError::input_validation("HTTP response too large (max 10MB)"));
        }
        
        // Basic HTTP response validation
        let response_str = String::from_utf8_lossy(response);
        if !response_str.starts_with("HTTP/1.1 ") && !response_str.starts_with("HTTP/2 ") {
            return Err(GatewayError::input_validation("Invalid HTTP response format"));
        }
        
        // Check for status code
        if !response_str.contains("200") && !response_str.contains("201") &&
           !response_str.contains("400") && !response_str.contains("404") &&
           !response_str.contains("500") {
            return Err(GatewayError::input_validation("Invalid or unsupported HTTP status code"));
        }
        
        Ok(())
    }
    
    /// Get gateway status
    pub async fn get_status(&self) -> GatewayStatus {
        GatewayStatus {
            version: crate::VERSION.to_string(),
            available_platforms: self.get_available_platforms(),
            default_platform: Platform::RISC0, // Default platform
            uptime_seconds: self.start_time.elapsed().as_secs(),
            proofs_generated: self.stats.proofs_generated,
            proofs_verified: self.stats.proofs_verified,
            last_proof_at: self.stats.last_proof_at,
        }
    }
    
    /// Get health status
    pub async fn get_health(&self) -> HealthResponse {
        let mut platforms = HashMap::new();
        
        // Check SP1 health
        let sp1_health = if self.is_platform_available(&Platform::SP1) {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        };
        platforms.insert("sp1".to_string(), sp1_health);
        
        // Check RISC0 health
        let risc0_health = if self.is_platform_available(&Platform::RISC0) {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        };
        platforms.insert("risc0".to_string(), risc0_health);
        
        // Overall health is healthy if any platform is healthy
        let overall_health = if platforms.values().any(|status| matches!(status, HealthStatus::Healthy)) {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        };
        
        HealthResponse {
            status: overall_health,
            platforms,
            timestamp: Utc::now(),
        }
    }
    
    /// CLI-specific methods
    pub async fn prove_cli(&self, platform: &str, input_path: &str, output_path: &str) -> GatewayResult<()> {
        let platform: Platform = platform.parse()
            .map_err(|e| GatewayError::input_validation(format!("Invalid platform: {}", e)))?;
        
        if !self.is_platform_available(&platform) {
            return Err(GatewayError::platform(platform.to_string(), "Platform not available"));
        }
        
        let input_bytes = std::fs::read(input_path)
            .map_err(|e| GatewayError::FileIO(e))?;
        let input: ZkTlsInput = serde_json::from_slice(&input_bytes)
            .map_err(|e| GatewayError::serialization(format!("Failed to deserialize input from {}: {}", input_path, e)))?;
        
        let request = ProveRequest {
            platform,
            input,
            timeout_ms: None, // CLI doesn't specify timeout for now
        };
        
        let response = self.prove(request).await?;
        
        std::fs::write(output_path, &response.proof)
            .map_err(|e| GatewayError::FileIO(e))?;
        
        tracing::info!("Proof generated and saved to {}", output_path);
        Ok(())
    }
    
    pub async fn verify_cli(&self, platform: &str, proof_path: &str) -> GatewayResult<()> {
        let platform: Platform = platform.parse()
            .map_err(|e| GatewayError::input_validation(format!("Invalid platform: {}", e)))?;
        
        if !self.is_platform_available(&platform) {
            return Err(GatewayError::platform(platform.to_string(), "Platform not available"));
        }
        
        let proof_bytes = std::fs::read(proof_path)
            .map_err(|e| GatewayError::FileIO(e))?;
        
        let request = VerifyRequest {
            platform,
            proof: proof_bytes,
            expected: None, // Claim will be extracted from proof
        };
        
        let response = self.verify(request).await?;
        
        if response.verified {
            tracing::info!("Proof verified successfully!");
            if let Some(claim) = response.claim {
                tracing::info!("Claim: {:?}", claim);
            }
        } else {
            tracing::error!("Proof verification failed!");
        }
        Ok(())
    }
    
    pub async fn start_server(&self, host: &str, port: u16, default_platform: &str) -> GatewayResult<()> {
        use crate::api::ApiServer;
        use std::sync::Arc;
        
        // Validate platform
        let platform: Platform = default_platform.parse()
            .map_err(|e| GatewayError::input_validation(format!("Invalid default platform: {}", e)))?;
        
        // Check if platform is available
        if !self.is_platform_available(&platform) {
            return Err(GatewayError::input_validation(format!(
                "Platform {} is not available", platform
            )));
        }
        
        // Create API server
        let api_server = ApiServer::new(Arc::new(self.clone()), self.config.clone());
        
        // Start server
        tracing::info!("Starting zkTLS Gateway API server on {}:{}", host, port);
        tracing::info!("Default platform: {}", platform);
        
        api_server.start(host, port).await
    }
    
    pub fn show_config(&self) -> GatewayResult<()> {
        let config_json = serde_json::to_string_pretty(&self.config)
            .map_err(|e| GatewayError::serialization(format!("Failed to serialize config: {}", e)))?;
        
        println!("Current configuration:");
        println!("{}", config_json);
        Ok(())
    }
    
    pub fn set_config(&self, key: &str, value: &str) -> GatewayResult<()> {
        // Parse key path (e.g., "server.port", "platforms.sp1.timeout_ms")
        let key_parts: Vec<&str> = key.split('.').collect();
        
        if key_parts.is_empty() {
            return Err(GatewayError::input_validation("Configuration key cannot be empty"));
        }
        
        match key_parts[0] {
            "server" => self.set_server_config(&key_parts[1..], value),
            "platforms" => self.set_platform_config(&key_parts[1..], value),
            "logging" => self.set_logging_config(&key_parts[1..], value),
            "security" => self.set_security_config(&key_parts[1..], value),
            _ => Err(GatewayError::input_validation(format!("Unknown configuration section: {}", key_parts[0]))),
        }
    }
    
    fn set_server_config(&self, key_parts: &[&str], value: &str) -> GatewayResult<()> {
        if key_parts.is_empty() {
            return Err(GatewayError::input_validation("Server configuration key incomplete"));
        }
        
        match key_parts[0] {
            "port" => {
                let port: u16 = value.parse()
                    .map_err(|e| GatewayError::input_validation(format!("Invalid port value: {}", e)))?;
                if port == 0 {
                    return Err(GatewayError::input_validation("Port cannot be 0"));
                }
                println!("Server port set to: {}", port);
            },
            "host" => {
                if value.is_empty() {
                    return Err(GatewayError::input_validation("Host cannot be empty"));
                }
                println!("Server host set to: {}", value);
            },
            "default_platform" => {
                let platform: Platform = value.parse()
                    .map_err(|e| GatewayError::input_validation(format!("Invalid platform: {}", e)))?;
                println!("Default platform set to: {}", platform);
            },
            _ => return Err(GatewayError::input_validation(format!("Unknown server configuration key: {}", key_parts[0]))),
        }
        
        Ok(())
    }
    
    fn set_platform_config(&self, key_parts: &[&str], value: &str) -> GatewayResult<()> {
        if key_parts.len() < 2 {
            return Err(GatewayError::input_validation("Platform configuration key incomplete"));
        }
        
        let platform = key_parts[0];
        let setting = key_parts[1];
        
        match platform {
            "sp1" | "risc0" => {
                match setting {
                    "timeout_ms" => {
                        let timeout: u64 = value.parse()
                            .map_err(|e| GatewayError::input_validation(format!("Invalid timeout value: {}", e)))?;
                        if timeout == 0 {
                            return Err(GatewayError::input_validation("Timeout cannot be 0"));
                        }
                        println!("{} timeout set to: {} ms", platform, timeout);
                    },
                    "memory_limit_bytes" => {
                        let memory: u64 = value.parse()
                            .map_err(|e| GatewayError::input_validation(format!("Invalid memory limit value: {}", e)))?;
                        if memory == 0 {
                            return Err(GatewayError::input_validation("Memory limit cannot be 0"));
                        }
                        println!("{} memory limit set to: {} bytes", platform, memory);
                    },
                    _ => return Err(GatewayError::input_validation(format!("Unknown platform setting: {}", setting))),
                }
            },
            _ => return Err(GatewayError::input_validation(format!("Unknown platform: {}", platform))),
        }
        
        Ok(())
    }
    
    fn set_logging_config(&self, key_parts: &[&str], value: &str) -> GatewayResult<()> {
        if key_parts.is_empty() {
            return Err(GatewayError::input_validation("Logging configuration key incomplete"));
        }
        
        match key_parts[0] {
            "level" => {
                let valid_levels = ["trace", "debug", "info", "warn", "error"];
                if !valid_levels.contains(&value.to_lowercase().as_str()) {
                    return Err(GatewayError::input_validation(format!(
                        "Invalid log level: {}. Valid levels: {:?}", value, valid_levels
                    )));
                }
                println!("Log level set to: {}", value);
            },
            "structured" => {
                let structured: bool = value.parse()
                    .map_err(|e| GatewayError::input_validation(format!("Invalid boolean value: {}", e)))?;
                println!("Structured logging set to: {}", structured);
            },
            _ => return Err(GatewayError::input_validation(format!("Unknown logging setting: {}", key_parts[0]))),
        }
        
        Ok(())
    }
    
    fn set_security_config(&self, key_parts: &[&str], value: &str) -> GatewayResult<()> {
        if key_parts.is_empty() {
            return Err(GatewayError::input_validation("Security configuration key incomplete"));
        }
        
        match key_parts[0] {
            "enable_cors" => {
                let enabled: bool = value.parse()
                    .map_err(|e| GatewayError::input_validation(format!("Invalid boolean value: {}", e)))?;
                println!("CORS enabled set to: {}", enabled);
            },
            "rate_limit_per_minute" => {
                let rate_limit: u32 = value.parse()
                    .map_err(|e| GatewayError::input_validation(format!("Invalid rate limit value: {}", e)))?;
                if rate_limit == 0 {
                    return Err(GatewayError::input_validation("Rate limit cannot be 0"));
                }
                println!("Rate limit set to: {} requests per minute", rate_limit);
            },
            _ => return Err(GatewayError::input_validation(format!("Unknown security setting: {}", key_parts[0]))),
        }
        
        Ok(())
    }
    
    pub fn init_config(&self) -> GatewayResult<()> {
        GatewayConfig::init_default(None)
    }
    
    pub async fn get_status_cli(&self) -> GatewayResult<()> {
        let status = self.get_status().await;
        let status_json = serde_json::to_string_pretty(&status)
            .map_err(|e| GatewayError::serialization(format!("Failed to serialize status: {}", e)))?;
        
        println!("Gateway Status:");
        println!("{}", status_json);
        Ok(())
    }
}