//! Configuration management for zkTLS gateway
//!
//! This module provides comprehensive configuration management for the gateway,
//! supporting multiple configuration sources and validation.

use crate::{GatewayConfig, GatewayError, DEFAULT_CONFIG_FILE};
use std::path::Path;
use std::fs;

/// Configuration manager for the gateway
pub struct ConfigManager {
    config: GatewayConfig,
    config_path: String,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new(config_path: Option<String>) -> Result<Self, GatewayError> {
        let path = config_path.unwrap_or_else(|| DEFAULT_CONFIG_FILE.to_string());
        let config = Self::load_config(&path)?;
        
        Ok(Self {
            config,
            config_path: path,
        })
    }
    
    /// Load configuration from file
    fn load_config(path: &str) -> Result<GatewayConfig, GatewayError> {
        if !Path::new(path).exists() {
            tracing::info!("Configuration file not found, using defaults: {}", path);
            return Ok(GatewayConfig::default());
        }
        
        let content = fs::read_to_string(path)
            .map_err(|e| GatewayError::config(format!("Failed to read config file {}: {}", path, e)))?;
        
        let config: GatewayConfig = toml::from_str(&content)
            .map_err(|e| GatewayError::config(format!("Failed to parse config file {}: {}", path, e)))?;
        
        // Validate configuration
        Self::validate_config(&config)?;
        
        tracing::info!("Configuration loaded from: {}", path);
        Ok(config)
    }
    
    /// Validate configuration
    fn validate_config(config: &GatewayConfig) -> Result<(), GatewayError> {
        // Validate server configuration
        if config.server.port == 0 {
            return Err(GatewayError::config("Server port cannot be 0"));
        }
        
        if config.server.request_timeout_ms == 0 {
            return Err(GatewayError::config("Request timeout cannot be 0"));
        }
        
        if config.server.max_request_size_bytes == 0 {
            return Err(GatewayError::config("Max request size cannot be 0"));
        }
        
        // Validate platform configurations
        if let Some(sp1_config) = &config.platforms.sp1 {
            if sp1_config.timeout_ms == 0 {
                return Err(GatewayError::config("SP1 timeout cannot be 0"));
            }
        }
        
        if let Some(risc0_config) = &config.platforms.risc0 {
            if risc0_config.timeout_ms == 0 {
                return Err(GatewayError::config("RISC0 timeout cannot be 0"));
            }
        }
        
        // Validate logging configuration
        let valid_log_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_log_levels.contains(&config.logging.level.as_str()) {
            return Err(GatewayError::config(format!(
                "Invalid log level: {}. Valid levels: {:?}",
                config.logging.level, valid_log_levels
            )));
        }
        
        // Validate security configuration
        if config.security.rate_limit_per_minute == 0 {
            return Err(GatewayError::config("Rate limit per minute cannot be 0"));
        }
        
        Ok(())
    }
    
    /// Get the current configuration
    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }
    
    /// Update configuration
    pub fn update_config(&mut self, new_config: GatewayConfig) -> Result<(), GatewayError> {
        Self::validate_config(&new_config)?;
        self.config = new_config;
        Ok(())
    }
    
    /// Save configuration to file
    pub fn save_config(&self) -> Result<(), GatewayError> {
        let content = toml::to_string_pretty(&self.config)
            .map_err(|e| GatewayError::config(format!("Failed to serialize config: {}", e)))?;
        
        fs::write(&self.config_path, content)
            .map_err(|e| GatewayError::config(format!("Failed to write config file: {}", e)))?;
        
        tracing::info!("Configuration saved to: {}", self.config_path);
        Ok(())
    }
    
    /// Initialize default configuration file
    pub fn init_default_config(path: Option<String>) -> Result<(), GatewayError> {
        let config_path = path.unwrap_or_else(|| DEFAULT_CONFIG_FILE.to_string());
        
        if Path::new(&config_path).exists() {
            return Err(GatewayError::config(format!(
                "Configuration file already exists: {}",
                config_path
            )));
        }
        
        let config = GatewayConfig::default();
        let content = toml::to_string_pretty(&config)
            .map_err(|e| GatewayError::config(format!("Failed to serialize default config: {}", e)))?;
        
        fs::write(&config_path, content)
            .map_err(|e| GatewayError::config(format!("Failed to write default config file: {}", e)))?;
        
        tracing::info!("Default configuration initialized: {}", config_path);
        Ok(())
    }
}

impl GatewayConfig {
    /// Load configuration from file
    pub fn load(path: &str) -> Result<Self, GatewayError> {
        ConfigManager::load_config(path)
    }
    
    /// Initialize default configuration file
    pub fn init_default(path: Option<String>) -> Result<(), GatewayError> {
        ConfigManager::init_default_config(path)
    }
    
    /// Get platform configuration
    pub fn get_platform_config(&self, platform: &crate::types::Platform) -> Option<&crate::types::PlatformConfig> {
        match platform {
            crate::types::Platform::SP1 => self.platforms.sp1.as_ref(),
            crate::types::Platform::RISC0 => self.platforms.risc0.as_ref(),
        }
    }
    
    /// Check if platform is enabled
    pub fn is_platform_enabled(&self, platform: &crate::types::Platform) -> bool {
        match platform {
            crate::types::Platform::SP1 => self.platforms.sp1.is_some(),
            crate::types::Platform::RISC0 => self.platforms.risc0.is_some(),
        }
    }
    
    /// Get available platforms
    pub fn get_available_platforms(&self) -> Vec<crate::types::Platform> {
        let mut platforms = Vec::new();
        
        if self.platforms.sp1.is_some() {
            platforms.push(crate::types::Platform::SP1);
        }
        
        if self.platforms.risc0.is_some() {
            platforms.push(crate::types::Platform::RISC0);
        }
        
        platforms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = GatewayConfig::default();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.default_platform, crate::types::Platform::SP1);
        assert!(config.platforms.sp1.is_some());
        assert!(config.platforms.risc0.is_some());
    }

    #[test]
    fn test_config_validation() {
        let mut config = GatewayConfig::default();
        
        // Valid config should pass
        assert!(ConfigManager::validate_config(&config).is_ok());
        
        // Invalid port should fail
        config.server.port = 0;
        assert!(ConfigManager::validate_config(&config).is_err());
        
        // Reset and test invalid timeout
        config.server.port = 8080;
        config.server.request_timeout_ms = 0;
        assert!(ConfigManager::validate_config(&config).is_err());
    }

    #[test]
    fn test_config_manager() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        
        // Test loading non-existent file (should use defaults)
        let manager = ConfigManager::new(Some(config_path.clone())).unwrap();
        assert_eq!(manager.config().server.port, 8080);
        
        // Test saving and loading
        manager.save_config().unwrap();
        let loaded_manager = ConfigManager::new(Some(config_path)).unwrap();
        assert_eq!(loaded_manager.config().server.port, 8080);
    }

    #[test]
    fn test_platform_configuration() {
        let config = GatewayConfig::default();
        
        assert!(config.is_platform_enabled(&crate::types::Platform::SP1));
        assert!(config.is_platform_enabled(&crate::types::Platform::RISC0));
        
        let platforms = config.get_available_platforms();
        assert_eq!(platforms.len(), 2);
        assert!(platforms.contains(&crate::types::Platform::SP1));
        assert!(platforms.contains(&crate::types::Platform::RISC0));
        
        let sp1_config = config.get_platform_config(&crate::types::Platform::SP1);
        assert!(sp1_config.is_some());
        
        let risc0_config = config.get_platform_config(&crate::types::Platform::RISC0);
        assert!(risc0_config.is_some());
    }
}
